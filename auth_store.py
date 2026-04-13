from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

import bcrypt

from crypto_system import Blockchain, Wallet


DATABASE_PATH = Path(__file__).with_name("megacoin.db")
SESSION_TTL_SECONDS = 60 * 60 * 24 * 7


def hash_password(password: str, salt_hex: Optional[str] = None) -> str:
    if salt_hex is not None:
        # Legacy fallback for older pbkdf2 records.
        raise ValueError("Legacy salt-based hashing is no longer used.")
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return f"bcrypt${hashed.decode('utf-8')}"


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("bcrypt$"):
        hashed = stored.split("$", 1)[1].encode("utf-8")
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    # Backward-compatible read path for old pbkdf2 users; forces rehash on next login if needed.
    import hashlib

    salt_hex, expected = stored.split("$", 1)
    salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"{salt_hex}${derived.hex()}" == f"{salt_hex}${expected}"


class AuthStore:
    def __init__(self, blockchain: Blockchain, db_path: Path = DATABASE_PATH):
        self.blockchain = blockchain
        self.db_path = db_path
        self._init_db()
        state_payload, _ = self.load_chain_state()
        if state_payload:
            restored = Blockchain.from_dict(state_payload)
            self.blockchain.chain = restored.chain
            self.blockchain.pending_transactions = restored.pending_transactions
            self.blockchain.stakes = restored.stakes
            self.blockchain.wallet_registry = restored.wallet_registry
        self.load_wallets()
        self.rebuild_transaction_history()

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init_db(self) -> None:
        with self.db() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wallets (
                    user_id INTEGER PRIMARY KEY,
                    owner TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    public_key_hex TEXT NOT NULL,
                    private_key_hex TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tx_id TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    wallet_address TEXT NOT NULL,
                    counterparty_address TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    amount REAL NOT NULL,
                    fee REAL NOT NULL,
                    reference TEXT,
                    timestamp REAL NOT NULL,
                    status TEXT NOT NULL,
                    block_index INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS app_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )

    def load_wallets(self) -> None:
        with self.db() as connection:
            rows = connection.execute(
                "SELECT owner, public_key_hex, private_key_hex FROM wallets"
            ).fetchall()
        for row in rows:
            wallet = Wallet(
                owner=row["owner"],
                public_key_hex=row["public_key_hex"],
                private_key_hex=row["private_key_hex"],
            )
            self.blockchain.register_wallet(wallet)

    def load_chain_state(self) -> tuple[Optional[dict], dict]:
        with self.db() as connection:
            rows = connection.execute(
                "SELECT key, value FROM app_state WHERE key IN ('blockchain_state', 'invoice_state')"
            ).fetchall()
        data = {row["key"]: json.loads(row["value"]) for row in rows}
        return data.get("blockchain_state"), data.get("invoice_state", {})

    def save_chain_state(self, blockchain_payload: dict, invoices_payload: dict) -> None:
        now = time.time()
        with self.db() as connection:
            connection.execute(
                """
                INSERT INTO app_state(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                ("blockchain_state", json.dumps(blockchain_payload), now),
            )
            connection.execute(
                """
                INSERT INTO app_state(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                ("invoice_state", json.dumps(invoices_payload), now),
            )

    def create_user(self, username: str, password: str) -> dict:
        username = username.strip().lower()
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters.")
        wallet = Wallet.create(username)
        created_at = time.time()
        with self.db() as connection:
            try:
                cursor = connection.execute(
                    "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, hash_password(password), created_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Username already exists.") from exc
            user_id = int(cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO wallets(user_id, owner, address, public_key_hex, private_key_hex, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    wallet.owner,
                    wallet.address,
                    wallet.public_key_hex,
                    wallet.private_key_hex,
                    created_at,
                ),
            )
        self.blockchain.register_wallet(wallet)
        return {"user": {"id": user_id, "username": username}, "session": self.create_session(user_id)}

    def authenticate_user(self, username: str, password: str) -> dict:
        username = username.strip().lower()
        with self.db() as connection:
            row = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None or not verify_password(password, row["password_hash"]):
            raise ValueError("Invalid username or password.")
        return {"user": {"id": int(row["id"]), "username": row["username"]}, "session": self.create_session(int(row["id"]))}

    def create_session(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        created_at = time.time()
        expires_at = created_at + SESSION_TTL_SECONDS
        with self.db() as connection:
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            connection.execute(
                "INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token, user_id, created_at, expires_at),
            )
        return token

    def user_from_session(self, token: str) -> Optional[dict]:
        if not token:
            return None
        now = time.time()
        with self.db() as connection:
            row = connection.execute(
                """
                SELECT users.id, users.username, sessions.expires_at
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token = ?
                """,
                (token,),
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] < now:
                connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
                return None
        return {"id": int(row["id"]), "username": row["username"]}

    def destroy_session(self, token: str) -> None:
        with self.db() as connection:
            connection.execute("DELETE FROM sessions WHERE token = ?", (token,))

    def wallet_record(self, user_id: int) -> sqlite3.Row:
        with self.db() as connection:
            row = connection.execute(
                "SELECT user_id, owner, address, public_key_hex, private_key_hex FROM wallets WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            raise ValueError("Wallet not found for user.")
        return row

    def wallet_for_user(self, user_id: int) -> Wallet:
        row = self.wallet_record(user_id)
        return Wallet(
            owner=row["owner"],
            public_key_hex=row["public_key_hex"],
            private_key_hex=row["private_key_hex"],
        )

    def wallet_payload(self, user_id: int) -> dict:
        row = self.wallet_record(user_id)
        address = row["address"]
        return {
            "owner": row["owner"],
            "address": address,
            "public_key_hex": row["public_key_hex"],
            "balance": self.blockchain.get_balance(address),
            "spendable_balance": self.blockchain.get_spendable_balance(address),
            "stake": self.blockchain.stakes.get(address, 0.0),
        }

    def register_wallet_if_missing(self, user_id: int) -> None:
        wallet = self.wallet_for_user(user_id)
        if wallet.address not in self.blockchain.wallet_registry:
            self.blockchain.register_wallet(wallet)

    def rebuild_transaction_history(self) -> None:
        with self.db() as connection:
            wallets = connection.execute("SELECT user_id, address FROM wallets").fetchall()
            connection.execute("DELETE FROM transactions")
            wallet_map = [(int(row["user_id"]), row["address"]) for row in wallets]

            def insert_tx(tx, status: str, block_index):
                for user_id, address in wallet_map:
                    if tx.sender != address and tx.recipient != address:
                        continue
                    direction = "outgoing" if tx.sender == address and tx.recipient != address else "incoming"
                    if tx.sender == address and tx.recipient == address:
                        direction = "self"
                    counterparty = tx.recipient if tx.sender == address else tx.sender
                    connection.execute(
                        """
                        INSERT INTO transactions(
                            tx_id, user_id, wallet_address, counterparty_address, direction,
                            amount, fee, reference, timestamp, status, block_index
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            tx.tx_id(),
                            user_id,
                            address,
                            counterparty,
                            direction,
                            tx.amount,
                            tx.fee,
                            tx.reference,
                            tx.timestamp,
                            status,
                            block_index,
                        ),
                    )

            for block in self.blockchain.chain:
                for tx in block.transactions:
                    insert_tx(tx, "confirmed", block.index)
            for tx in self.blockchain.pending_transactions:
                insert_tx(tx, "pending", None)

    def history_for_user(self, user_id: int) -> list[dict]:
        with self.db() as connection:
            rows = connection.execute(
                """
                SELECT tx_id, wallet_address, counterparty_address, direction, amount, fee,
                       reference, timestamp, status, block_index
                FROM transactions
                WHERE user_id = ?
                ORDER BY timestamp DESC
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]
