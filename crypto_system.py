from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from ecdsa import BadSignatureError, SECP256k1, SigningKey, VerifyingKey


NETWORK_SENDER = "NETWORK"
MEGACOIN = "MegaCoin"
ADDRESS_PREFIX = "MGC"


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: float
    timestamp: float = field(default_factory=time.time)
    signature: Optional[str] = None
    reference: str = ""
    fee: float = 0.01

    def payload(self) -> str:
        return json.dumps(
            {
                "sender": self.sender,
                "recipient": self.recipient,
                "amount": round(self.amount, 8),
                "timestamp": self.timestamp,
                "reference": self.reference,
                "fee": round(self.fee, 8),
            },
            sort_keys=True,
        )

    def tx_id(self) -> str:
        return sha256(self.payload())

    def sign(self, wallet: "Wallet") -> None:
        if wallet.address != self.sender:
            raise ValueError("Wallet does not match transaction sender.")
        self.signature = wallet.sign(self.payload())

    def is_reward(self) -> bool:
        return self.sender == NETWORK_SENDER

    def is_valid(self, chain: "Blockchain") -> bool:
        if self.amount <= 0:
            return False
        if self.fee < 0:
            return False
        if len(self.reference) > 140:
            return False
        if self.is_reward():
            return self.signature is None and self.fee == 0
        if self.signature is None:
            return False
        wallet = chain.wallet_registry.get(self.sender)
        if wallet is None:
            return False
        return wallet.verify(self.payload(), self.signature)

    def total_cost(self) -> float:
        return self.amount + self.fee

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Transaction":
        return cls(**payload)


@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: list[Transaction]
    validator: str
    timestamp: float = field(default_factory=time.time)
    hash: str = ""

    def compute_hash(self) -> str:
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "validator": self.validator,
            "transactions": [transaction.to_dict() for transaction in self.transactions],
        }
        return sha256(json.dumps(block_data, sort_keys=True))

    def seal(self) -> None:
        self.hash = self.compute_hash()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [transaction.to_dict() for transaction in self.transactions],
            "validator": self.validator,
            "timestamp": self.timestamp,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Block":
        return cls(
            index=payload["index"],
            previous_hash=payload["previous_hash"],
            transactions=[Transaction.from_dict(item) for item in payload["transactions"]],
            validator=payload["validator"],
            timestamp=payload["timestamp"],
            hash=payload.get("hash", ""),
        )


class Wallet:
    def __init__(
        self,
        owner: str,
        public_key_hex: str,
        private_key_hex: Optional[str] = None,
    ):
        self.owner = owner
        self.public_key_hex = public_key_hex
        self.private_key_hex = private_key_hex
        self.address = self.address_from_public_key(public_key_hex)

    @staticmethod
    def address_from_public_key(public_key_hex: str) -> str:
        return f"{ADDRESS_PREFIX}{sha256(public_key_hex)[:40]}"

    @classmethod
    def create(cls, owner: str) -> "Wallet":
        signing_key = SigningKey.generate(curve=SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        return cls(
            owner=owner,
            public_key_hex=verifying_key.to_string("compressed").hex(),
            private_key_hex=signing_key.to_string().hex(),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Wallet":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            owner=payload["owner"],
            public_key_hex=payload["public_key_hex"],
            private_key_hex=payload.get("private_key_hex"),
        )

    @classmethod
    def from_public_record(cls, payload: dict[str, Any]) -> "Wallet":
        return cls(
            owner=payload["owner"],
            public_key_hex=payload["public_key_hex"],
            private_key_hex=None,
        )

    def save(self, path: str | Path) -> None:
        payload = {
            "owner": self.owner,
            "address": self.address,
            "public_key_hex": self.public_key_hex,
            "private_key_hex": self.private_key_hex,
        }
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def sign(self, message: str) -> str:
        if self.private_key_hex is None:
            raise ValueError("This wallet only contains a public key and cannot sign transactions.")
        signing_key = SigningKey.from_string(bytes.fromhex(self.private_key_hex), curve=SECP256k1)
        signature = signing_key.sign_deterministic(message.encode("utf-8"), hashfunc=hashlib.sha256)
        return signature.hex()

    def verify(self, message: str, signature: str) -> bool:
        try:
            verifying_key = VerifyingKey.from_string(
                bytes.fromhex(self.public_key_hex),
                curve=SECP256k1,
                valid_encodings=("compressed", "uncompressed"),
            )
            return verifying_key.verify(
                bytes.fromhex(signature),
                message.encode("utf-8"),
                hashfunc=hashlib.sha256,
            )
        except (BadSignatureError, ValueError):
            return False

    def to_public_record(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "address": self.address,
            "public_key_hex": self.public_key_hex,
        }


class Blockchain:
    def __init__(self, block_reward: float = 12.5, max_pending_per_sender: int = 5):
        self.block_reward = block_reward
        self.max_pending_per_sender = max_pending_per_sender
        self.chain: list[Block] = [self._create_genesis_block()]
        self.pending_transactions: list[Transaction] = []
        self.wallet_registry: dict[str, Wallet] = {}
        self.stakes: dict[str, float] = {}

    def _create_genesis_block(self) -> Block:
        genesis = Block(index=0, previous_hash="0", transactions=[], validator="GENESIS")
        genesis.seal()
        return genesis

    def register_wallet(self, wallet: Wallet) -> None:
        self.wallet_registry[wallet.address] = wallet
        self.stakes.setdefault(wallet.address, 0.0)

    def airdrop(self, recipient: str, amount: float, reference: str = "airdrop") -> Block:
        if amount <= 0:
            raise ValueError("Airdrop amount must be positive.")
        block = Block(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash,
            transactions=[
                Transaction(
                    sender=NETWORK_SENDER,
                    recipient=recipient,
                    amount=amount,
                    reference=reference,
                    fee=0,
                )
            ],
            validator="GENESIS",
        )
        block.seal()
        self.chain.append(block)
        return block

    def add_stake(self, address: str, amount: float) -> float:
        if amount <= 0:
            raise ValueError("Stake amount must be positive.")
        spendable = self.get_spendable_balance(address)
        if spendable < amount:
            raise ValueError("Insufficient spendable balance to stake.")
        self.stakes[address] = self.stakes.get(address, 0.0) + amount
        return self.stakes[address]

    def get_balance(self, address: str) -> float:
        balance = 0.0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender == address:
                    balance -= transaction.total_cost() if not transaction.is_reward() else transaction.amount
                if transaction.recipient == address:
                    balance += transaction.amount
        return round(balance, 8)

    def get_spendable_balance(self, address: str) -> float:
        return round(self.get_balance(address) - self.stakes.get(address, 0.0), 8)

    def create_transaction(self, transaction: Transaction) -> None:
        if not transaction.is_valid(self):
            raise ValueError("Invalid transaction signature or payload.")
        if self.get_spendable_balance(transaction.sender) < transaction.total_cost():
            raise ValueError("Insufficient balance.")
        if sum(1 for tx in self.pending_transactions if tx.sender == transaction.sender) >= self.max_pending_per_sender:
            raise ValueError("Too many pending transactions from this sender.")
        if any(existing.tx_id() == transaction.tx_id() for existing in self.pending_transactions):
            raise ValueError("Duplicate transaction.")
        self.pending_transactions.append(transaction)

    def select_validator(self) -> str:
        return self._select_validator_for(self.chain[-1].hash, len(self.chain), self.stakes)

    @staticmethod
    def _select_validator_for(previous_hash: str, index: int, stakes: dict[str, float]) -> str:
        eligible = {address: stake for address, stake in stakes.items() if stake > 0}
        if not eligible:
            raise ValueError("No validators have staked MegaCoin.")

        total_stake = sum(eligible.values())
        seed = sha256(f"{previous_hash}:{index}")
        draw = (int(seed, 16) % 1_000_000) / 1_000_000 * total_stake
        cursor = 0.0
        for address, stake in sorted(eligible.items()):
            cursor += stake
            if draw <= cursor:
                return address
        return next(reversed(sorted(eligible)))

    def forge_pending_transactions(self, validator_address: Optional[str] = None) -> Block:
        selected = self.select_validator()
        if validator_address is not None and validator_address != selected:
            raise ValueError("This validator is not selected to forge the next block.")

        fees = round(sum(tx.fee for tx in self.pending_transactions), 8)
        reward_transaction = Transaction(
            sender=NETWORK_SENDER,
            recipient=selected,
            amount=round(self.block_reward + fees, 8),
            reference="validator-reward",
            fee=0,
        )
        block = Block(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash,
            transactions=[*self.pending_transactions, reward_transaction],
            validator=selected,
        )
        block.seal()
        self.chain.append(block)
        self.pending_transactions = []
        return block

    def apply_external_block(self, block: Block) -> None:
        if block.index != len(self.chain):
            raise ValueError("Unexpected block height.")
        if block.previous_hash != self.chain[-1].hash:
            raise ValueError("Previous hash mismatch.")
        try:
            validator = self._select_validator_for(block.previous_hash, block.index, self.stakes)
            if block.validator != validator:
                raise ValueError("Unexpected validator for block.")
        except ValueError:
            if block.validator != "GENESIS" or any(not tx.is_reward() for tx in block.transactions):
                raise
        if block.compute_hash() != block.hash:
            raise ValueError("Invalid block hash.")
        for transaction in block.transactions:
            if not transaction.is_valid(self):
                raise ValueError("Block contains invalid transaction.")
        self.chain.append(block)
        confirmed_ids = {tx.tx_id() for tx in block.transactions}
        self.pending_transactions = [
            tx for tx in self.pending_transactions if tx.tx_id() not in confirmed_ids
        ]

    def find_transaction(self, tx_id: str) -> tuple[Optional[Transaction], Optional[int]]:
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.tx_id() == tx_id:
                    return transaction, block.index
        for transaction in self.pending_transactions:
            if transaction.tx_id() == tx_id:
                return transaction, None
        return None, None

    def search_transactions(
        self,
        *,
        address: Optional[str] = None,
        reference: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for block in self.chain:
            for transaction in block.transactions:
                if address and address not in (transaction.sender, transaction.recipient):
                    continue
                if reference and reference not in transaction.reference:
                    continue
                results.append(
                    {
                        "transaction": transaction.to_dict(),
                        "tx_id": transaction.tx_id(),
                        "block_index": block.index,
                        "confirmations": len(self.chain) - block.index,
                    }
                )
        return results

    def is_chain_valid(self, candidate_chain: Optional[list[Block]] = None) -> bool:
        chain = candidate_chain or self.chain
        if not chain:
            return False
        if chain[0].hash != chain[0].compute_hash():
            return False

        stakes = self.stakes.copy()
        for index in range(1, len(chain)):
            previous = chain[index - 1]
            current = chain[index]
            if current.previous_hash != previous.hash:
                return False
            if current.compute_hash() != current.hash:
                return False
            if current.validator == "GENESIS":
                if any(not transaction.is_reward() for transaction in current.transactions):
                    return False
                continue

            eligible = {address: stake for address, stake in stakes.items() if stake > 0}
            if not eligible:
                return False

            selected = self._select_validator_for(previous.hash, index, stakes)
            if current.validator != selected:
                return False

            reward_count = 0
            fee_total = round(sum(tx.fee for tx in current.transactions if not tx.is_reward()), 8)
            expected_reward = round(self.block_reward + fee_total, 8)
            for transaction in current.transactions:
                if not transaction.is_valid(self):
                    return False
                if transaction.is_reward():
                    reward_count += 1
                    if transaction.recipient != current.validator or transaction.amount != expected_reward:
                        return False
            if reward_count != 1:
                return False
        return True

    def replace_chain(self, blocks: list[Block], stakes: dict[str, float], pending: list[Transaction]) -> bool:
        if len(blocks) <= len(self.chain):
            return False
        original_stakes = self.stakes
        self.stakes = {key: float(value) for key, value in stakes.items()}
        try:
            if not self.is_chain_valid(blocks):
                return False
        finally:
            self.stakes = original_stakes
        self.chain = blocks
        self.stakes = {key: float(value) for key, value in stakes.items()}
        self.pending_transactions = pending
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "currency": MEGACOIN,
            "consensus": "proof-of-stake",
            "signature_scheme": "ECDSA-secp256k1",
            "block_reward": self.block_reward,
            "chain": [block.to_dict() for block in self.chain],
            "pending_transactions": [transaction.to_dict() for transaction in self.pending_transactions],
            "stakes": self.stakes,
            "wallet_registry": {
                address: wallet.to_public_record() for address, wallet in self.wallet_registry.items()
            },
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Blockchain":
        chain = cls(block_reward=payload.get("block_reward", 12.5))
        chain.chain = [Block.from_dict(item) for item in payload["chain"]]
        chain.pending_transactions = [
            Transaction.from_dict(item) for item in payload.get("pending_transactions", [])
        ]
        chain.stakes = {key: float(value) for key, value in payload.get("stakes", {}).items()}
        for address, record in payload.get("wallet_registry", {}).items():
            chain.wallet_registry[address] = Wallet.from_public_record(record)
        return chain


def main() -> None:
    chain = Blockchain(block_reward=15.0)
    alice = Wallet.create("Alice")
    bob = Wallet.create("Bob")
    validator = Wallet.create("Validator")

    for wallet in (alice, bob, validator):
        chain.register_wallet(wallet)

    chain.airdrop(alice.address, 40.0, "genesis-fund")
    chain.airdrop(validator.address, 20.0, "validator-fund")
    chain.add_stake(validator.address, 15.0)

    payment = Transaction(
        sender=alice.address,
        recipient=bob.address,
        amount=12.0,
        reference="sample-payment",
    )
    payment.sign(alice)
    chain.create_transaction(payment)
    chain.forge_pending_transactions(validator.address)

    print("Network:", MEGACOIN)
    print("Consensus:", "Proof of Stake")
    print("Signatures:", "ECDSA secp256k1")
    print("Blockchain valid:", chain.is_chain_valid())
    print("Alice balance:", chain.get_balance(alice.address))
    print("Bob balance:", chain.get_balance(bob.address))
    print("Validator balance:", chain.get_balance(validator.address))
    print("Validator stake:", chain.stakes[validator.address])
    print("Blocks forged:", len(chain.chain))


if __name__ == "__main__":
    main()
