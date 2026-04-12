from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

import segno

from crypto_system import Block, Blockchain, Transaction, Wallet


STATIC_DIR = Path(__file__).with_name("static")
ALLOWED_MESSAGE_TYPES = {"transaction", "block", "stake", "peer-discovery"}
INVOICE_PENDING = "pending"
INVOICE_PAID = "paid"
INVOICE_EXPIRED = "expired"


def http_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else {}


class Node:
    def __init__(self, host: str = "127.0.0.1", port: int = 8000) -> None:
        self.blockchain = Blockchain()
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.peers: set[str] = set()
        self.lock = threading.Lock()
        self.rate_limits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.seen_messages: dict[str, float] = {}
        self.invoices: dict[str, dict[str, Any]] = {}

    def set_public_url(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"

    def cleanup_seen_messages(self) -> None:
        cutoff = time.time() - 300
        self.seen_messages = {
            message_id: timestamp
            for message_id, timestamp in self.seen_messages.items()
            if timestamp >= cutoff
        }

    def check_rate_limit(self, client: str, bucket: str, limit: int, window: int = 60) -> None:
        key = (client, bucket)
        now = time.time()
        events = self.rate_limits[key]
        while events and events[0] < now - window:
            events.popleft()
        if len(events) >= limit:
            raise ValueError("Rate limit exceeded.")
        events.append(now)

    def register_wallet(self, payload: dict[str, Any]) -> dict[str, Any]:
        wallet = Wallet.from_public_record(payload)
        with self.lock:
            self.blockchain.register_wallet(wallet)
        return wallet.to_public_record()

    def create_wallet(self, owner: str) -> dict[str, Any]:
        wallet = Wallet.create(owner)
        with self.lock:
            self.blockchain.register_wallet(wallet)
        return {
            "owner": wallet.owner,
            "address": wallet.address,
            "public_key_hex": wallet.public_key_hex,
            "private_key_hex": wallet.private_key_hex,
        }

    def submit_transaction(self, payload: dict[str, Any]) -> dict[str, Any]:
        transaction = Transaction.from_dict(payload)
        with self.lock:
            self.blockchain.create_transaction(transaction)
            self.refresh_invoice_states()
        self.broadcast("transaction", transaction.to_dict())
        return {"status": "accepted", "tx_id": transaction.tx_id()}

    def sign_and_submit_transaction(
        self,
        owner: str,
        public_key_hex: str,
        private_key_hex: str,
        recipient: str,
        amount: float,
        reference: str = "",
    ) -> dict[str, Any]:
        wallet = Wallet(owner=owner, public_key_hex=public_key_hex, private_key_hex=private_key_hex)
        with self.lock:
            self.blockchain.register_wallet(wallet)
        transaction = Transaction(sender=wallet.address, recipient=recipient, amount=amount, reference=reference)
        transaction.sign(wallet)
        return self.submit_transaction(transaction.to_dict())

    def add_stake(self, address: str, amount: float) -> float:
        with self.lock:
            total = self.blockchain.add_stake(address, amount)
        self.broadcast("stake", {"address": address, "amount": amount})
        return total

    def forge_block(self) -> dict[str, Any]:
        with self.lock:
            block = self.blockchain.forge_pending_transactions()
            self.refresh_invoice_states()
        self.broadcast("block", {"block": block.to_dict()})
        return block.to_dict()

    def add_peer(self, peer: str, discover: bool = True) -> None:
        parsed = urllib.parse.urlparse(peer)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Peer must be a full URL like http://127.0.0.1:8000.")
        normalized = peer.rstrip("/")
        if normalized == self.base_url:
            return
        if normalized in self.peers:
            return
        self.peers.add(normalized)
        if discover:
            self.discover_peers_from(normalized)
            try:
                http_json(f"{normalized}/peers", method="POST", payload={"peer": self.base_url})
            except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                pass

    def discover_peers_from(self, peer: str) -> None:
        try:
            payload = http_json(f"{peer}/peers/list")
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return
        for discovered in payload.get("peers", []):
            if discovered.rstrip("/") != self.base_url:
                self.peers.add(discovered.rstrip("/"))

    def sync(self) -> bool:
        replaced = False
        for peer in list(self.peers):
            self.discover_peers_from(peer)
            try:
                payload = http_json(f"{peer}/chain")
            except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                continue
            candidate = Blockchain.from_dict(payload)
            with self.lock:
                replaced = self.blockchain.replace_chain(
                    candidate.chain,
                    candidate.stakes,
                    candidate.pending_transactions,
                ) or replaced
                for address, wallet in candidate.wallet_registry.items():
                    if address not in self.blockchain.wallet_registry:
                        self.blockchain.register_wallet(wallet)
                self.refresh_invoice_states()
        return replaced

    def build_message(self, message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "message_id": uuid.uuid4().hex,
            "message_type": message_type,
            "origin": self.base_url,
            "timestamp": time.time(),
            "payload": payload,
        }

    def validate_message(self, envelope: dict[str, Any], expected_type: str) -> dict[str, Any]:
        self.cleanup_seen_messages()
        for field in ("message_id", "message_type", "origin", "timestamp", "payload"):
            if field not in envelope:
                raise ValueError("Malformed peer message.")
        if envelope["message_type"] != expected_type:
            raise ValueError("Unexpected message type.")
        if envelope["message_type"] not in ALLOWED_MESSAGE_TYPES:
            raise ValueError("Unsupported message type.")
        if not isinstance(envelope["payload"], dict):
            raise ValueError("Peer message payload must be an object.")
        origin = str(envelope["origin"]).rstrip("/")
        if origin not in self.peers:
            raise ValueError("Message origin is not a known peer.")
        if abs(time.time() - float(envelope["timestamp"])) > 120:
            raise ValueError("Peer message is too old or too far in the future.")
        if envelope["message_id"] in self.seen_messages:
            raise ValueError("Duplicate peer message.")
        self.seen_messages[envelope["message_id"]] = time.time()
        return envelope["payload"]

    def broadcast(self, message_type: str, payload: dict[str, Any]) -> None:
        envelope = self.build_message(message_type, payload)
        route = {
            "transaction": "/peers/transactions",
            "stake": "/peers/stakes",
            "block": "/peers/blocks",
            "peer-discovery": "/peers/discovery",
        }[message_type]
        for peer in list(self.peers):
            try:
                http_json(f"{peer}{route}", method="POST", payload=envelope)
            except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                continue

    def create_invoice(self, payload: dict[str, Any]) -> dict[str, Any]:
        amount = round(float(payload["amount"]), 8)
        if amount <= 0:
            raise ValueError("Invoice amount must be positive.")
        invoice_id = payload.get("invoice_id") or f"inv_{uuid.uuid4().hex[:12]}"
        expires_in = int(payload.get("expires_in", 900))
        if expires_in <= 0:
            raise ValueError("Invoice timeout must be positive.")
        confirmations_required = int(payload.get("confirmations_required", 2))
        if confirmations_required < 2 or confirmations_required > 3:
            raise ValueError("Invoice confirmations_required must be between 2 and 3.")
        created_at = time.time()
        invoice = {
            "invoice_id": invoice_id,
            "merchant_address": payload["merchant_address"],
            "amount": amount,
            "description": payload.get("description", ""),
            "reference": payload.get("reference") or invoice_id,
            "created_at": created_at,
            "expires_at": created_at + expires_in,
            "expires_in": expires_in,
            "status": INVOICE_PENDING,
            "confirmations_required": confirmations_required,
            "tx_id": None,
            "confirmations": 0,
            "matched_amount": 0.0,
            "payment_received_at": None,
        }
        self.invoices[invoice_id] = invoice
        return self.serialize_invoice(invoice)

    def invoice_status_snapshot(self, invoice: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        return {
            "invoice_id": invoice["invoice_id"],
            "status": invoice["status"],
            "confirmations": invoice["confirmations"],
            "confirmations_required": invoice["confirmations_required"],
            "matched_amount": invoice["matched_amount"],
            "tx_id": invoice["tx_id"],
            "expires_at": invoice["expires_at"],
            "time_left": max(0, int(invoice["expires_at"] - now)),
            "expired": invoice["status"] == INVOICE_EXPIRED,
            "paid": invoice["status"] == INVOICE_PAID,
        }

    def serialize_invoice(self, invoice: dict[str, Any]) -> dict[str, Any]:
        payment_uri = (
            f"megacoin:{invoice['merchant_address']}?amount={invoice['amount']}&reference={invoice['reference']}"
        )
        return {
            **invoice,
            "payment_uri": payment_uri,
            "checkout_url": f"{self.base_url}/checkout/{invoice['invoice_id']}",
            "status_snapshot": self.invoice_status_snapshot(invoice),
        }

    def list_invoices(self) -> list[dict[str, Any]]:
        self.refresh_invoice_states()
        return [
            self.serialize_invoice(invoice)
            for invoice in sorted(self.invoices.values(), key=lambda item: item["created_at"], reverse=True)
        ]

    def match_invoice_payment(self, invoice: dict[str, Any]) -> bool:
        pending_match = next(
            (
                tx
                for tx in self.blockchain.pending_transactions
                if tx.recipient == invoice["merchant_address"]
                and tx.reference == invoice["reference"]
                and tx.amount >= invoice["amount"]
            ),
            None,
        )
        confirmed_matches = self.blockchain.search_transactions(
            address=invoice["merchant_address"],
            reference=invoice["reference"],
        )
        confirmed_match = next(
            (
                item
                for item in confirmed_matches
                if item["transaction"]["recipient"] == invoice["merchant_address"]
                and item["transaction"]["amount"] >= invoice["amount"]
            ),
            None,
        )

        if confirmed_match is not None:
            invoice["tx_id"] = confirmed_match["tx_id"]
            invoice["confirmations"] = confirmed_match["confirmations"]
            invoice["matched_amount"] = confirmed_match["transaction"]["amount"]
            invoice["payment_received_at"] = confirmed_match["transaction"]["timestamp"]
            invoice["status"] = (
                INVOICE_PAID
                if confirmed_match["confirmations"] >= invoice["confirmations_required"]
                else INVOICE_PENDING
            )
            return True

        if pending_match is not None:
            invoice["tx_id"] = pending_match.tx_id()
            invoice["confirmations"] = 0
            invoice["matched_amount"] = pending_match.amount
            invoice["payment_received_at"] = pending_match.timestamp
            invoice["status"] = INVOICE_PENDING
            return True

        return False

    def refresh_invoice_states(self) -> None:
        now = time.time()
        for invoice in self.invoices.values():
            if invoice["status"] == INVOICE_PAID:
                self.match_invoice_payment(invoice)
                continue

            invoice["tx_id"] = None
            invoice["confirmations"] = 0
            invoice["matched_amount"] = 0.0
            invoice["payment_received_at"] = None
            invoice["status"] = INVOICE_PENDING

            if self.match_invoice_payment(invoice):
                continue
            if now >= invoice["expires_at"]:
                invoice["status"] = INVOICE_EXPIRED

    def expire_invoice(self, invoice_id: str) -> dict[str, Any]:
        if invoice_id not in self.invoices:
            raise ValueError("Invoice not found.")
        invoice = self.invoices[invoice_id]
        if invoice["status"] != INVOICE_PAID:
            invoice["expires_at"] = time.time() - 1
            self.refresh_invoice_states()
        return self.serialize_invoice(invoice)

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        if invoice_id not in self.invoices:
            raise ValueError("Invoice not found.")
        self.refresh_invoice_states()
        return self.serialize_invoice(self.invoices[invoice_id])

    def qr_svg(self, text: str) -> bytes:
        qr = segno.make(text)
        return qr.svg_inline(scale=4).encode("utf-8")


class MegaCoinHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self.redirect("/wallet")
            return
        if path == "/wallet":
            self.respond_html((STATIC_DIR / "wallet.html").read_text(encoding="utf-8"))
            return
        if path == "/merchant":
            self.respond_html((STATIC_DIR / "merchant.html").read_text(encoding="utf-8"))
            return
        if path.startswith("/checkout/"):
            self.respond_html((STATIC_DIR / "checkout.html").read_text(encoding="utf-8"))
            return
        if path == "/explorer":
            self.respond_html((STATIC_DIR / "explorer.html").read_text(encoding="utf-8"))
            return
        if path == "/chain":
            self.respond(self.server.node.blockchain.to_dict())
            return
        if path == "/status":
            self.respond(
                {
                    "currency": "MegaCoin",
                    "consensus": "proof-of-stake",
                    "signature_scheme": "ECDSA-secp256k1",
                    "blocks": len(self.server.node.blockchain.chain),
                    "pending_transactions": len(self.server.node.blockchain.pending_transactions),
                    "peers": sorted(self.server.node.peers),
                }
            )
            return
        if path == "/peers/list":
            self.respond({"self": self.server.node.base_url, "peers": sorted(self.server.node.peers | {self.server.node.base_url})})
            return
        if path.startswith("/balance/"):
            address = path.split("/")[-1]
            self.respond(
                {
                    "address": address,
                    "balance": self.server.node.blockchain.get_balance(address),
                    "spendable_balance": self.server.node.blockchain.get_spendable_balance(address),
                    "stake": self.server.node.blockchain.stakes.get(address, 0.0),
                }
            )
            return
        if path.startswith("/transactions/"):
            tx_id = path.split("/")[-1]
            transaction, block_index = self.server.node.blockchain.find_transaction(tx_id)
            if transaction is None:
                self.respond({"error": "Transaction not found."}, status=HTTPStatus.NOT_FOUND)
                return
            confirmations = 0 if block_index is None else len(self.server.node.blockchain.chain) - block_index
            self.respond(
                {
                    "tx_id": tx_id,
                    "transaction": transaction.to_dict(),
                    "block_index": block_index,
                    "confirmations": confirmations,
                    "status": "pending" if block_index is None else "confirmed",
                }
            )
            return
        if path.startswith("/merchant/invoices/"):
            invoice_id = path.split("/")[-1]
            try:
                self.respond(self.server.node.get_invoice(invoice_id))
            except ValueError as exc:
                self.respond({"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
            return
        if path == "/merchant/invoices":
            self.respond({"invoices": self.server.node.list_invoices()})
            return
        if path.startswith("/merchant/status/"):
            invoice_id = path.split("/")[-1]
            try:
                invoice = self.server.node.get_invoice(invoice_id)
                self.respond(invoice["status_snapshot"])
            except ValueError as exc:
                self.respond({"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
            return
        if path == "/explorer/summary":
            chain = self.server.node.blockchain
            latest = chain.chain[-1]
            recent = []
            for block in chain.chain[-10:]:
                recent.append(
                    {
                        "index": block.index,
                        "hash": block.hash,
                        "validator": block.validator,
                        "transaction_count": len(block.transactions),
                        "timestamp": block.timestamp,
                    }
                )
            self.respond(
                {
                    "status": {
                        "blocks": len(chain.chain),
                        "pending_transactions": len(chain.pending_transactions),
                        "latest_hash": latest.hash,
                    },
                    "recent_blocks": list(reversed(recent)),
                }
            )
            return
        if path == "/explorer/search":
            reference = query.get("reference", [None])[0]
            address = query.get("address", [None])[0]
            self.respond({"results": self.server.node.blockchain.search_transactions(address=address, reference=reference)})
            return
        if path == "/qr":
            text = query.get("text", [""])[0]
            self.respond_bytes(self.server.node.qr_svg(text), "image/svg+xml")
            return
        self.respond({"error": "Not found."}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        payload = self.read_json()
        client = self.client_address[0]
        try:
            if path == "/wallets/create":
                self.server.node.check_rate_limit(client, "wallet-create", 20)
                wallet = self.server.node.create_wallet(payload.get("owner", "MegaCoin User"))
                self.respond(wallet, status=HTTPStatus.CREATED)
                return
            if path == "/wallets/register":
                self.server.node.check_rate_limit(client, "wallet-register", 60)
                wallet = self.server.node.register_wallet(payload)
                self.respond(wallet, status=HTTPStatus.CREATED)
                return
            if path == "/wallets/sign-send":
                self.server.node.check_rate_limit(client, "wallet-send", 20)
                result = self.server.node.sign_and_submit_transaction(
                    owner=payload["owner"],
                    public_key_hex=payload["public_key_hex"],
                    private_key_hex=payload["private_key_hex"],
                    recipient=payload["recipient"],
                    amount=float(payload["amount"]),
                    reference=payload.get("reference", ""),
                )
                self.respond(result, status=HTTPStatus.CREATED)
                return
            if path == "/transactions":
                self.server.node.check_rate_limit(client, "transactions", 30)
                result = self.server.node.submit_transaction(payload)
                self.respond(result, status=HTTPStatus.CREATED)
                return
            if path == "/stake":
                self.server.node.check_rate_limit(client, "stake", 20)
                total = self.server.node.add_stake(payload["address"], float(payload["amount"]))
                self.respond({"address": payload["address"], "staked": total})
                return
            if path == "/forge":
                self.server.node.check_rate_limit(client, "forge", 30)
                block = self.server.node.forge_block()
                self.respond(block, status=HTTPStatus.CREATED)
                return
            if path == "/peers":
                self.server.node.check_rate_limit(client, "peers", 60)
                self.server.node.add_peer(payload["peer"])
                self.respond({"peers": sorted(self.server.node.peers)}, status=HTTPStatus.CREATED)
                return
            if path == "/sync":
                self.server.node.check_rate_limit(client, "sync", 30)
                replaced = self.server.node.sync()
                self.respond({"replaced": replaced, "length": len(self.server.node.blockchain.chain)})
                return
            if path == "/airdrop":
                self.server.node.check_rate_limit(client, "airdrop", 10)
                with self.server.node.lock:
                    block = self.server.node.blockchain.airdrop(
                        payload["recipient"],
                        float(payload["amount"]),
                        payload.get("reference", "airdrop"),
                    )
                    self.server.node.refresh_invoice_states()
                self.respond(block.to_dict(), status=HTTPStatus.CREATED)
                return
            if path == "/merchant/invoices":
                self.server.node.check_rate_limit(client, "merchant-invoices", 60)
                invoice = self.server.node.create_invoice(payload)
                self.respond(invoice, status=HTTPStatus.CREATED)
                return
            if path.startswith("/merchant/invoices/") and path.endswith("/expire"):
                self.server.node.check_rate_limit(client, "merchant-invoices", 60)
                invoice_id = path.split("/")[-2]
                invoice = self.server.node.expire_invoice(invoice_id)
                self.respond(invoice)
                return
            if path == "/peers/transactions":
                peer_payload = self.server.node.validate_message(payload, "transaction")
                transaction = Transaction.from_dict(peer_payload)
                with self.server.node.lock:
                    if all(
                        existing.tx_id() != transaction.tx_id()
                        for existing in self.server.node.blockchain.pending_transactions
                    ):
                        self.server.node.blockchain.create_transaction(transaction)
                        self.server.node.refresh_invoice_states()
                self.respond({"status": "accepted"})
                return
            if path == "/peers/stakes":
                peer_payload = self.server.node.validate_message(payload, "stake")
                with self.server.node.lock:
                    self.server.node.blockchain.stakes.setdefault(peer_payload["address"], 0.0)
                    self.server.node.blockchain.stakes[peer_payload["address"]] += float(peer_payload["amount"])
                self.respond({"status": "updated"})
                return
            if path == "/peers/blocks":
                peer_payload = self.server.node.validate_message(payload, "block")
                block = Block.from_dict(peer_payload["block"])
                with self.server.node.lock:
                    self.server.node.blockchain.apply_external_block(block)
                    self.server.node.refresh_invoice_states()
                self.respond({"status": "accepted"})
                return
            if path == "/peers/discovery":
                peer_payload = self.server.node.validate_message(payload, "peer-discovery")
                for peer in peer_payload.get("peers", []):
                    self.server.node.add_peer(peer, discover=False)
                self.respond({"status": "accepted"})
                return
        except (KeyError, TypeError, ValueError) as exc:
            self.respond({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        self.respond({"error": "Not found."}, status=HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        return json.loads(raw or "{}")

    def respond(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def respond_html(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.respond_bytes(html.encode("utf-8"), "text/html; charset=utf-8", status=status)

    def respond_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.end_headers()


def create_server(host: str, port: int, node: Optional[Node] = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), MegaCoinHandler)
    server.node = node or Node(host, port)
    server.node.set_public_url(host, server.server_port)
    return server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a MegaCoin proof-of-stake node.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--peer", action="append", default=[])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    node = Node(args.host, args.port)
    for peer in args.peer:
        node.add_peer(peer)
    server = create_server(args.host, args.port, node=node)
    node.set_public_url(args.host, server.server_port)
    if node.peers:
        node.broadcast("peer-discovery", {"peers": sorted(node.peers | {node.base_url})})
    print(f"MegaCoin node listening on {node.base_url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
