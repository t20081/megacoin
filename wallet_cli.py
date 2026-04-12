from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

from crypto_system import Transaction, Wallet


def http_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else {}


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple MegaCoin wallet CLI.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("receive", help="Create a wallet file or show its receiving address.")
    create.add_argument("--wallet", required=True, help="Path to the local wallet JSON file.")
    create.add_argument("--owner", default="MegaCoin User")
    create.add_argument("--node", default="http://127.0.0.1:8000")

    balance = subparsers.add_parser("balance", help="Check the wallet balance from a node.")
    balance.add_argument("--wallet", required=True)
    balance.add_argument("--node", default="http://127.0.0.1:8000")

    send = subparsers.add_parser("send", help="Send MegaCoin to another address.")
    send.add_argument("--wallet", required=True)
    send.add_argument("--to", required=True)
    send.add_argument("--amount", required=True, type=float)
    send.add_argument("--reference", default="")
    send.add_argument("--node", default="http://127.0.0.1:8000")

    return parser


def receive_command(args: argparse.Namespace) -> None:
    wallet_path = Path(args.wallet)
    if wallet_path.exists():
        wallet = Wallet.load(wallet_path)
    else:
        ensure_parent(wallet_path)
        wallet = Wallet.create(args.owner)
        wallet.save(wallet_path)
    http_json(f"{args.node}/wallets/register", method="POST", payload=wallet.to_public_record())
    print(wallet.address)


def balance_command(args: argparse.Namespace) -> None:
    wallet = Wallet.load(args.wallet)
    payload = http_json(f"{args.node}/balance/{wallet.address}")
    print(json.dumps(payload, indent=2))


def send_command(args: argparse.Namespace) -> None:
    wallet = Wallet.load(args.wallet)
    http_json(f"{args.node}/wallets/register", method="POST", payload=wallet.to_public_record())
    transaction = Transaction(
        sender=wallet.address,
        recipient=args.to,
        amount=args.amount,
        reference=args.reference,
    )
    transaction.sign(wallet)
    payload = http_json(f"{args.node}/transactions", method="POST", payload=transaction.to_dict())
    print(json.dumps(payload, indent=2))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "receive":
        receive_command(args)
        return
    if args.command == "balance":
        balance_command(args)
        return
    if args.command == "send":
        send_command(args)
        return


if __name__ == "__main__":
    main()
