import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from websockets.sync.client import connect as ws_connect

from crypto_system import Blockchain, Transaction, Wallet
from node_server import Node, create_server, http_json


class CryptoSystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chain = Blockchain(block_reward=20.0)
        self.alice = Wallet.create("Alice")
        self.bob = Wallet.create("Bob")
        self.validator = Wallet.create("Validator")

        for wallet in (self.alice, self.bob, self.validator):
            self.chain.register_wallet(wallet)

        self.chain.airdrop(self.alice.address, 30.0, "test-fund")
        self.chain.airdrop(self.validator.address, 15.0, "validator-fund")
        self.chain.add_stake(self.validator.address, 10.0)

    def test_wallet_signatures_verify(self) -> None:
        message = "send coins"
        signature = self.alice.sign(message)
        self.assertTrue(self.alice.verify(message, signature))
        self.assertFalse(self.bob.verify(message, signature))

    def test_pos_transaction_flow_and_balances(self) -> None:
        tx = Transaction(sender=self.alice.address, recipient=self.bob.address, amount=7.5, fee=0.01)
        tx.sign(self.alice)
        self.chain.create_transaction(tx)
        self.chain.forge_pending_transactions(self.validator.address)

        self.assertEqual(self.chain.get_balance(self.alice.address), 22.49)
        self.assertEqual(self.chain.get_balance(self.bob.address), 7.5)
        self.assertEqual(self.chain.get_balance(self.validator.address), 35.01)
        self.assertEqual(self.chain.stakes[self.validator.address], 10.0)
        self.assertTrue(self.chain.is_chain_valid())

    def test_serialization_round_trip_preserves_valid_chain(self) -> None:
        tx = Transaction(sender=self.alice.address, recipient=self.bob.address, amount=2.0)
        tx.sign(self.alice)
        self.chain.create_transaction(tx)
        self.chain.forge_pending_transactions(self.validator.address)

        restored = Blockchain.from_dict(self.chain.to_dict())
        self.assertTrue(restored.is_chain_valid())
        self.assertEqual(restored.get_balance(self.bob.address), 2.0)

    def test_detects_tampering(self) -> None:
        tx = Transaction(sender=self.alice.address, recipient=self.bob.address, amount=2.0)
        tx.sign(self.alice)
        self.chain.create_transaction(tx)
        self.chain.forge_pending_transactions(self.validator.address)

        self.chain.chain[-1].transactions[0].amount = 999.0
        self.assertFalse(self.chain.is_chain_valid())

    def test_limits_pending_sender_spam(self) -> None:
        for index in range(self.chain.max_pending_per_sender):
            tx = Transaction(
                sender=self.alice.address,
                recipient=self.bob.address,
                amount=0.5,
                reference=f"spam-{index}",
            )
            tx.sign(self.alice)
            self.chain.create_transaction(tx)

        tx = Transaction(sender=self.alice.address, recipient=self.bob.address, amount=0.5, reference="spam-over")
        tx.sign(self.alice)
        with self.assertRaises(ValueError):
            self.chain.create_transaction(tx)


class NodeIntegrationTests(unittest.TestCase):
    def start_server(self):
        temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(temp_dir.name) / "megacoin.db"
        server = create_server("127.0.0.1", 0, node=Node("127.0.0.1", 0, db_path=db_path))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.1)
        return server, thread, f"http://127.0.0.1:{server.server_port}", temp_dir

    def stop_server(self, server, thread, temp_dir):
        server.shutdown()
        server.node.live_feed.stop()
        server.server_close()
        thread.join(timeout=2)
        temp_dir.cleanup()

    def test_peer_sync_cli_invoice_and_web_routes(self) -> None:
        server_a, thread_a, node_a, temp_a = self.start_server()
        server_b, thread_b, node_b, temp_b = self.start_server()
        try:
            http_json(f"{node_b}/peers", method="POST", payload={"peer": node_a})
            peers_a = http_json(f"{node_a}/peers/list")
            self.assertIn(node_b, peers_a["peers"])

            with tempfile.TemporaryDirectory() as temp_dir:
                wallet_dir = Path(temp_dir)
                alice_wallet = wallet_dir / "alice.json"
                bob_wallet = wallet_dir / "bob.json"
                validator_wallet = wallet_dir / "validator.json"

                alice_address = subprocess.check_output(
                    [
                        sys.executable,
                        "D:\\crypto_system\\wallet_cli.py",
                        "receive",
                        "--wallet",
                        str(alice_wallet),
                        "--owner",
                        "Alice",
                        "--node",
                        node_a,
                    ],
                    text=True,
                ).strip()
                bob_address = subprocess.check_output(
                    [
                        sys.executable,
                        "D:\\crypto_system\\wallet_cli.py",
                        "receive",
                        "--wallet",
                        str(bob_wallet),
                        "--owner",
                        "Bob",
                        "--node",
                        node_a,
                    ],
                    text=True,
                ).strip()
                validator_address = subprocess.check_output(
                    [
                        sys.executable,
                        "D:\\crypto_system\\wallet_cli.py",
                        "receive",
                        "--wallet",
                        str(validator_wallet),
                        "--owner",
                        "Validator",
                        "--node",
                        node_a,
                    ],
                    text=True,
                ).strip()

                http_json(
                    f"{node_a}/airdrop",
                    method="POST",
                    payload={"recipient": alice_address, "amount": 50.0, "reference": "merchant-fund"},
                )
                http_json(
                    f"{node_a}/airdrop",
                    method="POST",
                    payload={"recipient": validator_address, "amount": 25.0, "reference": "validator-fund"},
                )
                http_json(
                    f"{node_a}/stake",
                    method="POST",
                    payload={"address": validator_address, "amount": 20.0},
                )

                invoice = http_json(
                    f"{node_a}/merchant/invoices",
                    method="POST",
                    payload={
                        "merchant_address": bob_address,
                        "amount": 5.0,
                        "description": "Test order",
                        "confirmations_required": 2,
                        "expires_in": 120,
                    },
                )
                self.assertEqual(invoice["status"], "pending")
                self.assertIn("/checkout/", invoice["checkout_url"])

                sync_payload = http_json(f"{node_b}/sync", method="POST", payload={})
                self.assertEqual(sync_payload["length"], 3)

                send_output = subprocess.check_output(
                    [
                        sys.executable,
                        "D:\\crypto_system\\wallet_cli.py",
                        "send",
                        "--wallet",
                        str(alice_wallet),
                        "--to",
                        bob_address,
                        "--amount",
                        "5",
                        "--reference",
                        invoice["reference"],
                        "--node",
                        node_a,
                    ],
                    text=True,
                )
                send_payload = json.loads(send_output)
                self.assertEqual(send_payload["status"], "accepted")

                invoice_seen = http_json(f"{node_a}/merchant/invoices/{invoice['invoice_id']}")
                self.assertEqual(invoice_seen["status"], "pending")
                self.assertEqual(invoice_seen["matched_amount"], 5.0)
                self.assertEqual(invoice_seen["status_snapshot"]["paid"], False)

                forged = http_json(f"{node_a}/forge", method="POST", payload={})
                self.assertEqual(forged["validator"], validator_address)

                invoice_after_one_confirmation = http_json(f"{node_a}/merchant/invoices/{invoice['invoice_id']}")
                self.assertEqual(invoice_after_one_confirmation["status"], "pending")
                self.assertEqual(invoice_after_one_confirmation["confirmations"], 1)
                self.assertEqual(invoice_after_one_confirmation["status_snapshot"]["paid"], False)

                forged = http_json(f"{node_a}/forge", method="POST", payload={})
                self.assertEqual(forged["validator"], validator_address)

                invoice_confirmed = http_json(f"{node_a}/merchant/invoices/{invoice['invoice_id']}")
                self.assertEqual(invoice_confirmed["status"], "paid")
                self.assertEqual(invoice_confirmed["confirmations"], 2)
                self.assertEqual(invoice_confirmed["status_snapshot"]["paid"], True)

                http_json(f"{node_b}/sync", method="POST", payload={})
                status = http_json(f"{node_b}/balance/{bob_address}")
                self.assertEqual(status["balance"], 5.0)

                tx_status = http_json(f"{node_a}/transactions/{invoice_confirmed['tx_id']}")
                self.assertEqual(tx_status["status"], "confirmed")
                self.assertEqual(tx_status["confirmations"], 2)

                wallet_html = urllib.request.urlopen(f"{node_a}/wallet").read().decode("utf-8")
                merchant_html = urllib.request.urlopen(f"{node_a}/merchant").read().decode("utf-8")
                checkout_html = urllib.request.urlopen(invoice["checkout_url"]).read().decode("utf-8")
                explorer_html = urllib.request.urlopen(f"{node_a}/explorer").read().decode("utf-8")
                qr_svg = urllib.request.urlopen(f"{node_a}/qr?text=megacoin:{bob_address}").read().decode("utf-8")

                self.assertIn("MegaCoin Wallet", wallet_html)
                self.assertIn("Merchant Dashboard", merchant_html)
                self.assertIn("MegaCoin Checkout", checkout_html)
                self.assertIn("MegaCoin Explorer", explorer_html)
                self.assertIn("<svg", qr_svg)

                search = http_json(
                    f"{node_a}/explorer/search?reference={invoice['reference']}"
                )
                self.assertEqual(len(search["results"]), 1)

                invoice_list = http_json(f"{node_a}/merchant/invoices")
                self.assertEqual(len(invoice_list["invoices"]), 1)
                status_snapshot = http_json(f"{node_a}/merchant/status/{invoice['invoice_id']}")
                self.assertEqual(status_snapshot["status"], "paid")

                balance_output = subprocess.check_output(
                    [
                        sys.executable,
                        "D:\\crypto_system\\wallet_cli.py",
                        "balance",
                        "--wallet",
                        str(bob_wallet),
                        "--node",
                        node_b,
                    ],
                    text=True,
                )
                balance_payload = json.loads(balance_output)
                self.assertEqual(balance_payload["balance"], 5.0)
        finally:
            self.stop_server(server_a, thread_a, temp_a)
            self.stop_server(server_b, thread_b, temp_b)

    def test_expired_invoice_timeout_handling(self) -> None:
        server, thread, node, temp_dir = self.start_server()
        try:
            merchant = http_json(f"{node}/wallets/create", method="POST", payload={"owner": "Merchant"})
            invoice = http_json(
                f"{node}/merchant/invoices",
                method="POST",
                payload={
                    "merchant_address": merchant["address"],
                    "amount": 3.0,
                    "description": "Short lived order",
                    "expires_in": 1,
                },
            )
            time.sleep(1.2)
            expired = http_json(f"{node}/merchant/invoices/{invoice['invoice_id']}")
            self.assertEqual(expired["status"], "expired")
            self.assertTrue(expired["status_snapshot"]["expired"])

            listed = http_json(f"{node}/merchant/invoices")
            self.assertEqual(listed["invoices"][0]["status"], "expired")
        finally:
            self.stop_server(server, thread, temp_dir)

    def test_user_register_login_and_history(self) -> None:
        server, thread, node, temp_dir = self.start_server()
        try:
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
            register_request = urllib.request.Request(
                f"{node}/register",
                data=json.dumps({"username": "alice", "password": "password123"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            register_payload = json.loads(opener.open(register_request).read().decode("utf-8"))
            alice_address = register_payload["wallet"]["address"]

            merchant_request = urllib.request.Request(
                f"{node}/register",
                data=json.dumps({"username": "merchant", "password": "password123"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            merchant_payload = json.loads(opener.open(merchant_request).read().decode("utf-8"))
            merchant_address = merchant_payload["wallet"]["address"]

            http_json(
                f"{node}/airdrop",
                method="POST",
                payload={"recipient": alice_address, "amount": 25.0, "reference": "signup-bonus"},
            )

            login_request = urllib.request.Request(
                f"{node}/login",
                data=json.dumps({"username": "alice", "password": "password123"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            opener.open(login_request).read()

            wallet_payload = json.loads(opener.open(f"{node}/me/wallet").read().decode("utf-8"))
            self.assertEqual(wallet_payload["address"], alice_address)
            self.assertEqual(wallet_payload["balance"], 25.0)

            send_request = urllib.request.Request(
                f"{node}/me/send",
                data=json.dumps(
                    {"recipient": merchant_address, "amount": 4.0, "reference": "first-order"}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            send_payload = json.loads(opener.open(send_request).read().decode("utf-8"))
            self.assertEqual(send_payload["status"], "accepted")

            history_payload = json.loads(opener.open(f"{node}/me/history").read().decode("utf-8"))
            self.assertEqual(len(history_payload["items"]), 2)
            self.assertEqual(history_payload["items"][0]["status"], "pending")

            wallet_html = opener.open(f"{node}/wallet").read().decode("utf-8")
            self.assertIn("Personal account, personal wallet, live history.", wallet_html)
        finally:
            self.stop_server(server, thread, temp_dir)

    def test_blockchain_state_persists_across_restart(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(temp_dir.name) / "megacoin.db"
        server = create_server("127.0.0.1", 0, node=Node("127.0.0.1", 0, db_path=db_path))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.1)
        node_url = f"http://127.0.0.1:{server.server_port}"
        try:
            alice = http_json(f"{node_url}/wallets/create", method="POST", payload={"owner": "Alice"})
            validator = http_json(f"{node_url}/wallets/create", method="POST", payload={"owner": "Validator"})
            http_json(f"{node_url}/airdrop", method="POST", payload={"recipient": alice["address"], "amount": 10})
            http_json(f"{node_url}/airdrop", method="POST", payload={"recipient": validator["address"], "amount": 15})
            http_json(f"{node_url}/stake", method="POST", payload={"address": validator["address"], "amount": 10})
            http_json(f"{node_url}/forge", method="POST", payload={})
        finally:
            server.shutdown()
            server.node.live_feed.stop()
            server.server_close()
            thread.join(timeout=2)

        server2 = create_server("127.0.0.1", 0, node=Node("127.0.0.1", 0, db_path=db_path))
        thread2 = threading.Thread(target=server2.serve_forever, daemon=True)
        thread2.start()
        time.sleep(0.1)
        node_url2 = f"http://127.0.0.1:{server2.server_port}"
        try:
            status = http_json(f"{node_url2}/status")
            self.assertGreaterEqual(status["blocks"], 4)
            chain = http_json(f"{node_url2}/chain")
            self.assertEqual(chain["consensus"], "proof-of-stake")
        finally:
            server2.shutdown()
            server2.node.live_feed.stop()
            server2.server_close()
            thread2.join(timeout=2)
            temp_dir.cleanup()

    def test_websocket_receives_live_transaction_event(self) -> None:
        server, thread, node, temp_dir = self.start_server()
        try:
            status = http_json(f"{node}/status")
            ws_url = f"ws://127.0.0.1:{status['websocket_port']}"
            alice = http_json(f"{node}/wallets/create", method="POST", payload={"owner": "Alice"})
            bob = http_json(f"{node}/wallets/create", method="POST", payload={"owner": "Bob"})
            http_json(f"{node}/airdrop", method="POST", payload={"recipient": alice["address"], "amount": 12})

            with ws_connect(ws_url) as websocket:
                websocket.recv()
                tx = Transaction(sender=alice["address"], recipient=bob["address"], amount=2.0)
                wallet = Wallet(owner=alice["owner"], public_key_hex=alice["public_key_hex"], private_key_hex=alice["private_key_hex"])
                tx.sign(wallet)
                http_json(f"{node}/transactions", method="POST", payload=tx.to_dict())
                event = json.loads(websocket.recv(timeout=2))
                self.assertEqual(event["event"], "transaction")
        finally:
            self.stop_server(server, thread, temp_dir)


if __name__ == "__main__":
    unittest.main()
