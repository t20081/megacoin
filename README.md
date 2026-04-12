# MegaCoin Demo Network

This project is a small educational MegaCoin prototype written in pure Python.

It includes:

- wallets signed with ECDSA on `secp256k1`
- signed transactions with merchant `reference` fields
- Proof of Stake validator selection
- REST endpoints for transactions, balances, staking, forging, invoices, and peer sync
- simple peer discovery, peer message validation, and basic anti-spam protection
- a CLI wallet with `receive`, `send`, and `balance` commands
- a hosted web wallet UI with QR codes
- a hosted blockchain explorer web app

## Install dependencies

```powershell
python -m pip install ecdsa segno
```

## Run the core demo

```powershell
python D:\crypto_system\crypto_system.py
```

## Run a node

```powershell
python D:\crypto_system\node_server.py --port 8000
```

Add another peer-connected node:

```powershell
python D:\crypto_system\node_server.py --port 8001 --peer http://127.0.0.1:8000
```

Open the browser apps:

- Wallet UI: `http://127.0.0.1:8000/wallet`
- Merchant Dashboard: `http://127.0.0.1:8000/merchant`
- Explorer: `http://127.0.0.1:8000/explorer`

## CLI wallet

Create or reveal a receiving address:

```powershell
python D:\crypto_system\wallet_cli.py receive --wallet D:\crypto_system\alice.json --owner Alice --node http://127.0.0.1:8000
```

Check balance:

```powershell
python D:\crypto_system\wallet_cli.py balance --wallet D:\crypto_system\alice.json --node http://127.0.0.1:8000
```

Send MegaCoin:

```powershell
python D:\crypto_system\wallet_cli.py send --wallet D:\crypto_system\alice.json --to RECEIVER_ADDRESS --amount 5 --reference order-1001 --node http://127.0.0.1:8000
```

## REST API

Useful endpoints for websites and services:

- `POST /wallets/create`
- `POST /wallets/register`
- `POST /wallets/sign-send`
- `POST /transactions`
- `GET /transactions/<tx_id>`
- `GET /balance/<address>`
- `POST /stake`
- `POST /forge`
- `POST /peers`
- `GET /peers/list`
- `POST /sync`
- `POST /airdrop`
- `POST /merchant/invoices`
- `GET /merchant/invoices`
- `GET /merchant/invoices/<invoice_id>`
- `POST /merchant/invoices/<invoice_id>/expire`
- `GET /merchant/status/<invoice_id>`
- `GET /chain`
- `GET /status`
- `GET /qr?text=...`
- `GET /explorer/summary`
- `GET /explorer/search?address=...&reference=...`

## Merchant invoices

Create an invoice:

```powershell
curl -X POST http://127.0.0.1:8000/merchant/invoices `
  -H "Content-Type: application/json" `
  -d "{\"merchant_address\":\"MGC...\",\"amount\":5,\"description\":\"Order 1001\"}"
```

Check invoice status:

```powershell
curl http://127.0.0.1:8000/merchant/invoices/inv_123456789abc
```

The invoice moves from `pending` to `seen` to `confirmed` as matching transactions appear and receive confirmations.
Invoices now use:

- `pending`: waiting for payment, or payment seen but not yet confirmed enough
- `paid`: matching payment received with required confirmations
- `expired`: no qualifying payment arrived before timeout

Each invoice gets a hosted checkout page with QR code and live status polling at `/checkout/<invoice_id>`.

## Run the tests

```powershell
python -m unittest D:\crypto_system\test_crypto_system.py
```

## Notes

This is for learning and prototyping only, not real production security or finance.
