"""OPTIONAL: anchor a ledger hash on an Ethereum test network (Ganache / Sepolia).

Not used by default and NOT tested in the delivered zip (needs `pip install web3` and a running node).
Usage:  ETH_RPC=http://127.0.0.1:8545 python -c "from app.eth_anchor import anchor; print(anchor('abcd...'))"
Only the block hash is sent (as transaction data) - no personal data.
"""
import os


def anchor(block_hash_hex):
    from web3 import Web3  # imported lazily so the project runs without web3
    w3 = Web3(Web3.HTTPProvider(os.getenv("ETH_RPC", "http://127.0.0.1:8545")))
    acct = w3.eth.accounts[0]  # Ganache unlocked account
    tx = w3.eth.send_transaction({"from": acct, "to": acct, "value": 0,
                                  "data": "0x" + block_hash_hex})
    return w3.to_hex(tx)
