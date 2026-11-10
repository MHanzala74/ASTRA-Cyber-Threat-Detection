"""
ASTRA — Smart Contract Deploy Script

Deploys BOTH contracts from the compiled artifacts in build/contracts/:
    * ThreatLog     – per-record threat logging (LOGGING_MODE=per_record)
    * MerkleAnchor  – Merkle-root anchoring     (LOGGING_MODE=merkle)

No compiler download is needed; artifacts were compiled with solc 0.8.19
(optimizer on, 200 runs) from ThreatLog.sol and MerkleAnchor.sol.

Usage:
    1. Start Ganache:  ganache --port 8545
    2. Run:            python deploy_contract.py
    3. Copy the printed addresses into .env
"""

import json
import os
from pathlib import Path

from web3 import Web3

GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:8545")
BUILD_DIR   = Path(__file__).parent / "build" / "contracts"
CONTRACTS   = [
    ("ThreatLog",    "CONTRACT_ADDRESS"),
    ("MerkleAnchor", "MERKLE_CONTRACT_ADDRESS"),
]


def deploy_one(w3: Web3, name: str) -> str:
    artifact = json.loads((BUILD_DIR / f"{name}.json").read_text())
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])

    tx_hash = contract.constructor().transact({"from": w3.eth.accounts[0], "gas": 3_000_000})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"  ✅ {name:<13} {receipt['contractAddress']}  (gas {receipt['gasUsed']:,})")
    return receipt["contractAddress"]


def deploy():
    print("=" * 60)
    print("  ASTRA — Smart Contract Deployer")
    print("=" * 60)

    missing = [n for n, _ in CONTRACTS if not (BUILD_DIR / f"{n}.json").exists()]
    if missing:
        print(f"❌ Missing build artifacts in {BUILD_DIR}: {missing}")
        return

    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        raise ConnectionError(
            f"❌ Could not connect to {GANACHE_URL}\n"
            "   Run in a new terminal: ganache --port 8545"
        )
    print(f"✅ Connected — {len(w3.eth.accounts)} accounts available\n")

    addresses = {}
    try:
        for name, env_key in CONTRACTS:
            addresses[env_key] = deploy_one(w3, name)
    except Exception as e:
        print(f"\n❌ Deployment failed: {e}")
        print("\n💡 Alternative: deploy ThreatLog.sol / MerkleAnchor.sol with Remix IDE")
        return

    print(f"\n{'=' * 60}\n📋 Add these lines to your .env file:\n")
    for key, addr in addresses.items():
        print(f"   {key}={addr}")
    print("\n   # Optional — enable gas-efficient Merkle batching:")
    print("   LOGGING_MODE=merkle")
    print("=" * 60)
    return addresses


if __name__ == "__main__":
    deploy()
