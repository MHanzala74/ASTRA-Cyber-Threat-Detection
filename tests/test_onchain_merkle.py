"""
Checks that Python-built Merkle proofs verify inside the real Solidity contract,
using an in-memory EVM (eth-tester). Skipped if eth-tester is not installed.
"""
import json
from pathlib import Path

import pytest

pytest.importorskip("eth_tester")
from web3 import Web3, EthereumTesterProvider  # noqa: E402

from app.merkle import build_tree, from_hex, get_proof, hash_leaf, to_hex  # noqa: E402

BUILD = Path(__file__).resolve().parent.parent / "build" / "contracts"


def _deploy(w3, name):
    art = json.loads((BUILD / f"{name}.json").read_text())
    c = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    rcpt = w3.eth.wait_for_transaction_receipt(c.constructor().transact({"from": w3.eth.accounts[0]}))
    return w3.eth.contract(address=rcpt.contractAddress, abi=art["abi"])


@pytest.fixture()
def w3():
    return Web3(EthereumTesterProvider())


@pytest.mark.parametrize("n", [1, 2, 5, 16, 33])
def test_python_proof_verifies_on_chain(w3, n):
    anchor = _deploy(w3, "MerkleAnchor")
    leaves = [hash_leaf({"i": i, "v": "dos"}) for i in range(n)]
    levels = build_tree(leaves)
    anchor.functions.anchorBatch(levels[-1][0], n).transact({"from": w3.eth.accounts[0]})

    for i in range(n):
        proof = get_proof(levels, i)
        assert anchor.functions.verify(0, leaves[i], proof).call()

    forged = hash_leaf({"i": 0, "v": "benign"})
    assert not anchor.functions.verify(0, forged, get_proof(levels, 0)).call()


def test_only_owner_can_anchor(w3):
    anchor = _deploy(w3, "MerkleAnchor")
    with pytest.raises(Exception):
        anchor.functions.anchorBatch(b"\x01" * 32, 1).transact({"from": w3.eth.accounts[1]})
