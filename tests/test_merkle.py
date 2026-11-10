import pytest

from app.merkle import (
    MerkleBatcher, build_tree, get_proof, hash_leaf, merkle_root,
    to_hex, verify_proof,
)


def _rec(i):
    return {"final_verdict": "ddos", "severity": "critical", "rf_confidence": 0.9 + i / 1000, "n": i}


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 13, 50])
def test_every_leaf_has_valid_proof(n):
    leaves = [hash_leaf(_rec(i)) for i in range(n)]
    levels = build_tree(leaves)
    root = levels[-1][0]
    assert root == merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        assert verify_proof(leaf, get_proof(levels, i), root)


def test_proof_length_is_logarithmic():
    leaves = [hash_leaf(_rec(i)) for i in range(64)]
    assert len(get_proof(build_tree(leaves), 10)) == 6


def test_tampered_leaf_fails():
    leaves = [hash_leaf(_rec(i)) for i in range(8)]
    levels = build_tree(leaves)
    fake = hash_leaf({**_rec(3), "final_verdict": "benign"})
    assert not verify_proof(fake, get_proof(levels, 3), levels[-1][0])


def test_canonical_hash_ignores_key_order():
    assert hash_leaf({"a": 1, "b": 2}) == hash_leaf({"b": 2, "a": 1})


def test_empty_tree_rejected():
    with pytest.raises(ValueError):
        build_tree([])


def test_batcher_seals_anchors_and_detects_tampering(tmp_path):
    calls = []

    def fake_anchor(root, count):
        calls.append((root, count))
        return {"batch_id": len(calls) - 1, "tx_hash": "0xabc", "gas_used": 50_000}

    b = MerkleBatcher(tmp_path / "m.jsonl", batch_size=4)
    ids = [b.add(_rec(i), fake_anchor) for i in range(4)]

    assert len(calls) == 1 and calls[0][1] == 4
    assert b.stats()["anchored_batches"] == 1
    assert b.stats()["avg_gas_per_record"] == 12_500

    ok = b.verify_record(ids[2], _rec(2))
    assert ok["valid"] and ok["status"] == "anchored"

    bad = b.verify_record(ids[2], {**_rec(2), "severity": "none"})
    assert not bad["valid"]


def test_batcher_pending_and_flush(tmp_path):
    b = MerkleBatcher(tmp_path / "m.jsonl", batch_size=10)
    rid = b.add(_rec(0))
    assert b.get_proof_bundle(rid)["status"] == "pending"
    batch = b.flush()                       # no anchor fn -> sealed but unanchored
    assert batch is not None and not batch.anchored
    assert b.get_proof_bundle(rid)["status"] == "sealed_unanchored"

    n = b.retry_unanchored(lambda r, c: {"batch_id": 0, "tx_hash": "0x1", "gas_used": 1})
    assert n == 1 and b.get_proof_bundle(rid)["status"] == "anchored"


def test_batcher_survives_restart(tmp_path):
    path = tmp_path / "m.jsonl"
    b1 = MerkleBatcher(path, batch_size=2)
    b1.add(_rec(0), lambda r, c: {"batch_id": 0, "tx_hash": "0x1", "gas_used": 10})
    b1.add(_rec(1), lambda r, c: {"batch_id": 0, "tx_hash": "0x1", "gas_used": 10})
    b1.add(_rec(2))                          # left pending

    b2 = MerkleBatcher(path, batch_size=2)
    assert b2.stats()["total_records"] == 3
    assert b2.stats()["pending_records"] == 1
    assert b2.verify_record(0, _rec(0))["valid"]
    assert b2.add(_rec(3)) == 3              # ids continue, no collision
