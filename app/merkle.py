"""
ASTRA — Merkle Batching Module

Novelty: instead of writing every detected threat on-chain (one transaction per
record), ASTRA hashes records into a Merkle tree off-chain and anchors only the
32-byte root of each batch on the blockchain. Any record can later be proven to
belong to an anchored batch with a logarithmic-size proof, so tamper-evidence is
preserved while gas cost per record drops roughly by the batch size.

Conventions (compatible with the on-chain `MerkleAnchor.verify`):
    leaf   = keccak256(0x00 || canonical_json(record))   # 0x00 = domain separation
    parent = keccak256(min(a, b) || max(a, b))            # sorted pair, no direction flags
    An odd node at a level is promoted unchanged to the next level.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from eth_utils import keccak

from app.logger import logger

LEAF_PREFIX = b"\x00"


# ══════════════════════════════════════════════════════════════════════
#  Pure Merkle functions
# ══════════════════════════════════════════════════════════════════════
def canonical_json(record: dict) -> bytes:
    """Deterministic serialisation so the same record always hashes the same."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_leaf(record: dict) -> bytes:
    return keccak(LEAF_PREFIX + canonical_json(record))


def _hash_pair(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a <= b else keccak(b + a)


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """Return all tree levels, level 0 = leaves, last level = [root]."""
    if not leaves:
        raise ValueError("Cannot build a Merkle tree with no leaves")

    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur, nxt = levels[-1], []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur):
                nxt.append(_hash_pair(cur[i], cur[i + 1]))
            else:
                nxt.append(cur[i])  # odd node promoted
        levels.append(nxt)
    return levels


def merkle_root(leaves: list[bytes]) -> bytes:
    return build_tree(leaves)[-1][0]


def get_proof(levels: list[list[bytes]], index: int) -> list[bytes]:
    """Sibling hashes needed to rebuild the root from leaf `index`."""
    if not 0 <= index < len(levels[0]):
        raise IndexError("leaf index out of range")

    proof = []
    for level in levels[:-1]:
        sibling = index ^ 1
        if sibling < len(level):
            proof.append(level[sibling])
        index //= 2
    return proof


def verify_proof(leaf: bytes, proof: list[bytes], root: bytes) -> bool:
    computed = leaf
    for sibling in proof:
        computed = _hash_pair(computed, sibling)
    return computed == root


def to_hex(b: bytes) -> str:
    return "0x" + b.hex()


def from_hex(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


# ══════════════════════════════════════════════════════════════════════
#  Persistent batcher
# ══════════════════════════════════════════════════════════════════════
@dataclass
class SealedBatch:
    batch_id: int
    root: str
    record_ids: list[int]
    sealed_at: float
    tx_hash: Optional[str] = None
    onchain_batch_id: Optional[int] = None
    gas_used: Optional[int] = None

    @property
    def anchored(self) -> bool:
        return self.onchain_batch_id is not None


@dataclass
class _Entry:
    record_id: int
    record: dict
    leaf: str  # hex


# anchor_fn(root_bytes, leaf_count) -> {"batch_id": int, "tx_hash": str, "gas_used": int} | None
AnchorFn = Callable[[bytes, int], Optional[dict]]


class MerkleBatcher:
    """
    Collects threat records, seals them into Merkle batches and anchors roots.

    State is persisted in an append-only JSONL journal so proofs survive restarts
    and unsealed records are not lost.
    """

    def __init__(self, store_path: Path, batch_size: int = 50, max_age_seconds: int = 30):
        self.store_path = Path(store_path)
        self.batch_size = batch_size
        self.max_age_seconds = max_age_seconds
        self._lock = threading.RLock()

        self._entries: dict[int, _Entry] = {}
        self._batches: dict[int, SealedBatch] = {}
        self._record_batch: dict[int, int] = {}
        self._pending: list[int] = []
        self._pending_since: Optional[float] = None
        self._next_record_id = 0
        self._next_batch_id = 0

        self._load()

    # ── persistence ───────────────────────────────────────────────────
    def _append(self, obj: dict) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self.store_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, sort_keys=True) + "\n")

    def _load(self) -> None:
        if not self.store_path.exists():
            return
        for line in self.store_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            o = json.loads(line)
            if o["type"] == "record":
                self._entries[o["record_id"]] = _Entry(o["record_id"], o["record"], o["leaf"])
                self._pending.append(o["record_id"])
                self._next_record_id = max(self._next_record_id, o["record_id"] + 1)
            elif o["type"] == "batch":
                b = SealedBatch(**{k: v for k, v in o.items() if k != "type"})
                self._batches[b.batch_id] = b
                for rid in b.record_ids:
                    self._record_batch[rid] = b.batch_id
                sealed = set(b.record_ids)
                self._pending = [r for r in self._pending if r not in sealed]
                self._next_batch_id = max(self._next_batch_id, b.batch_id + 1)
            elif o["type"] == "anchor":
                b = self._batches.get(o["batch_id"])
                if b:
                    b.tx_hash = o["tx_hash"]
                    b.onchain_batch_id = o["onchain_batch_id"]
                    b.gas_used = o.get("gas_used")
        if self._pending:
            self._pending_since = time.time()
        logger.info("Merkle store loaded: %d records, %d batches, %d pending",
                    len(self._entries), len(self._batches), len(self._pending))

    # ── public API ────────────────────────────────────────────────────
    def add(self, record: dict, anchor_fn: Optional[AnchorFn] = None) -> int:
        """Add a record. Seals + anchors automatically when the batch is full."""
        with self._lock:
            rid = self._next_record_id
            self._next_record_id += 1
            leaf = to_hex(hash_leaf(record))

            self._entries[rid] = _Entry(rid, record, leaf)
            self._pending.append(rid)
            if self._pending_since is None:
                self._pending_since = time.time()
            self._append({"type": "record", "record_id": rid, "record": record, "leaf": leaf})

            if len(self._pending) >= self.batch_size:
                self.flush(anchor_fn)
            return rid

    def flush(self, anchor_fn: Optional[AnchorFn] = None) -> Optional[SealedBatch]:
        """Seal all pending records into one batch and try to anchor its root."""
        with self._lock:
            if not self._pending:
                return None

            ids = list(self._pending)
            leaves = [from_hex(self._entries[i].leaf) for i in ids]
            root = merkle_root(leaves)

            batch = SealedBatch(
                batch_id=self._next_batch_id,
                root=to_hex(root),
                record_ids=ids,
                sealed_at=time.time(),
            )
            self._next_batch_id += 1
            self._batches[batch.batch_id] = batch
            for i in ids:
                self._record_batch[i] = batch.batch_id
            self._pending, self._pending_since = [], None
            self._append({"type": "batch", **batch.__dict__})

            self._try_anchor(batch, anchor_fn)
            return batch

    def flush_if_stale(self, anchor_fn: Optional[AnchorFn] = None) -> Optional[SealedBatch]:
        with self._lock:
            if self._pending and self._pending_since and \
               time.time() - self._pending_since >= self.max_age_seconds:
                return self.flush(anchor_fn)
        return None

    def retry_unanchored(self, anchor_fn: Optional[AnchorFn]) -> int:
        """Anchor batches that were sealed while the chain was unavailable."""
        n = 0
        with self._lock:
            for b in self._batches.values():
                if not b.anchored and self._try_anchor(b, anchor_fn):
                    n += 1
        return n

    def _try_anchor(self, batch: SealedBatch, anchor_fn: Optional[AnchorFn]) -> bool:
        if anchor_fn is None:
            return False
        res = anchor_fn(from_hex(batch.root), len(batch.record_ids))
        if not res:
            return False
        batch.tx_hash = res["tx_hash"]
        batch.onchain_batch_id = res["batch_id"]
        batch.gas_used = res.get("gas_used")
        self._append({
            "type": "anchor", "batch_id": batch.batch_id, "tx_hash": batch.tx_hash,
            "onchain_batch_id": batch.onchain_batch_id, "gas_used": batch.gas_used,
        })
        return True

    # ── queries ───────────────────────────────────────────────────────
    def list_batches(self) -> list[dict]:
        with self._lock:
            return [
                {**b.__dict__, "record_count": len(b.record_ids), "anchored": b.anchored}
                for b in sorted(self._batches.values(), key=lambda x: x.batch_id)
            ]

    def stats(self) -> dict:
        with self._lock:
            anchored = [b for b in self._batches.values() if b.anchored]
            gas = [b.gas_used for b in anchored if b.gas_used]
            sealed_records = sum(len(b.record_ids) for b in anchored)
            return {
                "total_records": len(self._entries),
                "pending_records": len(self._pending),
                "sealed_batches": len(self._batches),
                "anchored_batches": len(anchored),
                "records_anchored": sealed_records,
                "avg_gas_per_record": (sum(gas) / sealed_records) if gas and sealed_records else None,
                "batch_size": self.batch_size,
            }

    def get_proof_bundle(self, record_id: int) -> Optional[dict]:
        """Everything needed to verify one record independently."""
        with self._lock:
            if record_id not in self._entries:
                return None
            entry = self._entries[record_id]
            bid = self._record_batch.get(record_id)
            if bid is None:
                return {"record_id": record_id, "record": entry.record, "leaf": entry.leaf,
                        "status": "pending", "proof": [], "root": None, "batch_id": None}

            batch = self._batches[bid]
            levels = build_tree([from_hex(self._entries[i].leaf) for i in batch.record_ids])
            idx = batch.record_ids.index(record_id)
            return {
                "record_id": record_id,
                "record": entry.record,
                "leaf": entry.leaf,
                "status": "anchored" if batch.anchored else "sealed_unanchored",
                "proof": [to_hex(p) for p in get_proof(levels, idx)],
                "root": batch.root,
                "batch_id": batch.batch_id,
                "onchain_batch_id": batch.onchain_batch_id,
                "tx_hash": batch.tx_hash,
            }

    def verify_record(self, record_id: int, submitted_record: dict) -> Optional[dict]:
        """
        Re-hash a *submitted* record and check it against the stored proof/root.
        Any modification of the original record makes verification fail.
        """
        bundle = self.get_proof_bundle(record_id)
        if bundle is None:
            return None
        if bundle["root"] is None:
            return {**bundle, "valid": False, "reason": "Record not sealed into a batch yet"}

        leaf = hash_leaf(submitted_record)
        ok = verify_proof(leaf, [from_hex(p) for p in bundle["proof"]], from_hex(bundle["root"]))
        return {**bundle, "submitted_leaf": to_hex(leaf), "valid": ok,
                "reason": "Record matches Merkle root" if ok else "Record does NOT match — tampered or wrong record"}
