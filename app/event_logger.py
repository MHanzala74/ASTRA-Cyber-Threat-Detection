"""
ASTRA — Threat Event Logger

Single entry point used by all prediction routers. Depending on LOGGING_MODE:

    per_record : one on-chain transaction per threat (original behaviour)
    merkle     : record is added to a Merkle batch; only the batch root is
                 anchored on-chain (far lower gas cost per record)
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional

from app.blockchain import blockchain
from app.config import settings
from app.logger import logger
from app.merkle import MerkleBatcher

_batcher: Optional[MerkleBatcher] = None
_lock = threading.Lock()


def get_batcher() -> MerkleBatcher:
    global _batcher
    with _lock:
        if _batcher is None:
            _batcher = MerkleBatcher(
                settings.merkle_store_path,
                batch_size=settings.merkle_batch_size,
                max_age_seconds=settings.merkle_flush_seconds,
            )
        return _batcher


def record_threat(prediction: dict, extra: Optional[dict] = None) -> Optional[dict]:
    """
    Log one detected threat. Returns a small reference dict, or None if nothing was logged.

    `extra` is merged into the record before hashing (e.g. the explanation hash),
    so it becomes part of the tamper-evident audit trail.
    """
    if settings.merkle_enabled:
        record = {
            **{k: v for k, v in prediction.items() if k != "audit_record_id"},
            **(extra or {}),
            "logged_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        rid = get_batcher().add(record, blockchain.anchor_batch)
        return {"mode": "merkle", "record_id": rid}

    tx = blockchain.log_threat(prediction)
    if tx:
        logger.info("Threat '%s' logged on blockchain: %s...", prediction.get("final_verdict"), tx[:20])
        return {"mode": "per_record", "tx_hash": tx}
    return None


def flush_pending() -> Optional[dict]:
    """Seal + anchor any buffered records (used by timer, shutdown, and API)."""
    b = get_batcher()
    batch = b.flush(blockchain.anchor_batch)
    retried = b.retry_unanchored(blockchain.anchor_batch)
    return {"sealed_batch": batch.batch_id if batch else None, "retried_unanchored": retried}
