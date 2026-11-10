"""
ASTRA - Blockchain Router
Endpoints for reading threat logs stored on-chain.
"""

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.blockchain import blockchain
from app.config import settings
from app.merkle import from_hex, hash_leaf

router = APIRouter()


@router.get("/blockchain/status", summary="Blockchain connection status")
def blockchain_status():
    """
    Check whether the blockchain node is reachable and the contracts are deployed.
    Also reports the active audit-logging mode (`per_record` or `merkle`).
    """
    stats = blockchain.get_stats()
    mode_info = {
        "logging_mode": settings.logging_mode,
        "threatlog_connected": blockchain.is_ready(),
        "merkle_contract_connected": blockchain.merkle_ready(),
    }

    if not stats.get("enabled"):
        return {
            "status": "disabled" if not blockchain.merkle_ready() else "merkle_only",
            "message": (
                "ThreatLog contract unavailable (Ganache not running or CONTRACT_ADDRESS missing). "
                + ("MerkleAnchor is connected." if blockchain.merkle_ready() else "")
            ).strip(),
            "details": stats,
            **mode_info,
        }

    return {
        "status":  "connected",
        "message": "Blockchain is active ✅",
        **stats,
        **mode_info,
    }


@router.get("/blockchain/logs", summary="Fetch all on-chain threat logs")
def get_blockchain_logs():
    """
    Retrieve all threat records stored on the smart contract.
    Returns an empty list if blockchain logging is disabled.
    """
    if not blockchain.is_ready():
        raise HTTPException(
            status_code=503,
            detail="Blockchain is not connected. Start Ganache and set CONTRACT_ADDRESS in .env.",
        )

    logs = blockchain.get_all_logs()
    return {"total": len(logs), "logs": logs}


@router.get("/blockchain/logs/{record_id}", summary="Fetch a single on-chain record")
def get_single_log(record_id: int):
    """Retrieve one specific threat record by its on-chain index."""
    if not blockchain.is_ready():
        raise HTTPException(status_code=503, detail="Blockchain is not connected.")

    if record_id < 0:
        raise HTTPException(status_code=400, detail="record_id must be a non-negative integer.")

    all_logs = blockchain.get_all_logs()

    if record_id >= len(all_logs):
        raise HTTPException(
            status_code=404,
            detail=f"Record {record_id} not found. Total records: {len(all_logs)}.",
        )

    return all_logs[record_id]


# ══════════════════════════════════════════════════════════════════════
#  Merkle audit trail (LOGGING_MODE=merkle)
# ══════════════════════════════════════════════════════════════════════
def _require_merkle():
    if not settings.merkle_enabled:
        raise HTTPException(
            status_code=409,
            detail="Merkle logging is disabled. Set LOGGING_MODE=merkle in .env and restart.",
        )
    from app.event_logger import get_batcher
    return get_batcher()


@router.get("/blockchain/merkle/stats", summary="Merkle batching statistics")
def merkle_stats():
    """Records, batches, pending buffer and average gas per record."""
    stats = _require_merkle().stats()
    return {**stats, "contract_connected": blockchain.merkle_ready()}


@router.get("/blockchain/merkle/batches", summary="List sealed Merkle batches")
def merkle_batches():
    batches = _require_merkle().list_batches()
    return {"total": len(batches), "batches": batches}


@router.post("/blockchain/merkle/flush", summary="Seal pending records and anchor their root now")
def merkle_flush():
    _require_merkle()
    from app.event_logger import flush_pending
    return flush_pending()


@router.get("/blockchain/merkle/proof/{record_id}", summary="Merkle proof for one audit record")
def merkle_proof(record_id: int):
    """Returns the record, its leaf hash, the sibling-hash proof and the anchored root."""
    bundle = _require_merkle().get_proof_bundle(record_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail=f"Audit record {record_id} not found.")
    return bundle


class VerifyRequest(BaseModel):
    record_id: int
    record: dict[str, Any]


@router.post("/blockchain/merkle/verify", summary="Verify a record against the anchored Merkle root")
def merkle_verify(req: VerifyRequest):
    """
    Re-hash the **submitted** record and check it against the stored proof,
    both locally and (if connected) inside the smart contract.
    Change any field of the original record and verification fails.
    """
    batcher = _require_merkle()
    result = batcher.verify_record(req.record_id, req.record)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Audit record {req.record_id} not found.")

    onchain = None
    if result.get("onchain_batch_id") is not None and result.get("root"):
        onchain = blockchain.verify_onchain(
            result["onchain_batch_id"],
            hash_leaf(req.record),
            [from_hex(p) for p in result["proof"]],
        )

    return {
        "record_id":      req.record_id,
        "valid_local":    result["valid"],
        "valid_onchain":  onchain,   # None = batch not anchored / chain unavailable
        "status":         result["status"],
        "batch_id":       result.get("batch_id"),
        "tx_hash":        result.get("tx_hash"),
        "reason":         result["reason"],
    }
