"""
ASTRA - Blockchain Router
Endpoints for reading threat logs stored on-chain.
"""

from fastapi import APIRouter, HTTPException
from app.blockchain import blockchain

router = APIRouter()


@router.get("/blockchain/status", summary="Blockchain connection status")
def blockchain_status():
    """Check whether the blockchain node is reachable and the contract is deployed."""
    stats = blockchain.get_stats()

    if not stats.get("enabled"):
        return {
            "status": "disabled",
            "message": "Ganache is not running or CONTRACT_ADDRESS is missing in .env.",
            "details": stats,
        }

    return {
        "status":  "connected",
        "message": "Blockchain is active ✅",
        **stats,
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
