"""ASTRA - Blockchain Router."""

from fastapi import APIRouter, HTTPException

from app.blockchain import blockchain

router = APIRouter()


@router.get("/blockchain/status")
def blockchain_status():
    """Check the blockchain connection status."""
    stats = blockchain.get_stats()

    if not stats.get("enabled"):
        return {
            "status": "disabled",
            "message": "Ganache is not running or CONTRACT_ADDRESS is missing in the environment.",
            "details": stats,
        }

    return {"status": "connected", "message": "Blockchain is active.", **stats}


@router.get("/blockchain/logs")
def get_blockchain_logs():
    """Fetch all threat logs stored on the blockchain."""
    if not blockchain.is_ready():
        raise HTTPException(
            status_code=503,
            detail="Blockchain is not connected. Start Ganache and set CONTRACT_ADDRESS.",
        )

    logs = blockchain.get_all_logs()
    return {"total": len(logs), "logs": logs}


@router.get("/blockchain/logs/{record_id}")
def get_single_log(record_id: int):
    """Fetch a specific record from the blockchain."""
    if not blockchain.is_ready():
        raise HTTPException(status_code=503, detail="Blockchain is not connected.")

    all_logs = blockchain.get_all_logs()

    if record_id >= len(all_logs) or record_id < 0:
        raise HTTPException(status_code=404, detail=f"Record {record_id} not found.")

    return all_logs[record_id]
