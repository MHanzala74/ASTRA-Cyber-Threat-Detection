"""
ASTRA - Health Check Router
"""

from fastapi import APIRouter
from app.schemas import HealthResponse
from app.models import model_manager
from app.blockchain import blockchain
from app.config import settings

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="System health check")
def health_check():
    """
    Returns the current status of the API, ML models, and blockchain connection.
    Use this endpoint for load-balancer health probes.
    """
    models_ok     = model_manager.is_ready()
    blockchain_ok = blockchain.is_connected()

    return HealthResponse(
        status="ok" if models_ok else "degraded",
        models_loaded=models_ok,
        blockchain_connected=blockchain_ok,
        version=settings.app_version,
        environment=settings.app_env,
        message=(
            "All systems operational."
            if models_ok
            else "Models not yet loaded. POST /api/v1/startup or restart the server."
        ),
    )
