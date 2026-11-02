"""ASTRA - Health Check Router."""

from fastapi import APIRouter

from app.models import model_manager
from app.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health_check():
    """Check the status of the API and models."""
    ready = model_manager.is_ready()

    return HealthResponse(
        status="ok" if ready else "degraded",
        models_loaded=ready,
        message="ASTRA API is running. Models loaded."
        if ready
        else "Models are not loaded yet. Call /startup.",
    )
