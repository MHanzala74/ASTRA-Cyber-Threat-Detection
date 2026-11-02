"""
ASTRA - Single Flow Prediction Router
"""

from fastapi import APIRouter, HTTPException

from app.models import model_manager
from app.schemas import NetworkFlow, ThreatPrediction
from app.services.prediction_service import predict_single_flow

router = APIRouter()


@router.post("/predict", response_model=ThreatPrediction)
def predict_single(flow: NetworkFlow):
    """Perform threat analysis on a single network flow."""
    if not model_manager.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded yet.")

    return predict_single_flow(flow)
