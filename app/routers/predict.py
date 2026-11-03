"""
ASTRA - Single Flow Prediction Router
"""

import numpy as np
import pandas as pd
from fastapi import APIRouter, HTTPException

from app.schemas import NetworkFlow, ThreatPrediction
from app.models import model_manager, EXPECTED_COLS, SEVERITY_MAP, RESPONSE_MAP
from app.blockchain import blockchain
from app.logger import logger

router = APIRouter()

# ── Alias map (field names with slashes) ────────────────────────────────
_ALIAS_MAP = {
    "Flow_Bytes_per_s":     "Flow_Bytes/s",
    "Flow_Packets_per_s":   "Flow_Packets/s",
    "Bwd_Packets_per_s":    "Bwd_Packets/s",
    "Down_Up_Ratio":        "Down/Up_Ratio",
    "Fwd_Avg_Bytes_Bulk":   "Fwd_Avg_Bytes/Bulk",
    "Fwd_Avg_Packets_Bulk": "Fwd_Avg_Packets/Bulk",
    "Bwd_Avg_Bytes_Bulk":   "Bwd_Avg_Bytes/Bulk",
    "Bwd_Avg_Packets_Bulk": "Bwd_Avg_Packets/Bulk",
}


def flow_to_array(flow: NetworkFlow) -> np.ndarray:
    """Convert a NetworkFlow Pydantic model into a (1, 51) numpy array."""
    raw = flow.model_dump(by_alias=True)

    for old, new in _ALIAS_MAP.items():
        if old in raw:
            raw[new] = raw.pop(old)

    df = pd.DataFrame([raw]).reindex(columns=EXPECTED_COLS, fill_value=0.0)
    return df.values.astype(np.float64)


def make_verdict(rf_label: str, xgb_label: str) -> str:
    """
    Ensemble decision logic:
    - Agreement  → return agreed label
    - One benign → return the threat (safer choice)
    - Both threats differ → prefer RF
    """
    if rf_label == xgb_label:
        return rf_label
    if rf_label == "benign":
        return xgb_label
    if xgb_label == "benign":
        return rf_label
    return rf_label  # Both threats differ: trust RF


@router.post("/predict", response_model=ThreatPrediction, summary="Analyze a single network flow")
def predict_single(flow: NetworkFlow):
    """
    Perform threat analysis on a **single** network flow.

    - Dual-model ensemble: **Random Forest + XGBoost**
    - Returns severity level and recommended response action
    - Threats are automatically logged to the blockchain
    """
    if not model_manager.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded. Try again shortly.")

    X        = flow_to_array(flow)
    X_scaled = model_manager.scaler.transform(X)
    result   = model_manager.predict(X_scaled)

    rf_label  = result["rf_predictions"][0]
    xgb_label = result["xgb_predictions"][0]
    verdict   = make_verdict(rf_label, xgb_label)

    prediction = ThreatPrediction(
        rf_prediction=rf_label,
        xgb_prediction=xgb_label,
        rf_confidence=round(result["rf_confidence"][0], 4),
        xgb_confidence=round(result["xgb_confidence"][0], 4),
        final_verdict=verdict,
        severity=SEVERITY_MAP.get(verdict, "unknown"),
        recommended_action=RESPONSE_MAP.get(verdict, "Investigate manually."),
        is_threat=(verdict != "benign"),
    )

    if prediction.is_threat:
        tx = blockchain.log_threat(prediction.model_dump())
        if tx:
            logger.info("Threat '%s' logged on blockchain: %s...", verdict, tx[:20])

    return prediction
