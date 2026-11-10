"""
ASTRA - Single Flow Prediction Router
"""

import numpy as np
import pandas as pd
from fastapi import APIRouter, HTTPException, Query

from app.schemas import ExplainedPrediction, NetworkFlow, ThreatPrediction
from app.explain import explain_flow
from app.models import model_manager, EXPECTED_COLS, SEVERITY_MAP, RESPONSE_MAP
from app.event_logger import record_threat
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


def _analyze(flow: NetworkFlow):
    """Run the ensemble on one flow. Returns (prediction, X_raw, X_scaled)."""
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
    return prediction, X, X_scaled


@router.post("/predict", response_model=ThreatPrediction, summary="Analyze a single network flow")
def predict_single(flow: NetworkFlow):
    """
    Perform threat analysis on a **single** network flow.

    - Dual-model ensemble: **Random Forest + XGBoost**
    - Returns severity level and recommended response action
    - Threats are automatically logged to the blockchain
    """
    prediction, _, _ = _analyze(flow)

    if prediction.is_threat:
        ref = record_threat(prediction.model_dump(exclude={"audit_record_id"}))
        if ref and ref.get("mode") == "merkle":
            prediction.audit_record_id = ref["record_id"]

    return prediction


@router.post(
    "/predict/explain",
    response_model=ExplainedPrediction,
    summary="Analyze a flow and explain WHY (TreeSHAP feature contributions)",
)
def predict_explain(flow: NetworkFlow, top_k: int = Query(8, ge=1, le=51, description="Top features to return")):
    """
    Same detection as `/predict`, plus an **exact TreeSHAP explanation** of the
    verdict: which flow features pushed the model towards (or away from) the
    detected class, and by how much.

    The explanation is hashed (keccak256) and the hash is committed inside the
    audit record, so the tamper-evident log also proves *why* the decision was made.
    """
    prediction, X_raw, X_scaled = _analyze(flow)
    explanation = explain_flow(X_raw, X_scaled, prediction.final_verdict, top_k=top_k)

    if prediction.is_threat:
        ref = record_threat(
            prediction.model_dump(exclude={"audit_record_id"}),
            extra={
                "explanation_hash": explanation["explanation_hash"],
                "explanation_top_features": [f["feature"] for f in explanation["top_features"][:3]],
            },
        )
        if ref and ref.get("mode") == "merkle":
            prediction.audit_record_id = ref["record_id"]

    return ExplainedPrediction(**prediction.model_dump(), explanation=explanation)
