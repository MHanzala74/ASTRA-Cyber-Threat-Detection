from __future__ import annotations

import numpy as np
import pandas as pd
from fastapi import HTTPException

from app.blockchain import blockchain
from app.models import RESPONSE_MAP, SEVERITY_MAP, EXPECTED_COLS, model_manager
from app.schemas import BatchPrediction, NetworkFlow, ThreatPrediction


def flow_to_array(flow: NetworkFlow) -> np.ndarray:
    """Convert a Pydantic model into a 51-feature numpy array."""
    raw = flow.model_dump(by_alias=True)

    rename = {
        "Flow_Bytes_per_s": "Flow_Bytes/s",
        "Flow_Packets_per_s": "Flow_Packets/s",
        "Bwd_Packets_per_s": "Bwd_Packets/s",
        "Down_Up_Ratio": "Down/Up_Ratio",
        "Fwd_Avg_Bytes_Bulk": "Fwd_Avg_Bytes/Bulk",
        "Fwd_Avg_Packets_Bulk": "Fwd_Avg_Packets/Bulk",
        "Bwd_Avg_Bytes_Bulk": "Bwd_Avg_Bytes/Bulk",
        "Bwd_Avg_Packets_Bulk": "Bwd_Avg_Packets/Bulk",
    }

    for old, new in rename.items():
        if old in raw:
            raw[new] = raw.pop(old)

    df = pd.DataFrame([raw]).reindex(columns=EXPECTED_COLS, fill_value=0.0)
    return df.values.astype(np.float64)


def make_verdict(rf_label: str, xgb_label: str) -> str:
    """Prefer the threat when the models disagree; otherwise keep the common label."""
    if rf_label == xgb_label:
        return rf_label

    if rf_label == "benign":
        return xgb_label
    if xgb_label == "benign":
        return rf_label

    return rf_label


def build_prediction_result(result: dict) -> list[ThreatPrediction]:
    preds: list[ThreatPrediction] = []

    for i in range(len(result["rf_predictions"])):
        rf_label = result["rf_predictions"][i]
        xgb_label = result["xgb_predictions"][i]
        verdict = make_verdict(rf_label, xgb_label)

        preds.append(
            ThreatPrediction(
                rf_prediction=rf_label,
                xgb_prediction=xgb_label,
                rf_confidence=round(result["rf_confidence"][i], 4),
                xgb_confidence=round(result["xgb_confidence"][i], 4),
                final_verdict=verdict,
                severity=SEVERITY_MAP.get(verdict, "unknown"),
                recommended_action=RESPONSE_MAP.get(verdict, "Investigate manually."),
                is_threat=(verdict != "benign"),
            )
        )

    return preds


def predict_single_flow(flow: NetworkFlow) -> ThreatPrediction:
    if not model_manager.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded yet.")

    X = flow_to_array(flow)
    X_scaled = model_manager.scaler.transform(X)
    result = model_manager.predict(X_scaled)
    prediction = build_prediction_result(result)[0]

    if prediction.is_threat:
        tx_hash = blockchain.log_threat(prediction.model_dump())
        if tx_hash:
            pass

    return prediction


def log_threats_to_blockchain(predictions: list[ThreatPrediction]) -> None:
    for prediction in predictions:
        if prediction.is_threat:
            blockchain.log_threat(prediction.model_dump())


def build_batch_prediction(flows: list[NetworkFlow]) -> BatchPrediction:
    if not model_manager.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded yet.")

    if len(flows) > 1000:
        raise HTTPException(status_code=400, detail="Max 1000 flows per request.")

    X = np.vstack([flow_to_array(flow) for flow in flows])
    X_scaled = model_manager.scaler.transform(X)
    predictions = build_prediction_result(model_manager.predict(X_scaled))
    log_threats_to_blockchain(predictions)

    summary = {}
    for prediction in predictions:
        summary[prediction.final_verdict] = summary.get(prediction.final_verdict, 0) + 1

    return BatchPrediction(
        total_flows=len(predictions),
        threats_found=sum(1 for prediction in predictions if prediction.is_threat),
        results=predictions,
        summary=summary,
    )
