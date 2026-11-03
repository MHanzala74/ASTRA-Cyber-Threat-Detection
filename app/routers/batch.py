"""
ASTRA - Batch Prediction Router
Supports JSON body (up to 1000 flows) and CSV upload (up to 5000 rows).
"""

import io
import numpy as np
import pandas as pd
from collections import Counter
from fastapi import APIRouter, HTTPException, UploadFile, File

from app.schemas import NetworkFlow, ThreatPrediction, BatchRequest, BatchPrediction
from app.models import model_manager, EXPECTED_COLS, SEVERITY_MAP, RESPONSE_MAP
from app.routers.predict import flow_to_array, make_verdict
from app.blockchain import blockchain
from app.logger import logger

router = APIRouter()

MAX_JSON_FLOWS = 1_000
MAX_CSV_ROWS   = 5_000


def _build_predictions(X_scaled: np.ndarray) -> list[ThreatPrediction]:
    result = model_manager.predict(X_scaled)
    preds  = []

    for i in range(len(result["rf_predictions"])):
        rf_label  = result["rf_predictions"][i]
        xgb_label = result["xgb_predictions"][i]
        verdict   = make_verdict(rf_label, xgb_label)

        preds.append(ThreatPrediction(
            rf_prediction=rf_label,
            xgb_prediction=xgb_label,
            rf_confidence=round(result["rf_confidence"][i], 4),
            xgb_confidence=round(result["xgb_confidence"][i], 4),
            final_verdict=verdict,
            severity=SEVERITY_MAP.get(verdict, "unknown"),
            recommended_action=RESPONSE_MAP.get(verdict, "Investigate manually."),
            is_threat=(verdict != "benign"),
        ))

    return preds


def _log_threats(preds: list[ThreatPrediction]):
    """Log only detected threats to the blockchain."""
    logged = sum(
        1 for p in preds
        if p.is_threat and blockchain.log_threat(p.model_dump())
    )
    if logged:
        logger.info("Blockchain: %d threat(s) logged from batch", logged)


def _make_batch_response(preds: list[ThreatPrediction]) -> BatchPrediction:
    return BatchPrediction(
        total_flows=len(preds),
        threats_found=sum(1 for p in preds if p.is_threat),
        results=preds,
        summary=dict(Counter(p.final_verdict for p in preds)),
    )


# ── JSON batch ─────────────────────────────────────────────────────────
@router.post(
    "/predict/batch",
    response_model=BatchPrediction,
    summary=f"Analyze multiple flows (JSON, max {MAX_JSON_FLOWS})",
)
def predict_batch(request: BatchRequest):
    """Analyze up to **1,000** network flows in a single JSON request."""
    if not model_manager.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded yet.")

    if len(request.flows) > MAX_JSON_FLOWS:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {MAX_JSON_FLOWS} flows per request. Received {len(request.flows)}.",
        )

    X        = np.vstack([flow_to_array(f) for f in request.flows])
    X_scaled = model_manager.scaler.transform(X)
    preds    = _build_predictions(X_scaled)

    _log_threats(preds)
    return _make_batch_response(preds)


# ── CSV upload ─────────────────────────────────────────────────────────
@router.post(
    "/predict/csv",
    response_model=BatchPrediction,
    summary=f"Analyze flows from CSV upload (max {MAX_CSV_ROWS} rows)",
)
async def predict_csv(file: UploadFile = File(...)):
    """
    Upload a **.csv** file containing network flow features.
    Columns must match the expected 51-feature schema (missing columns default to 0).
    Maximum **5,000 rows** per upload.
    """
    if not model_manager.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded yet.")

    if not (file.filename or "").endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted.")

    contents = await file.read()

    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV parse error: {e}")

    if len(df) > MAX_CSV_ROWS:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {MAX_CSV_ROWS} rows per file. Received {len(df)}.",
        )

    df.columns = df.columns.str.strip()
    df = df.reindex(columns=EXPECTED_COLS, fill_value=0.0).fillna(0.0)

    try:
        X_scaled = model_manager.scaler.transform(df.values.astype(np.float64))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Feature scaling error: {e}")

    preds = _build_predictions(X_scaled)

    _log_threats(preds)
    logger.info("CSV prediction: %d flows, %d threats", len(preds), sum(1 for p in preds if p.is_threat))
    return _make_batch_response(preds)
