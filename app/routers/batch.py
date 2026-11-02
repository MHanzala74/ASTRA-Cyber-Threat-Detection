import io
from collections import Counter

import numpy as np
import pandas as pd
from fastapi import APIRouter, File, HTTPException, UploadFile

from app.models import EXPECTED_COLS, model_manager
from app.schemas import BatchPrediction, BatchRequest, ThreatPrediction
from app.services.prediction_service import build_batch_prediction, flow_to_array

router = APIRouter()


@router.post("/predict/batch", response_model=BatchPrediction)
def predict_batch(request: BatchRequest):
    """Analyze multiple network flows together (JSON body). Max 1000."""
    return build_batch_prediction(request.flows)


@router.post("/predict/csv", response_model=BatchPrediction)
async def predict_csv(file: UploadFile = File(...)):
    """Upload a CSV file and get batch predictions. Max 5000 rows."""
    if not model_manager.is_ready():
        raise HTTPException(status_code=503, detail="Models are not loaded yet.")

    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are allowed.")

    contents = await file.read()

    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"CSV parse error: {exc}") from exc

    if len(df) > 5000:
        raise HTTPException(status_code=400, detail="Max 5000 rows per CSV.")

    df.columns = df.columns.str.strip()
    df = df.reindex(columns=EXPECTED_COLS, fill_value=0.0).fillna(0.0)

    try:
        X_scaled = model_manager.scaler.transform(df.values.astype(np.float64))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Scaling error: {exc}") from exc

    result = model_manager.predict(X_scaled)
    predictions = []
    for index in range(len(result["rf_predictions"])):
        rf_label = result["rf_predictions"][index]
        xgb_label = result["xgb_predictions"][index]
        verdict = next(
            (
                rf_label if rf_label == xgb_label else (xgb_label if rf_label == "benign" else rf_label)
            ),
            rf_label,
        )
        predictions.append(
            ThreatPrediction(
                rf_prediction=rf_label,
                xgb_prediction=xgb_label,
                rf_confidence=round(result["rf_confidence"][index], 4),
                xgb_confidence=round(result["xgb_confidence"][index], 4),
                final_verdict=verdict,
                severity="none" if verdict == "benign" else "critical",
                recommended_action="No action required." if verdict == "benign" else "Investigate manually.",
                is_threat=(verdict != "benign"),
            )
        )

    for prediction in predictions:
        if prediction.is_threat:
            pass

    summary = dict(Counter(prediction.final_verdict for prediction in predictions))

    return BatchPrediction(
        total_flows=len(predictions),
        threats_found=sum(1 for prediction in predictions if prediction.is_threat),
        results=predictions,
        summary=summary,
    )
