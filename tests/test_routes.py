from __future__ import annotations

from fastapi.testclient import TestClient

from app.blockchain import blockchain
from app.main import app
from app.models import model_manager

client = TestClient(app)


def test_health_route():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] in {"ok", "degraded"}


def test_predict_route_requires_loaded_models(monkeypatch):
    monkeypatch.setattr(model_manager, "is_ready", lambda: False)
    response = client.post("/api/v1/predict", json={})
    assert response.status_code == 503


def test_predict_route_with_mocked_model(monkeypatch):
    monkeypatch.setattr(model_manager, "is_ready", lambda: True)
    monkeypatch.setattr(model_manager, "scaler", type("Scaler", (), {"transform": lambda self, x: x})())
    monkeypatch.setattr(
        model_manager,
        "predict",
        lambda x: {
            "rf_predictions": ["ddos"],
            "xgb_predictions": ["ddos"],
            "rf_confidence": [0.99],
            "xgb_confidence": [0.97],
        },
    )
    monkeypatch.setattr(blockchain, "log_threat", lambda prediction: "0x1234")

    response = client.post("/api/v1/predict", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["final_verdict"] == "ddos"
    assert body["is_threat"] is True


def test_blockchain_status_degraded_mode():
    response = client.get("/api/v1/blockchain/status")
    assert response.status_code == 200
    assert response.json()["status"] == "disabled"


def test_csv_route_rejects_non_csv(monkeypatch):
    monkeypatch.setattr(model_manager, "is_ready", lambda: True)
    response = client.post(
        "/api/v1/predict/csv",
        files={"file": ("bad.txt", b"not-a-csv", "text/plain")},
    )
    assert response.status_code == 400
