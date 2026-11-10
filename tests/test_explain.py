import json
from pathlib import Path

import numpy as np
import pytest

from app.explain import explain_flow, explanation_hash
from app.models import EXPECTED_COLS, model_manager

FLOWS = json.loads((Path(__file__).parent / "fixtures" / "threat_flows.json").read_text())


@pytest.fixture(scope="module", autouse=True)
def _models():
    model_manager.load()


def _xy(name):
    X = np.array([[FLOWS[name][c] for c in EXPECTED_COLS]])
    return X, model_manager.scaler.transform(X)


@pytest.mark.parametrize("name", ["dos", "ddos", "portscan", "bruteforce"])
def test_explanation_is_faithful_to_xgboost(name):
    """base + sum(all contributions) -> softmax must equal predict_proba."""
    import xgboost as xgb

    X, Xs = _xy(name)
    label = model_manager.le.inverse_transform(model_manager.xgb.predict(Xs))[0]
    exp = explain_flow(X, Xs, label, top_k=51)

    classes = list(model_manager.le.classes_)
    proba = model_manager.xgb.predict_proba(Xs)[0][classes.index(label)]
    assert exp["xgb_probability"] == pytest.approx(proba, abs=1e-3)

    total = exp["base_value"] + sum(f["contribution"] for f in exp["top_features"])
    assert total == pytest.approx(exp["class_margin"], abs=5e-3)


def test_top_features_sorted_and_directional():
    X, Xs = _xy("dos")
    exp = explain_flow(X, Xs, "dos", top_k=5)
    mags = [abs(f["contribution"]) for f in exp["top_features"]]
    assert mags == sorted(mags, reverse=True) and len(mags) == 5
    for f in exp["top_features"]:
        assert f["direction"] == ("supports" if f["contribution"] > 0 else "opposes")
        assert f["feature"] in EXPECTED_COLS


def test_hash_changes_when_explanation_changes():
    X, Xs = _xy("dos")
    exp = explain_flow(X, Xs, "dos")
    assert exp["explanation_hash"] == explanation_hash(exp)
    tampered = json.loads(json.dumps(exp))
    tampered["top_features"][0]["contribution"] += 0.5
    assert explanation_hash(tampered) != exp["explanation_hash"]


def test_unknown_target_label_falls_back_to_xgb_class():
    X, Xs = _xy("dos")
    exp = explain_flow(X, Xs, "infiltration")      # not a class the saved XGBoost knows
    assert exp["target_class"] in list(model_manager.le.classes_)
