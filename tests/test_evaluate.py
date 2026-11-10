"""
Plumbing tests for scripts/evaluate.py using SYNTHETIC data. Ground truth here is
produced by the model itself, so these tests verify the pipeline (column/label
mapping, coverage guard, metrics, outputs) — not real-world detection accuracy.
"""
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.models import EXPECTED_COLS, model_manager

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("evaluate", ROOT / "scripts" / "evaluate.py")
ev = importlib.util.module_from_spec(spec)
sys.modules["evaluate"] = ev
spec.loader.exec_module(ev)

FLOWS = json.loads((Path(__file__).parent / "fixtures" / "threat_flows.json").read_text())


@pytest.fixture(scope="module", autouse=True)
def _models():
    model_manager.load()


def _make_csv(tmp_path, style="2017", drop=()):
    rng = np.random.default_rng(1)
    rows, labels = [], []
    names = {"dos": "DoS Hulk", "ddos": "DDoS", "portscan": "PortScan", "bruteforce": "FTP-Patator"}
    for k, v in FLOWS.items():
        for _ in range(40):
            rows.append({c: v[c] * (1 + rng.uniform(-0.02, 0.02)) for c in EXPECTED_COLS})
            labels.append(names[k])
    for _ in range(40):
        rows.append({c: 0.0 for c in EXPECTED_COLS}); labels.append("BENIGN")
    rows.append({c: 1.0 for c in EXPECTED_COLS}); labels.append("Bot")          # unmapped label
    df = pd.DataFrame(rows)
    if style == "2018":
        inv = {v: k for k, v in ev.ALIASES_2018.items()}
        df = df.rename(columns={c: inv.get(c, c.replace("_", " ")) for c in df.columns})
    else:
        df.columns = [c.replace("_", " ") for c in df.columns]
    df = df.drop(columns=list(drop))
    df["Label"] = labels
    p = tmp_path / f"d_{style}.csv"
    df.to_csv(p, index=False)
    return p


def test_aliases_cover_valid_model_features():
    assert set(ev.ALIASES_2018.values()) <= set(EXPECTED_COLS)


@pytest.mark.parametrize("style", ["2017", "2018"])
def test_loader_maps_columns_and_labels(tmp_path, style):
    X, y, info = ev.load_dataset(_make_csv(tmp_path, style), "Label", ev.DEFAULT_LABEL_MAP, None, False)
    assert info["features_matched"] == 51 and not info["features_missing"]
    assert set(y) >= {"dos", "ddos", "portscan", "bruteforce", "benign"}
    assert any(str(v).startswith("__unmapped__") for v in y)       # 'Bot' flagged, not silently mapped


def test_refuses_when_too_many_features_missing(tmp_path):
    p = _make_csv(tmp_path, "2017", drop=[c.replace("_", " ") for c in EXPECTED_COLS[:10]])
    with pytest.raises(SystemExit):
        ev.load_dataset(p, "Label", ev.DEFAULT_LABEL_MAP, None, False)


def test_few_missing_features_zero_filled_not_row_dropping(tmp_path):
    p = _make_csv(tmp_path, "2017", drop=[EXPECTED_COLS[0].replace("_", " ")])
    X, y, info = ev.load_dataset(p, "Label", ev.DEFAULT_LABEL_MAP, None, False)
    assert info["features_matched"] == 50 and len(X) == 201


def test_scoring_and_robustness_run(tmp_path):
    X, y, _ = ev.load_dataset(_make_csv(tmp_path), "Label", ev.DEFAULT_LABEL_MAP, None, False)
    classes = [str(c) for c in model_manager.le.classes_]
    m = np.isin(y, classes)
    X, y = X[m], y[m]
    preds = ev.predict_all(model_manager.scaler.transform(X.reset_index(drop=True)))
    res = {k: ev.score(y, p, classes) for k, p in preds.items()}
    assert res["ensemble"]["accuracy"] > 0.8
    assert set(res["ensemble"]["per_class"]) == set(classes)

    rob = ev.robustness_suite(X.values, y, classes)
    assert set(rob) == {"raw_jitter_eps", "gaussian_noise_sigma", "feature_mask_prob"}
    for rows in rob.values():
        assert rows[0]["level"] == 0.0
        # zero perturbation must reproduce the clean score exactly
        assert rows[0]["ensemble"]["accuracy"] == pytest.approx(res["ensemble"]["accuracy"])
        assert rows[-1]["ensemble"]["accuracy"] <= rows[0]["ensemble"]["accuracy"] + 1e-9


def test_cli_end_to_end_writes_outputs(tmp_path, monkeypatch):
    csv = _make_csv(tmp_path, "2018")
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "--csv", str(csv), "--name", "syn", "--out", str(tmp_path / "out"),
                                      "--robustness", "--robustness-rows", "200"])
    ev.main()
    d = tmp_path / "out" / "syn"
    for f in ("metrics.json", "report.md", "robustness.png", "confusion_ensemble.png"):
        assert (d / f).exists(), f
    meta = json.loads((d / "metrics.json").read_text())
    assert meta["counts"]["excluded"], "unmapped 'Bot' rows must be reported as excluded"
