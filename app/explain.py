"""
ASTRA — Explainable Detection (TreeSHAP via XGBoost)

For every prediction ASTRA can say *why* a flow was classified as a threat.
It uses XGBoost's built-in exact TreeSHAP (`pred_contribs=True`), so no extra
dependency is needed. For a target class c the contributions satisfy

    base_value + sum(contributions) = XGBoost margin (log-odds) for class c

and softmax over the per-class margins reproduces `predict_proba` exactly
(verified in tests), so the explanation is faithful to the model, not a surrogate.

The explanation is canonicalised and hashed (keccak256). That hash is stored in
the audit record, so an on-chain / Merkle-anchored record also commits to *why*
the decision was made ("verifiable explainable detection").
"""

from __future__ import annotations

import numpy as np
import xgboost as xgb

from app.merkle import canonical_json, to_hex
from app.models import EXPECTED_COLS, model_manager
from eth_utils import keccak

_ROUND = 4


def explain_flow(X_raw: np.ndarray, X_scaled: np.ndarray, target_label: str, top_k: int = 8) -> dict:
    """
    Explain one flow for `target_label`.

    Args:
        X_raw:    (1, 51) unscaled feature values (shown to the analyst)
        X_scaled: (1, 51) scaled values actually fed to the model
        target_label: class to explain (normally the final verdict)
        top_k: number of features to return, ranked by |contribution|
    """
    classes = list(model_manager.le.classes_)
    if target_label not in classes:
        # e.g. verdict label the XGBoost model has no class for -> explain XGB's own choice
        target_label = str(model_manager.le.inverse_transform(model_manager.xgb.predict(X_scaled))[0])
    cls = classes.index(target_label)

    booster = model_manager.xgb.get_booster()
    contribs = booster.predict(xgb.DMatrix(X_scaled), pred_contribs=True, validate_features=False)
    row = contribs[0, cls, :]                  # (n_features + 1,), last = bias
    phi, base = row[:-1], float(row[-1])

    order = np.argsort(-np.abs(phi))[:top_k]
    top = [{
        "feature":      EXPECTED_COLS[i],
        "value":        round(float(X_raw[0, i]), _ROUND),
        "scaled_value": round(float(X_scaled[0, i]), _ROUND),
        "contribution": round(float(phi[i]), _ROUND),
        "direction":    "supports" if phi[i] > 0 else "opposes",
    } for i in order]

    margins = contribs[0].sum(axis=-1)
    probs = np.exp(margins - margins.max())
    probs /= probs.sum()

    explanation = {
        "method":        "TreeSHAP (XGBoost pred_contribs, exact)",
        "target_class":  target_label,
        "base_value":    round(base, _ROUND),
        "class_margin":  round(float(margins[cls]), _ROUND),
        "xgb_probability": round(float(probs[cls]), _ROUND),
        "top_features":  top,
    }
    explanation["explanation_hash"] = explanation_hash(explanation)
    return explanation


def explanation_hash(explanation: dict) -> str:
    """keccak256 of the canonical explanation (excluding the hash field itself)."""
    body = {k: v for k, v in explanation.items() if k != "explanation_hash"}
    return to_hex(keccak(canonical_json(body)))
