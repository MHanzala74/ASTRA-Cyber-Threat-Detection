"""
ASTRA — Cross-dataset generalization & robustness evaluation

Why: high accuracy on the dataset a model was trained on says little about how it
behaves on new traffic. This script evaluates the SAVED ASTRA models on any
CICFlowMeter-style CSV (e.g. CSE-CIC-IDS2018 when the models were trained on
CICIDS2017) and reports honest per-class metrics, plus robustness under
evasion-like perturbations.

    # generalization on another dataset
    python scripts/evaluate.py --csv path/to/cse-cic-ids2018.csv --name cic2018

    # + robustness curves (jitter / noise / feature masking)
    python scripts/evaluate.py --csv data.csv --name cic2018 --robustness

Outputs go to docs/evaluation/<name>/ (metrics.json, report.md, confusion_*.png,
robustness.png). Rows whose label the model cannot predict are EXCLUDED and counted
explicitly, and the script refuses to run if too many of the 51 features are missing
(silently zero-filling would make the numbers meaningless).
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_recall_fscore_support)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore")

from app.models import EXPECTED_COLS, model_manager  # noqa: E402
from app.routers.predict import make_verdict  # noqa: E402

# ── Column-name normalisation ─────────────────────────────────────────────
# CICIDS2017 headers differ from the model's names only by spaces/underscores.
# CSE-CIC-IDS2018 uses abbreviated CICFlowMeter-V3 names; map them to the model's names.
ALIASES_2018 = {
    "Tot Fwd Pkts": "Total_Fwd_Packets", "TotLen Fwd Pkts": "Total_Length_of_Fwd_Packets",
    "Fwd Pkt Len Max": "Fwd_Packet_Length_Max", "Fwd Pkt Len Min": "Fwd_Packet_Length_Min",
    "Fwd Pkt Len Mean": "Fwd_Packet_Length_Mean", "Bwd Pkt Len Max": "Bwd_Packet_Length_Max",
    "Bwd Pkt Len Min": "Bwd_Packet_Length_Min", "Flow Byts/s": "Flow_Bytes/s",
    "Flow Pkts/s": "Flow_Packets/s", "Bwd IAT Tot": "Bwd_IAT_Total",
    "Fwd Header Len": "Fwd_Header_Length", "Bwd Header Len": "Bwd_Header_Length",
    "Bwd Pkts/s": "Bwd_Packets/s", "Pkt Len Min": "Min_Packet_Length",
    "Pkt Len Max": "Max_Packet_Length", "Pkt Len Mean": "Packet_Length_Mean",
    "Pkt Len Var": "Packet_Length_Variance",
    "FIN Flag Cnt": "FIN_Flag_Count", "RST Flag Cnt": "RST_Flag_Count",
    "PSH Flag Cnt": "PSH_Flag_Count", "ACK Flag Cnt": "ACK_Flag_Count",
    "URG Flag Cnt": "URG_Flag_Count",
    "Fwd Byts/b Avg": "Fwd_Avg_Bytes/Bulk", "Fwd Pkts/b Avg": "Fwd_Avg_Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd_Avg_Bulk_Rate", "Bwd Byts/b Avg": "Bwd_Avg_Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd_Avg_Packets/Bulk", "Bwd Blk Rate Avg": "Bwd_Avg_Bulk_Rate",
    "Init Fwd Win Byts": "Init_Win_bytes_forward", "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd", "Fwd Seg Size Min": "min_seg_size_forward",
}

# ── Label normalisation → ASTRA classes ───────────────────────────────────
DEFAULT_LABEL_MAP = {
    "benign": "benign",
    "dos hulk": "dos", "dos goldeneye": "dos", "dos slowloris": "dos", "dos slowhttptest": "dos",
    "dos attacks-hulk": "dos", "dos attacks-goldeneye": "dos", "dos attacks-slowloris": "dos",
    "dos attacks-slowhttptest": "dos", "dos": "dos",
    "ddos": "ddos", "ddos attack-hoic": "ddos", "ddos attack-loic-udp": "ddos",
    "ddos attacks-loic-http": "ddos",
    "ftp-patator": "bruteforce", "ssh-patator": "bruteforce", "ftp-bruteforce": "bruteforce",
    "ssh-bruteforce": "bruteforce", "bruteforce": "bruteforce",
    "portscan": "portscan",
    "infiltration": "infiltration", "infilteration": "infiltration",
}

MIN_FEATURE_COVERAGE = 45   # of 51


def _norm(name: str) -> str:
    return str(name).strip().replace(" ", "_")


def load_dataset(csv_path: Path, label_col: str, label_map: dict, nrows: int | None,
                 allow_missing: bool) -> tuple[pd.DataFrame, np.ndarray, dict]:
    df = pd.read_csv(csv_path, nrows=nrows, low_memory=False)
    df.columns = [c.strip() for c in df.columns]

    # find the label column (case-insensitive)
    lab = next((c for c in df.columns if c.lower() == label_col.lower()), None)
    if lab is None:
        raise SystemExit(f"Label column '{label_col}' not found. Columns: {list(df.columns)[:8]}...")

    rename = {c: ALIASES_2018.get(c, _norm(c)) for c in df.columns}
    df = df.rename(columns=rename)
    labels = df.pop(lab if lab in df.columns else rename[lab])

    present = [c for c in EXPECTED_COLS if c in df.columns]
    missing = [c for c in EXPECTED_COLS if c not in df.columns]
    info = {"features_matched": len(present), "features_missing": missing}
    if len(present) < MIN_FEATURE_COVERAGE and not allow_missing:
        raise SystemExit(
            f"Only {len(present)}/51 model features found in the CSV (need >= {MIN_FEATURE_COVERAGE}).\n"
            f"Missing: {missing}\nUse --allow-missing to zero-fill anyway (results will be unreliable)."
        )

    X = df.reindex(columns=EXPECTED_COLS).apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    for c in missing:                      # absent columns are zero-filled (and reported), not row-dropping
        X[c] = 0.0
    X = X.fillna(0.0) if allow_missing else X.dropna()
    labels = labels.loc[X.index].astype(str).str.strip().str.lower().map(
        lambda s: label_map.get(s, f"__unmapped__:{s}"))

    info["rows_read"] = int(len(df))
    info["rows_dropped_nan_inf"] = int(len(df) - len(X))
    return X, labels.values, info


def predict_all(X_scaled: np.ndarray) -> dict[str, np.ndarray]:
    r = model_manager.predict(X_scaled)
    rf, xgb = np.array(r["rf_predictions"]), np.array(r["xgb_predictions"])
    ens = np.array([make_verdict(a, b) for a, b in zip(rf, xgb)])
    return {"random_forest": rf, "xgboost": xgb, "ensemble": ens}


def score(y_true: np.ndarray, y_pred: np.ndarray, classes: list[str]) -> dict:
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=classes, zero_division=0)
    is_atk_t, is_atk_p = y_true != "benign", y_pred != "benign"
    benign = ~is_atk_t
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=[c for c, n in zip(classes, s) if n > 0],
                                   average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=classes, average="weighted", zero_division=0)),
        "attack_recall": float((is_atk_p & is_atk_t).sum() / max(is_atk_t.sum(), 1)),
        "false_positive_rate": float((is_atk_p & benign).sum() / max(benign.sum(), 1)),
        "per_class": {c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i])}
                      for i, c in enumerate(classes)},
    }


# ── Robustness perturbations ─────────────────────────────────────────────
def perturb_jitter(X_raw: np.ndarray, eps: float, rng) -> np.ndarray:
    """Multiplicative jitter in RAW space: emulates an attacker padding packets / adding delay."""
    return X_raw * (1.0 + rng.uniform(-eps, eps, size=X_raw.shape))


def perturb_noise(X_scaled: np.ndarray, sigma: float, rng) -> np.ndarray:
    """Gaussian noise in scaled space (RobustScaler => unit ~ one IQR)."""
    return X_scaled + rng.normal(0.0, sigma, size=X_scaled.shape)


def perturb_mask(X_scaled: np.ndarray, p: float, rng) -> np.ndarray:
    """Randomly knock out features (sensor failure / missing telemetry): scaled 0 == training median."""
    return np.where(rng.random(X_scaled.shape) < p, 0.0, X_scaled)


def robustness_suite(X_raw: np.ndarray, y: np.ndarray, classes: list[str], seed: int = 0) -> dict:
    rng = np.random.default_rng(seed)
    scaler = model_manager.scaler
    X_scaled = scaler.transform(pd.DataFrame(X_raw, columns=EXPECTED_COLS))
    settings = {
        "raw_jitter_eps":     (perturb_jitter, X_raw,    [0.0, 0.05, 0.1, 0.2, 0.5], True),
        "gaussian_noise_sigma": (perturb_noise, X_scaled, [0.0, 0.05, 0.1, 0.25, 0.5], False),
        "feature_mask_prob":  (perturb_mask,   X_scaled, [0.0, 0.05, 0.1, 0.2, 0.3], False),
    }
    out = {}
    for name, (fn, base, levels, raw_space) in settings.items():
        rows = []
        for lv in levels:
            Xp = fn(base, lv, rng)
            if raw_space:
                Xp = scaler.transform(pd.DataFrame(Xp, columns=EXPECTED_COLS))
            preds = predict_all(Xp)
            rows.append({"level": lv, **{m: score(y, p, classes) for m, p in preds.items()}})
        out[name] = rows
    return out


# ── Reporting ────────────────────────────────────────────────────────────
def save_confusion(y, pred, classes, path: Path, title: str):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = confusion_matrix(y, pred, labels=classes)
    cmn = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(classes)), classes, rotation=35, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True"); ax.set_title(title)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=7,
                    color="white" if cmn[i, j] > 0.5 else "black")
    fig.colorbar(im, fraction=0.046); fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def save_robustness_plot(rob: dict, path: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    titles = {"raw_jitter_eps": "Raw-space jitter (± fraction)", "gaussian_noise_sigma": "Gaussian noise σ (IQR units)",
              "feature_mask_prob": "Features masked (probability)"}
    fig, axes = plt.subplots(1, 3, figsize=(14, 3.8), sharey=True)
    for ax, (name, rows) in zip(axes, rob.items()):
        xs = [r["level"] for r in rows]
        for m, style in (("random_forest", "--"), ("xgboost", ":"), ("ensemble", "-")):
            ax.plot(xs, [r[m]["macro_f1"] for r in rows], style, marker="o", label=m)
        ax.set_title(titles[name], fontsize=10); ax.set_xlabel("perturbation level"); ax.grid(alpha=.3)
    axes[0].set_ylabel("macro-F1"); axes[0].legend(fontsize=8)
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def write_report(out: Path, name: str, info: dict, counts: dict, results: dict, rob: dict | None):
    L = [f"# ASTRA evaluation — `{name}`", "",
         f"- Rows read: **{info['rows_read']:,}**, dropped (NaN/inf): **{info['rows_dropped_nan_inf']:,}**",
         f"- Features matched: **{info['features_matched']}/51**"
         + (f" (missing: {', '.join(info['features_missing'])})" if info["features_missing"] else ""),
         f"- Label counts used: {counts['used']}",
         f"- Excluded (label not supported by saved model): {counts['excluded'] or 'none'}", "",
         "## Overall", "", "| Model | Accuracy | Macro-F1 | Weighted-F1 | Attack recall | False-positive rate |", "|---|---|---|---|---|---|"]
    for m, r in results.items():
        L.append(f"| {m} | {r['accuracy']:.4f} | {r['macro_f1']:.4f} | {r['weighted_f1']:.4f} | "
                 f"{r['attack_recall']:.4f} | {r['false_positive_rate']:.4f} |")
    L += ["", "## Per-class (ensemble)", "", "| Class | Precision | Recall | F1 | Support |", "|---|---|---|---|---|"]
    for c, v in results["ensemble"]["per_class"].items():
        L.append(f"| {c} | {v['precision']:.4f} | {v['recall']:.4f} | {v['f1']:.4f} | {v['support']:,} |")
    if rob:
        L += ["", "## Robustness (ensemble macro-F1)", "", "![robustness](robustness.png)", ""]
        for nm, rows in rob.items():
            L.append(f"**{nm}**: " + ", ".join(f"{r['level']}→{r['ensemble']['macro_f1']:.3f}" for r in rows) + "  ")
    (out / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", required=True, type=Path)
    ap.add_argument("--name", default=None, help="output folder name (default: csv stem)")
    ap.add_argument("--label-col", default="Label")
    ap.add_argument("--label-map", type=Path, help="JSON {raw label (lowercase): astra class} to override/extend defaults")
    ap.add_argument("--nrows", type=int, default=None)
    ap.add_argument("--robustness", action="store_true")
    ap.add_argument("--robustness-rows", type=int, default=20000, help="subsample size for robustness runs")
    ap.add_argument("--allow-missing", action="store_true")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "evaluation")
    a = ap.parse_args()

    model_manager.load()
    classes = [str(c) for c in model_manager.le.classes_]

    lmap = dict(DEFAULT_LABEL_MAP)
    if a.label_map:
        lmap.update({k.lower(): v for k, v in json.loads(a.label_map.read_text()).items()})

    X, y, info = load_dataset(a.csv, a.label_col, lmap, a.nrows, a.allow_missing)

    supported = np.isin(y, classes)
    excluded = pd.Series(y[~supported]).value_counts().to_dict()
    X, y = X[supported], y[supported]
    if len(y) == 0:
        raise SystemExit("No rows with labels supported by the model after mapping. Check --label-map.")

    X_scaled = model_manager.scaler.transform(X.reset_index(drop=True))
    preds = predict_all(X_scaled)
    results = {m: score(y, p, classes) for m, p in preds.items()}

    out = a.out / (a.name or a.csv.stem)
    out.mkdir(parents=True, exist_ok=True)
    counts = {"used": pd.Series(y).value_counts().to_dict(), "excluded": excluded}

    for m, p in preds.items():
        save_confusion(y, p, classes, out / f"confusion_{m}.png", f"{m} — {a.name or a.csv.stem}")

    rob = None
    if a.robustness:
        n = min(a.robustness_rows, len(y))
        idx = np.random.default_rng(0).choice(len(y), n, replace=False)
        rob = robustness_suite(X.values[idx], y[idx], classes)
        save_robustness_plot(rob, out / "robustness.png")

    (out / "metrics.json").write_text(json.dumps({"dataset": info, "counts": counts, "results": results,
                                                  "robustness": rob}, indent=2), encoding="utf-8")
    write_report(out, a.name or a.csv.stem, info, counts, results, rob)

    print(f"\nEnsemble: acc={results['ensemble']['accuracy']:.4f}  macro-F1={results['ensemble']['macro_f1']:.4f}  "
          f"attack-recall={results['ensemble']['attack_recall']:.4f}  FPR={results['ensemble']['false_positive_rate']:.4f}")
    print(f"Report written to {out}/report.md")


if __name__ == "__main__":
    main()
