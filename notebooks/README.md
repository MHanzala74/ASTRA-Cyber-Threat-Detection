# Notebooks

```
notebooks/
├── pipeline/        reproducible training + evaluation of the shipped 5-class models
│   ├── 01_data_preparation.ipynb
│   ├── 02_model_training.ipynb
│   ├── 03_evaluation.ipynb
│   └── 04_explainability_and_robustness.ipynb
└── experiments/     earlier exploratory comparison (different data, not the shipped models)
    └── 01_model_comparison_7class.ipynb
```

## `pipeline/` — run in order 01 → 02 → 03 → 04

These notebooks train and evaluate the same model family that the API loads from `artifacts/`:
Random Forest + XGBoost, 51 CICFlowMeter features, `RobustScaler`, five classes
(`benign`, `bruteforce`, `ddos`, `dos`, `portscan`), and the ensemble fusion rule from
`app/routers/predict.py`. No resampling (SMOTE) is used.

**Input:** the original CIC-IDS-2017 `MachineLearningCVE` folder (8 CSV files; not included in this repository).

```bash
pip install pandas numpy scikit-learn xgboost joblib matplotlib jupyter
export ASTRA_DATA_DIR=/path/to/MachineLearningCVE      # PowerShell: $env:ASTRA_DATA_DIR="C:\path\to\MachineLearningCVE"
export ASTRA_SMOKE=1                                   # optional: 5% sample for a quick dry run
jupyter lab notebooks/pipeline
```

| Notebook | What it does | Main outputs (in `astra_run/`) |
|---|---|---|
| `01_data_preparation` | load CSVs, keep 51 features, map labels to 5 classes, drop NaN/Inf and duplicate rows, stratified 80/20 split, fit `RobustScaler` on train only | `splits.joblib`, `data_meta.json`, `artifacts/scaler.pkl`, `artifacts/label_encoder.pkl` |
| `02_model_training` | train Random Forest and XGBoost (same hyperparameters as the shipped artifacts) | `artifacts/rf_multiclass.pkl`, `artifacts/xgb_multiclass.pkl`, `training_meta.json` |
| `03_evaluation` | accuracy, macro/weighted P/R/F1, per-class report, confusion matrix, fusion-rule ablation, LaTeX tables | `metrics_eval.json`, `confusion_matrix_ensemble.*`, `tables.tex` |
| `04_explainability_and_robustness` | exact TreeSHAP (top features per class, additivity check), robustness to jitter / Gaussian noise / feature masking, stability of the top-5 SHAP features under perturbation | `robustness_results.json`, `robustness.png`, `shap_stability.png`, `shap_top_features.csv` |

The notebooks are committed **without outputs**: no results are stored in this repository until the
pipeline has been run on the full dataset. All numbers are computed when the notebooks run.
Results from `ASTRA_SMOKE=1` are for checking the setup only.

After a full run, copy the four `.pkl` files from `astra_run/artifacts/` to `artifacts/`, pin the
`scikit-learn` / `xgboost` versions printed by notebook 02 in `requirements.txt`, then run `pytest`.

## `experiments/01_model_comparison_7class.ipynb`

An earlier exploratory comparison of Random Forest, LightGBM, XGBoost and CatBoost on a
2,520,590-row, 7-class, 32-feature dataset (`astra_processed_dataset.csv`, not included).
Saved outputs are kept. It is **not** the pipeline behind `artifacts/` (different features, scaler,
classes and hyperparameters), so its metrics must not be quoted as the performance of the shipped models.

Setup: 80/20 stratified split (`random_state=42`, 504,118 test rows), `StandardScaler`; the Random Forest was
trained after capping each class at 50,000 rows and applying `SMOTETomek`; the other models used the
unresampled training split. The weakest classes for every model are **Bots** (389 test rows) and
**Web Attacks** (429 test rows). For Random Forest, Bots precision is 0.09 at recall 0.99, which is why the
5-class pipeline above excludes both classes.
