# Notebooks

## `01_model_training_experiments.ipynb`

Comparison of four gradient-boosting / tree ensembles for multiclass network-flow
classification. All numbers below are copied from the saved cell outputs of the notebook.

### Data

| Item | Value |
|---|---|
| Input file | `astra_processed_dataset.csv` (not included in this repository) |
| Rows | 2,520,590 |
| Features | 32 (engineered and selected from CICFlowMeter flow features) |
| Classes | 7: Bots, Brute Force, DDoS, DoS, Normal Traffic, Port Scanning, Web Attacks |
| Split | 80 / 20, stratified, `random_state=42` (504,118 test rows) |
| Scaling | `StandardScaler`, fitted on the training split only |

Class counts (full dataset): Bots 1,948; Brute Force 9,150; DDoS 128,014; DoS 193,745;
Normal Traffic 2,094,896; Port Scanning 90,694; Web Attacks 2,143.

### Training setup

- **Random Forest:** trained on a resampled set. Each training class was capped at 50,000
  rows, then `SMOTETomek(random_state=42)` was applied. Hyperparameters: 100 trees,
  `max_depth=20`, `min_samples_split=5`, `min_samples_leaf=2`, `class_weight='balanced'`.
- **LightGBM, XGBoost, CatBoost:** trained on the full (unresampled) scaled training split.
  - LightGBM: 500 estimators, `max_depth=8`, `num_leaves=63`, learning rate 0.1, subsample 0.8, colsample 0.8, `class_weight='balanced'`.
  - XGBoost: 500 estimators, `max_depth=8`, learning rate 0.1, subsample 0.8, colsample 0.8.
  - CatBoost: 500 iterations, depth 8, learning rate 0.1, `auto_class_weights='Balanced'`.

### Results (test split, 504,118 rows)

Random Forest overall (weighted): accuracy 98.94%, precision 99.70%, recall 98.94%, F1 99.28%.

Macro-averaged F1 from the per-class reports (2-decimal precision as printed):

| Model | Macro F1 |
|---|---|
| Random Forest | 0.84 |
| LightGBM | 0.94 |
| XGBoost | 0.94 |
| CatBoost | 0.89 |

The weakest class for every model is **Bots** (389 test rows). Random Forest reaches
recall 0.99 but precision 0.09 on it; XGBoost has precision 0.82 and recall 0.50.
Web Attacks (429 test rows) is the second weakest for Random Forest and CatBoost
(precision 0.59 and 0.67). Accuracy of LightGBM, XGBoost and CatBoost prints as 1.00
at two decimals, so it is not quoted here to more precision.

### Relation to the deployed models

This notebook is an **experiment**. It does **not** produce the files in `artifacts/`.
The shipped API uses 51 CICFlowMeter features, a `RobustScaler`, five classes
(benign, bruteforce, ddos, dos, portscan) and a Random Forest with default depth plus an
XGBoost model with 100 trees. The training code for those artifacts is not in this
repository, so the metrics above must not be quoted as the performance of the shipped models.

### Running

```bash
pip install pandas numpy matplotlib seaborn scikit-learn imbalanced-learn lightgbm xgboost catboost
# place astra_processed_dataset.csv next to the notebook, then run all cells
```
