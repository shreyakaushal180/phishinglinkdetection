"""
train_model.py
==============
Downloads PhiUSIIL phishing dataset via KaggleHub, preprocesses it,
trains Random Forest + XGBoost ensemble, evaluates it, and saves
artifacts to ./models/.

Run once:  python train_model.py
"""

import os
import sys
import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
import joblib
import kagglehub

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, roc_auc_score
)
from xgboost import XGBClassifier

# ---- Paths ------------------------------------------------------------------
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR  = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

MODEL_PATH    = os.path.join(MODELS_DIR, "ensemble_model.joblib")
SCALER_PATH   = os.path.join(MODELS_DIR, "scaler.joblib")
FEATURES_PATH = os.path.join(MODELS_DIR, "feature_columns.joblib")

# ---- 1. Load Dataset --------------------------------------------------------
print("=" * 60)
print("  PhiUSIIL Phishing URL Detector - Training Pipeline")
print("=" * 60)
print("\n[1/6] Downloading / locating dataset from Kaggle ...")

try:
    dataset_path = kagglehub.dataset_download(
        "kaggleprollc/phishing-url-websites-dataset-phiusiil"
    )
    print("      Dataset folder:", dataset_path)

    # Find the largest CSV file (main dataset)
    csv_files = []
    for root, dirs, files in os.walk(dataset_path):
        for f in files:
            if f.lower().endswith(".csv"):
                csv_files.append(os.path.join(root, f))

    if not csv_files:
        raise FileNotFoundError("No CSV files found under: " + dataset_path)

    csv_path = max(csv_files, key=os.path.getsize)
    size_mb  = os.path.getsize(csv_path) / 1024 / 1024
    print("      File:", os.path.basename(csv_path), " ({:.1f} MB)".format(size_mb))

    df = pd.read_csv(csv_path, low_memory=False)
    print("      Loaded: {:,} rows x {} columns".format(df.shape[0], df.shape[1]))

except Exception as e:
    print("\n  ERROR loading dataset:", e)
    print("  Ensure KAGGLE_USERNAME and KAGGLE_KEY env vars are set,")
    print("  or place kaggle.json at C:\\Users\\<you>\\.kaggle\\kaggle.json")
    sys.exit(1)

# ---- 2. Inspect & identify columns ------------------------------------------
print("\n[2/6] Inspecting dataset ...")
print("      Columns ({}): {} ...".format(len(df.columns), list(df.columns)[:12]))

LABEL_CANDIDATES = [
    "label", "Label", "phishing", "Phishing", "class", "Class",
    "is_phishing", "target", "Target", "status", "Status",
]
label_col = next((c for c in LABEL_CANDIDATES if c in df.columns), df.columns[-1])
print("      Label column  :", label_col)
print("      Label values  :", df[label_col].value_counts().to_dict())

# ---- 3. Preprocessing -------------------------------------------------------
print("\n[3/6] Preprocessing ...")

# Drop all object (text) columns except label
text_cols = [c for c in df.columns if df[c].dtype == object and c != label_col]
print("      Dropping text columns:", text_cols)
df.drop(columns=text_cols, inplace=True, errors="ignore")

# Encode label -> 0 (legitimate) / 1 (phishing)
if df[label_col].dtype == object:
    unique_vals = df[label_col].unique()
    phish_markers = {"phishing", "1", "yes", "bad", "malicious", "phish"}
    pos_val = next(
        (v for v in unique_vals if str(v).lower() in phish_markers),
        unique_vals[0]
    )
    df[label_col] = (df[label_col] == pos_val).astype(int)
else:
    df[label_col] = df[label_col].astype(int)

before = len(df)
df.dropna(inplace=True)
print("      NaN rows dropped: {:,}  (remaining: {:,})".format(before - len(df), len(df)))

X = df.drop(columns=[label_col])
y = df[label_col]

# Remove any stray non-numeric columns
non_num = [c for c in X.columns if X[c].dtype == object]
if non_num:
    print("      Dropping non-numeric:", non_num)
    X.drop(columns=non_num, inplace=True)

feature_columns = list(X.columns)
print("      Feature columns:", len(feature_columns))
print("      Class balance  :", y.value_counts().to_dict())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print("      Train: {:,}  |  Test: {:,}".format(len(X_train), len(X_test)))

scaler     = StandardScaler()
X_train_sc = scaler.fit_transform(X_train)
X_test_sc  = scaler.transform(X_test)

# ---- 4. Train Models --------------------------------------------------------
print("\n[4/6] Training ensemble (Random Forest + XGBoost) ...")
print("      (This may take a few minutes on first run)")

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=4,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced",
)

xgb = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1,
    verbosity=0,
)

ensemble = VotingClassifier(
    estimators=[("rf", rf), ("xgb", xgb)],
    voting="soft",
    n_jobs=-1,
)

ensemble.fit(X_train_sc, y_train)
print("      Training complete [OK]")

# ---- 5. Evaluate ------------------------------------------------------------
print("\n[5/6] Evaluating on test set ...")

y_pred  = ensemble.predict(X_test_sc)
y_proba = ensemble.predict_proba(X_test_sc)[:, 1]
acc     = accuracy_score(y_test, y_pred)
auc     = roc_auc_score(y_test, y_proba)

print("\n      Accuracy : {:.4f}  ({:.2f}%)".format(acc, acc * 100))
print("      ROC-AUC  : {:.4f}".format(auc))
print("\n      Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

cm = confusion_matrix(y_test, y_pred)
print("      Confusion Matrix:")
print("        TN={:>6}  FP={}".format(cm[0, 0], cm[0, 1]))
print("        FN={:>6}  TP={}".format(cm[1, 0], cm[1, 1]))

# ---- 6. Save Artifacts ------------------------------------------------------
print("\n[6/6] Saving model artifacts ...")
joblib.dump(ensemble,        MODEL_PATH)
joblib.dump(scaler,          SCALER_PATH)
joblib.dump(feature_columns, FEATURES_PATH)

print("      Model   ->", MODEL_PATH)
print("      Scaler  ->", SCALER_PATH)
print("      Columns ->", FEATURES_PATH)
print("\n[DONE] Training pipeline finished successfully!")
print("       Accuracy: {:.2f}%  |  AUC: {:.4f}".format(acc * 100, auc))
print("       Run 'python app.py' to start the web server.\n")
