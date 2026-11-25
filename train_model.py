"""
Train the phishing URL ensemble using the local Dataset.csv file.

Run with: python train_model.py
"""

import os
import sys
import warnings

warnings.filterwarnings("ignore")

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "Dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "ensemble_model.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
FEATURES_PATH = os.path.join(MODELS_DIR, "feature_columns.joblib")

SELECTED_FEATURES = [
    "url_length",
    "average_subdomain_length",
    "entropy_of_url",
    "entropy_of_domain",
    "domain_length",
    "number_of_subdomains",
    "number_of_special_char_in_url",
    "number_of_digits_in_domain",
    "number_of_dots_in_domain",
    "number_of_digits_in_url",
    "number_of_slash_in_url",
    "number_of_dots_in_url",
    "path_length",
    "number_of_hyphens_in_domain",
    "number_of_hyphens_in_url",
    "having_digits_in_domain",
    "number_of_equal_in_url",
    "number_of_digits_in_subdomain",
    "having_repeated_digits_in_domain",
    "having_digits_in_subdomain",
    "number_of_questionmark_in_url",
    "number_of_special_characters_in_domain",
    "number_of_underline_in_url",
    "having_query",
    "having_repeated_digits_in_url",
]


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)

    print("=" * 60)
    print("  Phishing URL Detector - Local Dataset Training")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print("ERROR: Dataset.csv was not found in:", BASE_DIR)
        sys.exit(1)

    print("\n[1/5] Loading Dataset.csv ...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    print("      Loaded: {:,} rows x {} columns".format(*df.shape))

    if "Type" not in df.columns:
        print("ERROR: Dataset.csv does not contain the required 'Type' label.")
        sys.exit(1)

    missing = [column for column in SELECTED_FEATURES if column not in df.columns]
    if missing:
        print("ERROR: Missing required dataset features:", missing)
        sys.exit(1)

    print("\n[2/5] Selecting features and preprocessing ...")
    df = df[["Type"] + SELECTED_FEATURES].copy()
    df.dropna(inplace=True)

    y = pd.to_numeric(df["Type"], errors="raise").astype(int)
    if set(y.unique()) != {0, 1}:
        print("ERROR: 'Type' must contain only labels 0 and 1.")
        sys.exit(1)

    X = df[SELECTED_FEATURES].apply(pd.to_numeric, errors="raise")
    print("      Selected features:", len(SELECTED_FEATURES))
    print("      Usable rows      :", "{:,}".format(len(df)))
    print("      Class balance    :", y.value_counts().sort_index().to_dict())

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\n[3/5] Training Random Forest + XGBoost ensemble ...")
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
    ensemble.fit(X_train_scaled, y_train)
    print("      Training complete [OK]")

    print("\n[4/5] Evaluating on test set ...")
    y_pred = ensemble.predict(X_test_scaled)
    y_proba = ensemble.predict_proba(X_test_scaled)[:, 1]
    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)

    print("      Accuracy : {:.4f} ({:.2f}%)".format(accuracy, accuracy * 100))
    print("      ROC-AUC  : {:.4f}".format(auc))
    report = classification_report(
        y_test,
        y_pred,
        target_names=["Legitimate", "Phishing"],
        output_dict=False,
    )
    print("\n" + str(report))
    print("      Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print("        TN={:>6}  FP={}".format(cm[0, 0], cm[0, 1]))
    print("        FN={:>6}  TP={}".format(cm[1, 0], cm[1, 1]))

    print("\n[5/5] Saving model artifacts ...")
    joblib.dump(ensemble, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(SELECTED_FEATURES, FEATURES_PATH)
    print("      Model   ->", MODEL_PATH)
    print("      Scaler  ->", SCALER_PATH)
    print("      Columns ->", FEATURES_PATH)

    print("\n[DONE] Training pipeline finished successfully!")
    print("       Accuracy: {:.2f}% | AUC: {:.4f}".format(accuracy * 100, auc))
    print("       Run 'python app.py' to start the web server.\n")


if __name__ == "__main__":
    main()
