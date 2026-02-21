import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import precision_recall_curve, classification_report, confusion_matrix


# -----------------------------
# CONFIG
# -----------------------------
DATA_PATH = os.path.join("data", "phish_dataset.csv")
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "phish_model.joblib")
META_PATH  = os.path.join(MODEL_DIR, "phish_meta.json")

TEXT_COL = "text"
LABEL_COL = "label"   # 0 = safe, 1 = phish


def choose_threshold(y_true, p_phish, target_precision=0.95):
    """
    Choose the LOWEST threshold that achieves at least target_precision,
    so we reduce false positives (normal msgs flagged as sus/phish).
    Falls back to 0.5 if target precision can't be reached.
    """
    precisions, recalls, thresholds = precision_recall_curve(y_true, p_phish)
    # thresholds has length = len(precisions)-1
    best = None
    for i, t in enumerate(thresholds):
        prec = precisions[i + 1]
        rec = recalls[i + 1]
        if prec >= target_precision:
            best = (t, prec, rec)
            break

    if best is None:
        return 0.5, float(precisions[-1]), float(recalls[-1])

    t, prec, rec = best
    return float(t), float(prec), float(rec)


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {DATA_PATH}. Expected columns '{TEXT_COL}' and '{LABEL_COL}'."
        )

    df = pd.read_csv(DATA_PATH)

    if TEXT_COL not in df.columns or LABEL_COL not in df.columns:
        raise ValueError(f"CSV must contain columns: '{TEXT_COL}' and '{LABEL_COL}'. Found: {list(df.columns)}")

    X = df[TEXT_COL].astype(str).fillna("")
    y = df[LABEL_COL].astype(int).values

    # Split: train / temp
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    # Split temp: val / test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )

    # Base pipeline
    base_pipe = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            max_features=50000,
            min_df=2  # helps reduce weird one-off tokens
        )),
        ("clf", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            solver="lbfgs"
        ))
    ])

    # Fit base model
    base_pipe.fit(X_train, y_train)

    # Calibrate probabilities (very important!)
    # NOTE: needs an estimator that can be refit; easiest is to calibrate the whole pipeline.
    calib = CalibratedClassifierCV(base_pipe, method="sigmoid", cv=3)
    calib.fit(X_train, y_train)

    # Find threshold that reduces false positives
    p_val = calib.predict_proba(X_val)[:, 1]
    phish_threshold, prec, rec = choose_threshold(y_val, p_val, target_precision=0.95)

    # Also define a "suspicious" band below the phish threshold
    suspicious_threshold = max(0.30, phish_threshold - 0.15)

    # Evaluate on test
    p_test = calib.predict_proba(X_test)[:, 1]
    y_pred_test = (p_test >= phish_threshold).astype(int)

    print("\n=== TEST (Phish threshold) ===")
    print(f"Chosen phish_threshold: {phish_threshold:.4f}  (val precision≈{prec:.3f}, recall≈{rec:.3f})")
    print(classification_report(y_test, y_pred_test, digits=4))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred_test))

    # Save model + metadata
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(calib, MODEL_PATH)

    meta = {
        "text_col": TEXT_COL,
        "label_col": LABEL_COL,
        "thresholds": {
            "suspicious": float(suspicious_threshold),
            "phish": float(phish_threshold),
        }
    }
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"\n✅ Saved model -> {MODEL_PATH}")
    print(f"✅ Saved meta  -> {META_PATH}")


if __name__ == "__main__":
    main()