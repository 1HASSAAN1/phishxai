import os
import re
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, confusion_matrix


# -----------------------------
# CONFIG (match your Kaggle file)
# -----------------------------
DATA_PATH = os.path.join("data", "Phishing_Email.csv")   # put Kaggle file here
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "phish_hash_sgd.joblib")

TEXT_COL = "Email Text"
LABEL_COL = "Email Type"

# Optional: cap super long emails (prevents one giant email blowing RAM/time)
MAX_CHARS = 20000


def clean_text(s: str) -> str:
    if not isinstance(s, str):
        return ""
    s = s[:MAX_CHARS]
    s = s.replace("\x00", " ")
    # collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()
    return s


def label_to_int(x: str) -> int:
    x = str(x).strip().lower()
    # dataset uses "Safe Email" vs "Phishing Email"
    if "phish" in x:
        return 1
    return 0


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {DATA_PATH}.\n"
            f"Put your Kaggle file here: backend/data/Phishing_Email.csv"
        )

    df = pd.read_csv(DATA_PATH)

    if TEXT_COL not in df.columns or LABEL_COL not in df.columns:
        raise ValueError(
            f"CSV must contain columns '{TEXT_COL}' and '{LABEL_COL}'. "
            f"Found: {list(df.columns)}"
        )

    # Drop missing rows safely
    df = df.dropna(subset=[TEXT_COL, LABEL_COL]).copy()

    X = df[TEXT_COL].map(clean_text)
    y = df[LABEL_COL].map(label_to_int).astype(int)

    # train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Memory-safe pipeline (no vocabulary stored)
    pipe = Pipeline([
        ("vec", HashingVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            alternate_sign=False,   # important for linear models stability
            n_features=2**18,       # 262k features (safe); can try 2**17 if needed
            norm="l2"
        )),
        ("clf", SGDClassifier(
            loss="log_loss",        # logistic regression equivalent
            alpha=1e-5,
            max_iter=2000,
            tol=1e-3,
            class_weight="balanced",
            random_state=42
        ))
    ])

    pipe.fit(X_train, y_train)
    preds = pipe.predict(X_test)

    print("\n=== Classification Report ===")
    print(classification_report(y_test, preds, digits=4))

    print("\n=== Confusion Matrix ===")
    print(confusion_matrix(y_test, preds))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)
    print(f"\n✅ Saved model -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
