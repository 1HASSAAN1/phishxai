import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

# -----------------------------
# CONFIG
# -----------------------------
DATA_PATH = os.path.join("data", "phish_dataset.csv")
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "phish_tfidf_logreg.joblib")

TEXT_COL = "text"     # CSV column for message/URL text
LABEL_COL = "label"   # CSV column for label: 0 = safe, 1 = phish


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {DATA_PATH}. Create it with columns '{TEXT_COL}' and '{LABEL_COL}'."
        )

    df = pd.read_csv(DATA_PATH)

    if TEXT_COL not in df.columns or LABEL_COL not in df.columns:
        raise ValueError(
            f"CSV must contain columns: '{TEXT_COL}' and '{LABEL_COL}'. Found: {list(df.columns)}"
        )

    X = df[TEXT_COL].astype(str).fillna("")
    y = df[LABEL_COL].astype(int)

    # train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Model pipeline
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            max_features=50000
        )),
        ("clf", LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            solver="lbfgs"
        ))
    ])

    pipe.fit(X_train, y_train)

    preds = pipe.predict(X_test)

    print("\n=== Classification Report ===")
    print(classification_report(y_test, preds, digits=4))

    print("\n=== Confusion Matrix ===")
    print(confusion_matrix(y_test, preds))

    # Save model
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)
    print(f"\n✅ Saved model -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
