"""
model.py
--------
Machine Learning engine for phishing URL detection.
Trains a Random Forest classifier on URL-derived features,
persists the model to disk, and provides prediction utilities.
"""

import os
import csv
import json
import pickle
import logging
from datetime import datetime

# We defer heavy imports until needed so the app starts fast
# even if scikit-learn isn't installed yet.

MODEL_PATH   = os.path.join(os.path.dirname(__file__), "models", "phishing_rf.pkl")
DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "data.csv")

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════
#  MODEL MANAGEMENT
# ══════════════════════════════════════════════

def get_model():
    """
    Load the trained model from disk, or train a fresh one if it doesn't exist.
    Returns the (model, scaler) tuple.
    """
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    if os.path.exists(MODEL_PATH):
        logger.info("Loading existing model from %s", MODEL_PATH)
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)

    logger.info("No saved model found – training a new one …")
    return train_model()


def train_model(save: bool = True):
    """
    Train a Random Forest classifier on the CSV dataset.
    Performs an 80/20 train-test split and logs accuracy.
    Returns (model, scaler).
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    from utils.feature_extractor import build_ml_feature_vector

    # ── Load dataset ───────────────────────────
    X, y = [], []
    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                vec = build_ml_feature_vector(row["url"].strip())
                X.append(vec)
                y.append(int(row["label"]))
            except Exception as e:
                logger.warning("Skipping row due to error: %s", e)

    if len(X) < 10:
        raise ValueError("Dataset too small to train. Add more samples to dataset/data.csv")

    # ── Split ──────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # ── Scale ──────────────────────────────────
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── Train Random Forest ────────────────────
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=2,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train_s, y_train)

    # ── Evaluate ───────────────────────────────
    preds  = model.predict(X_test_s)
    report = classification_report(y_test, preds, target_names=["Legitimate", "Phishing"])
    logger.info("Model training complete:\n%s", report)
    print("\n📊 Model Evaluation Report:\n" + report)

    accuracy = model.score(X_test_s, y_test)
    logger.info("Test accuracy: %.2f%%", accuracy * 100)

    # ── Persist ────────────────────────────────
    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump((model, scaler), f)
        logger.info("Model saved to %s", MODEL_PATH)
        # Save training metadata
        meta = {
            "trained_at": datetime.utcnow().isoformat(),
            "samples": len(X),
            "accuracy": round(accuracy, 4),
            "model_type": "RandomForestClassifier",
            "features": 24,
        }
        meta_path = MODEL_PATH.replace(".pkl", "_meta.json")
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

    return model, scaler


# ══════════════════════════════════════════════
#  PREDICTION
# ══════════════════════════════════════════════

def predict_url(url: str, model_tuple=None) -> dict:
    """
    Predict whether a URL is phishing.

    Returns:
        {
          "ml_score":    float (0.0 – 1.0),   # probability of being phishing
          "ml_label":    str,                   # "Phishing" or "Legitimate"
          "confidence":  float,                 # same as ml_score * 100
          "feature_importances": list[dict],    # top important features
        }
    """
    from utils.feature_extractor import build_ml_feature_vector, ML_FEATURE_NAMES

    if model_tuple is None:
        model_tuple = get_model()

    model, scaler = model_tuple
    vec = build_ml_feature_vector(url)
    vec_scaled = scaler.transform([vec])

    proba = model.predict_proba(vec_scaled)[0]
    phishing_prob = float(proba[1])          # index 1 = phishing class
    label = "Phishing" if phishing_prob >= 0.5 else "Legitimate"

    # ── Feature importances (top 5) ────────────
    importances = []
    if hasattr(model, "feature_importances_"):
        pairs = sorted(
            zip(ML_FEATURE_NAMES, model.feature_importances_),
            key=lambda x: x[1], reverse=True
        )
        importances = [
            {"feature": name, "importance": round(imp, 4)}
            for name, imp in pairs[:5]
        ]

    return {
        "ml_score":            round(phishing_prob, 4),
        "ml_label":            label,
        "confidence":          round(phishing_prob * 100, 1),
        "feature_importances": importances,
    }


def get_model_info() -> dict:
    """Return metadata about the currently loaded model."""
    meta_path = MODEL_PATH.replace(".pkl", "_meta.json")
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            return json.load(f)
    return {"status": "Model metadata not found. Run train_model() first."}
