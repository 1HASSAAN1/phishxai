import os
import numpy as np
import joblib

from flask import Flask, request, jsonify
from flask_cors import CORS

# Optional XAI libs (graceful if not installed)
try:
    import shap
    SHAP_AVAILABLE = True
except Exception:
    SHAP_AVAILABLE = False

try:
    from lime.lime_text import LimeTextExplainer
    LIME_AVAILABLE = True
except Exception:
    LIME_AVAILABLE = False


# -----------------------------
# APP SETUP
# -----------------------------
app = Flask(__name__)
CORS(app)

ALLOWED_CHANNELS = {"email", "sms", "url"}
MAX_TEXT_LEN = 20000
MAX_URL_LEN = 2048

MODEL_PATH = os.path.join("models", "phish_tfidf_logreg.joblib")

model = None
shap_explainer = None
lime_explainer = None


# -----------------------------
# HELPERS
# -----------------------------
def error_response(message: str, status_code: int = 400, details=None):
    payload = {"ok": False, "error": message}
    if details is not None:
        payload["details"] = details
    return jsonify(payload), status_code


def ensure_model_loaded():
    """
    Load model + explainers once (lazy init).
    """
    global model, shap_explainer, lime_explainer

    if model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. Run: python train_model.py"
            )
        model = joblib.load(MODEL_PATH)

    # SHAP explainer (Text masker -> uses model.predict_proba)
    if SHAP_AVAILABLE and shap_explainer is None:
        masker = shap.maskers.Text()
        shap_explainer = shap.Explainer(lambda xs: model.predict_proba(xs), masker)

    # LIME explainer
    if LIME_AVAILABLE and lime_explainer is None:
        lime_explainer = LimeTextExplainer(class_names=["safe", "phish"])


def normalize_input(channel: str, text: str, url: str):
    """
    Returns (input_text, clean_text, clean_url) depending on channel.
    For url channel: input_text is the URL.
    For email/sms: input_text is the text.
    """
    text = (text or "").strip()
    url = (url or "").strip()

    if channel == "url":
        candidate = url or text
        if not candidate:
            raise ValueError("For channel 'url', provide 'url' (preferred) or 'text' containing the URL.")
        if len(candidate) > MAX_URL_LEN:
            raise ValueError(f"URL too long (max {MAX_URL_LEN} characters).")
        clean_url = candidate
        clean_text = ""
        return clean_url, clean_text, clean_url

    # email/sms
    if not text:
        raise ValueError(f"For channel '{channel}', field 'text' is required.")
    if len(text) > MAX_TEXT_LEN:
        raise ValueError(f"Text too long (max {MAX_TEXT_LEN} characters).")
    clean_text = text
    clean_url = ""
    return clean_text, clean_text, None


def shap_explain_text(input_text: str, max_terms: int = 8):
    """
    Returns list of top tokens pushing towards class 1 (phish).
    """
    if not (SHAP_AVAILABLE and shap_explainer is not None):
        return None

    sv = shap_explainer([input_text])

    # sv.values could be:
    # - (1, tokens, classes) or (1, tokens)
    values = sv.values[0]
    tokens = sv.data[0]

    # Determine contributions for class 1 if multi-class array
    contrib = None
    if len(values) > 0 and isinstance(values[0], (list, np.ndarray)):
        # class 1 contributions
        contrib = np.array([v[1] for v in values], dtype=float)
    else:
        contrib = np.array(values, dtype=float)

    # top positive contributions
    idx = np.argsort(contrib)[::-1]
    top = []
    for i in idx[:max_terms]:
        tok = str(tokens[i]).strip()
        if tok:
            top.append({"token": tok, "contribution": float(contrib[i])})
    return top


def lime_explain_text(input_text: str, max_terms: int = 8):
    """
    Returns list of token/phrase weights from LIME.
    Positive weights typically push toward class 1 depending on model output.
    """
    if not (LIME_AVAILABLE and lime_explainer is not None):
        return None

    exp = lime_explainer.explain_instance(
        input_text,
        classifier_fn=lambda xs: model.predict_proba(xs),
        num_features=max_terms
    )
    items = exp.as_list()
    return [{"token": t, "weight": float(w)} for t, w in items]


# -----------------------------
# ROUTES
# -----------------------------
@app.get("/")
def home():
    return jsonify({
        "ok": True,
        "message": "PhishXAI backend running",
        "endpoints": {"health": "GET /health", "analyze": "POST /api/analyze"}
    })


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/api/analyze")
def analyze():
    # 1) Ensure request is JSON
    if not request.is_json:
        return error_response(
            "Request must be JSON. Set header Content-Type: application/json",
            status_code=415
        )

    data = request.get_json(silent=True)
    if data is None:
        return error_response("Malformed JSON body.", status_code=400)

    # 2) Validate channel
    channel = (data.get("channel") or "").strip().lower()
    if channel not in ALLOWED_CHANNELS:
        return error_response(
            "Invalid channel. Use one of: email, sms, url",
            status_code=400,
            details={"channel": channel}
        )

    # 3) Validate content
    text = data.get("text")
    url = data.get("url")

    try:
        ensure_model_loaded()
        input_text, clean_text, clean_url = normalize_input(channel, text, url)
    except FileNotFoundError as e:
        return error_response(str(e), status_code=500)
    except ValueError as e:
        return error_response(str(e), status_code=400)
    except Exception as e:
        return error_response("Failed to initialise model.", status_code=500, details=str(e) if app.debug else None)

    # 4) ML prediction
     # 4) ML prediction (with correct class mapping)
    proba = model.predict_proba([input_text])[0]
    classes = list(getattr(model, "classes_", [0, 1]))  # safer

    p_safe = float(proba[classes.index(0)]) if 0 in classes else float(proba[0])
    p_phish = float(proba[classes.index(1)]) if 1 in classes else float(proba[-1])

    # Demo-friendly threshold (tiny datasets often output low probabilities)
    THRESHOLD = 0.35

    # Keyword guardrail (helps your demo + makes sense academically as hybrid system)
    KEYWORDS = ["urgent", "verify", "password", "login", "invoice", "payment", "account", "transaction"]
    blob = input_text.lower()
    keyword_hit = any(k in blob for k in KEYWORDS)

    if keyword_hit and p_phish < THRESHOLD:
        # bump risk a bit so obvious phish doesn't look "safe"
        p_phish = max(p_phish, 0.60)

    verdict = "Suspicious" if (p_phish >= THRESHOLD or keyword_hit) else "Safe"
    risk = p_phish
    confidence = float(max(p_safe, p_phish))

    reasons = [
        "ML model: TF-IDF + Logistic Regression.",
        f"Decision threshold: {THRESHOLD:.2f}.",
    ]
    if keyword_hit:
        reasons.append("Heuristic guardrail: suspicious keywords detected.")
    else:
        reasons.append("No strong heuristic keyword indicators detected.")


    # 5) XAI
    xai_payload = {"available": {"shap": SHAP_AVAILABLE, "lime": LIME_AVAILABLE}}
    try:
        shap_top = shap_explain_text(input_text, max_terms=8)
        lime_top = lime_explain_text(input_text, max_terms=8)

        if shap_top is not None:
            xai_payload["shap_top_tokens"] = shap_top
        if lime_top is not None:
            xai_payload["lime_top_tokens"] = lime_top
    except Exception as e:
        # don't fail the whole API if explanation fails
        xai_payload["warning"] = "XAI generation failed."
        if app.debug:
            xai_payload["details"] = str(e)

    # 6) Response
    return jsonify({
        "ok": True,
        "channel": channel,
        "input": {
            "text": clean_text if channel != "url" else None,
            "url": clean_url if channel == "url" else None
        },
        "result": {
            "verdict": verdict,
            "risk": risk,
            "confidence": confidence,
            "probabilities": {"safe": p_safe, "phish": p_phish},
            "reasons": reasons
        },
        "xai": xai_payload
    })


# -----------------------------
# ERROR HANDLERS
# -----------------------------
@app.errorhandler(404)
def not_found(_):
    return error_response("Endpoint not found.", status_code=404)


@app.errorhandler(500)
def server_error(e):
    details = str(e) if app.debug else None
    return error_response("Internal server error.", status_code=500, details=details)


if __name__ == "__main__":
    print("🚀 Flask server starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
