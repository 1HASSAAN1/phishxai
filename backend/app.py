from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

ALLOWED_CHANNELS = {"email", "sms", "url"}
MAX_TEXT_LEN = 20000   # protect server from huge pastes
MAX_URL_LEN = 2048

def error_response(message: str, status_code: int = 400, details=None):
    payload = {"ok": False, "error": message}
    if details is not None:
        payload["details"] = details
    return jsonify(payload), status_code

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

    # 2) Validate 'channel'
    channel = (data.get("channel") or "").strip().lower()
    if channel not in ALLOWED_CHANNELS:
        return error_response(
            "Invalid channel. Use one of: email, sms, url",
            status_code=400,
            details={"channel": channel}
        )

    # 3) Validate input content
    text = (data.get("text") or "").strip()
    url = (data.get("url") or "").strip()

    # For url channel: allow either url field OR text containing the url
    if channel == "url":
        candidate = url or text
        if not candidate:
            return error_response(
                "For channel 'url', provide 'url' (preferred) or 'text' containing the URL.",
                status_code=400
            )
        if len(candidate) > MAX_URL_LEN:
            return error_response(
                f"URL too long (max {MAX_URL_LEN} characters).",
                status_code=400
            )
        # normalize
        url = candidate
        text = ""  # keep clean: url channel uses url field

    else:
        # email/sms require text
        if not text:
            return error_response(
                f"For channel '{channel}', field 'text' is required.",
                status_code=400
            )
        if len(text) > MAX_TEXT_LEN:
            return error_response(
                f"Text too long (max {MAX_TEXT_LEN} characters).",
                status_code=400
            )

    # 4) Prototype logic (placeholder)
    blob = (text or url).lower()
    suspicious = any(k in blob for k in ["urgent", "verify", "password", "account", "invoice", "payment", "login"])

    verdict = "Suspicious" if suspicious else "Safe"
    risk = 0.62 if suspicious else 0.18
    confidence = 0.78 if suspicious else 0.66
    reasons = (
        ["Prototype heuristic used (ML + SHAP/LIME not plugged in yet).",
         "Suspicious language or pattern detected."]
        if suspicious
        else ["Prototype heuristic used (ML + SHAP/LIME not plugged in yet).",
              "No strong phishing indicators detected in this prototype scan."]
    )

    # 5) Consistent success response
    return jsonify({
        "ok": True,
        "channel": channel,
        "input": {"text": text if channel != "url" else None, "url": url if channel == "url" else None},
        "result": {
            "verdict": verdict,
            "risk": risk,
            "confidence": confidence,
            "reasons": reasons
        }
    })

# Optional: global error handler (keeps API clean)
@app.errorhandler(404)
def not_found(_):
    return error_response("Endpoint not found.", status_code=404)

@app.errorhandler(500)
def server_error(e):
    return error_response("Internal server error.", status_code=500, details=str(e))

if __name__ == "__main__":
    print("🚀 Flask server starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
