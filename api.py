import re
import logging
from urllib.parse import urlparse

import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS

# ==============================
# LOGGING
# ==============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ==============================
# APP
# ==============================
app = Flask(__name__)
CORS(app)

# ==============================
# LOAD MODEL ONCE
# ==============================
try:
    model = joblib.load("phishing_model.pkl")
    logging.info("Model loaded successfully")
except Exception as e:
    logging.error(f"Model load failed: {e}")
    model = None

# ==============================
# FEATURE ORDER (MUST MATCH TRAINING)
# ==============================
FEATURE_COLUMNS = [
    "url_length",
    "count_dots",
    "count_hyphens",
    "count_slashes",
    "count_digits",
    "has_ip",
    "has_https",
    "suspicious_word_count",
    "domain_length",
    "subdomain_count"
]

THRESHOLD = 0.35

# ==============================
# UTILS
# ==============================
def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and parsed.netloc != ""


def has_ip_address(url: str) -> int:
    return 1 if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url) else 0


def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = {
        "url_length": len(url),
        "count_dots": url.count("."),
        "count_hyphens": url.count("-"),
        "count_slashes": url.count("/"),
        "count_digits": sum(c.isdigit() for c in url),
        "has_ip": has_ip_address(url),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "suspicious_word_count": sum(
            w in url.lower()
            for w in ["login", "secure", "account", "verify", "update", "bank"]
        ),
        "domain_length": len(hostname),
        "subdomain_count": hostname.count(".")
    }

    return features

# ==============================
# HEALTH
# ==============================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None})

# ==============================
# PREDICT
# ==============================
@app.route("/predict", methods=["POST"])
def predict():
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing url"}), 400

    url = data["url"].strip()
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    try:
        feats = extract_features(url)

        input_df = pd.DataFrame(
            [[feats[col] for col in FEATURE_COLUMNS]],
            columns=FEATURE_COLUMNS
        )

        prob = model.predict_proba(input_df)[0][1]
        prediction = "phishing" if prob >= THRESHOLD else "legitimate"

        logging.info(f"{url} → {prediction} ({prob:.3f})")

        return jsonify({
            "url": url,
            "prediction": prediction,
            "confidence": round(float(prob), 3)
        })

    except Exception as e:
        logging.error(f"Prediction failed: {e}")
        return jsonify({"error": "Internal prediction error"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
