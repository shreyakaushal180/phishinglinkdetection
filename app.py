"""
app.py  —  Flask backend for the Phishing URL Detector
"""

import os
import sys
import joblib
import pandas as pd

from flask import Flask, request, jsonify, render_template, send_from_directory
from feature_extractor import extract_features

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR  = os.path.join(BASE_DIR, "models")
MODEL_PATH   = os.path.join(MODELS_DIR, "ensemble_model.joblib")
SCALER_PATH  = os.path.join(MODELS_DIR, "scaler.joblib")
FEATURES_PATH = os.path.join(MODELS_DIR, "feature_columns.joblib")

app = Flask(__name__, template_folder="templates", static_folder="static")

# ── Load Model ───────────────────────────────────────────────────────────────
model           = None
scaler          = None
feature_columns = None
MODEL_READY     = False
MODEL_ERROR     = ""

def load_model():
    global model, scaler, feature_columns, MODEL_READY, MODEL_ERROR
    try:
        if not os.path.exists(MODEL_PATH):
            MODEL_ERROR = "Model not found. Please run train_model.py first."
            return
        model           = joblib.load(MODEL_PATH)
        scaler          = joblib.load(SCALER_PATH)
        feature_columns = joblib.load(FEATURES_PATH)
        MODEL_READY     = True
        print("[app] Model loaded successfully")
    except Exception as e:
        MODEL_ERROR = str(e)
        print(f"[app] ERROR loading model: {e}")

load_model()

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({
        "ready":   MODEL_READY,
        "error":   MODEL_ERROR,
        "features": len(feature_columns) if feature_columns else 0,
    })


@app.route("/api/predict", methods=["POST"])
def api_predict():
    if not MODEL_READY:
        return jsonify({
            "success": False,
            "error":   MODEL_ERROR or "Model not loaded.",
        }), 503

    data = request.get_json(force=True)
    url  = (data.get("url") or "").strip()

    if not url:
        return jsonify({"success": False, "error": "No URL provided."}), 400

    # --- Feature extraction ---------------------------------------------------
    try:
        raw_features = extract_features(url)
    except Exception as e:
        return jsonify({"success": False, "error": f"Feature extraction failed: {e}"}), 500

    # --- Align features with model's training columns ------------------------
    # Build a DataFrame with the exact columns the model expects, in order.
    # Missing columns get 0, extra columns are ignored.
    row = {col: raw_features.get(col, 0) for col in feature_columns}
    X   = pd.DataFrame([row], columns=feature_columns)

    try:
        X_sc        = scaler.transform(X)
        prediction  = int(model.predict(X_sc)[0])
        proba       = float(model.predict_proba(X_sc)[0][prediction])
        confidence  = round(proba * 100, 2)
    except Exception as e:
        return jsonify({"success": False, "error": f"Prediction failed: {e}"}), 500

    # --- Top contributing extracted features (for transparency) --------------
    top_features = sorted(
        [(k, v) for k, v in raw_features.items() if isinstance(v, (int, float))],
        key=lambda x: abs(x[1]),
        reverse=True
    )[:5]

    return jsonify({
        "success":    True,
        "url":        url,
        "prediction": prediction,          # 1 = phishing, 0 = legitimate
        "label":      "Phishing" if prediction == 1 else "Legitimate",
        "confidence": confidence,
        "top_features": [{"name": k, "value": v} for k, v in top_features],
    })


@app.route("/api/batch", methods=["POST"])
def api_batch():
    """Accept a JSON list of URLs and return predictions for all."""
    if not MODEL_READY:
        return jsonify({"success": False, "error": MODEL_ERROR}), 503

    data = request.get_json(force=True)
    urls = data.get("urls", [])
    if not urls or not isinstance(urls, list):
        return jsonify({"success": False, "error": "Provide a JSON list under 'urls'."}), 400

    results = []
    for url in urls[:50]:  # cap at 50 per batch
        url = url.strip()
        try:
            raw   = extract_features(url)
            row   = {col: raw.get(col, 0) for col in feature_columns}
            X     = pd.DataFrame([row], columns=feature_columns)
            X_sc  = scaler.transform(X)
            pred  = int(model.predict(X_sc)[0])
            proba = float(model.predict_proba(X_sc)[0][pred])
            results.append({
                "url":        url,
                "prediction": pred,
                "label":      "Phishing" if pred == 1 else "Legitimate",
                "confidence": round(proba * 100, 2),
            })
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return jsonify({"success": True, "results": results})


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n Starting Phishing Detector on http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
