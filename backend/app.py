import pickle
import os
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from feature_extractor import extract_features, get_feature_dict, get_red_flags, FEATURE_NAMES, FEATURE_LABELS

app = Flask(__name__)
CORS(app)

model_data = None


def load_model():
    global model_data
    path = os.path.join(os.path.dirname(__file__), "model.pkl")
    if not os.path.exists(path):
        print("[!] model.pkl not found — run train_model.py first")
        return
    with open(path, "rb") as f:
        model_data = pickle.load(f)
    print(f"[+] model loaded (accuracy: {model_data['accuracy']:.4f})")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model_data is not None,
        "accuracy": round(model_data["accuracy"], 4) if model_data else None,
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = (data or {}).get("url", "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400
    if model_data is None:
        return jsonify({"error": "model not loaded"}), 503

    try:
        fv = np.array([extract_features(url)])
        clf = model_data["model"]

        prediction = int(clf.predict(fv)[0])
        proba = clf.predict_proba(fv)[0]
        confidence = float(proba[prediction])

        verdict = "PHISHING" if prediction == 1 else "LEGITIMATE"
        phish_prob = float(proba[1]) * 100

        if prediction == 1:
            risk = "HIGH" if confidence >= 0.85 else ("MEDIUM" if confidence >= 0.65 else "LOW")
        else:
            risk = "SAFE" if confidence >= 0.85 else "LOW"

        # Build feature breakdown sorted by model importance
        importances = clf.feature_importances_
        feature_breakdown = sorted([
            {
                "name": name,
                "label": FEATURE_LABELS.get(name, name),
                "value": float(val),
                "importance": float(imp),
            }
            for name, val, imp in zip(FEATURE_NAMES, fv[0], importances)
        ], key=lambda x: x["importance"], reverse=True)

        return jsonify({
            "url": url,
            "verdict": verdict,
            "risk_level": risk,
            "confidence": round(confidence * 100, 2),
            "phishing_probability": round(phish_prob, 2),
            "legit_probability": round(float(proba[0]) * 100, 2),
            "red_flags": get_red_flags(url),
            "feature_breakdown": feature_breakdown[:10],
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/bulk", methods=["POST"])
def bulk():
    data = request.get_json()
    urls = (data or {}).get("urls", [])

    if not urls:
        return jsonify({"error": "urls array is required"}), 400
    if len(urls) > 50:
        return jsonify({"error": "max 50 urls per request"}), 400
    if model_data is None:
        return jsonify({"error": "model not loaded"}), 503

    clf = model_data["model"]
    results = []
    for url in urls:
        try:
            fv = np.array([extract_features(url.strip())])
            pred = int(clf.predict(fv)[0])
            proba = clf.predict_proba(fv)[0]
            results.append({
                "url": url,
                "verdict": "PHISHING" if pred == 1 else "LEGITIMATE",
                "phishing_probability": round(float(proba[1]) * 100, 2),
            })
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return jsonify({"results": results})


if __name__ == "__main__":
    load_model()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
