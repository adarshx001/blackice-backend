import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# -------------------------------------------------
# Health Check
# -------------------------------------------------

@app.route("/")
def home():
    return jsonify({"status": "BlackICE Backend Running"})


# -------------------------------------------------
# 1. Phishing URL Checker (VirusTotal)
# -------------------------------------------------

@app.route("/api/check-url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        VT_HEADERS = {"x-apikey": os.environ.get("VT_API_KEY")}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=VT_HEADERS,
            data={"url": url}
        )
        result = response.json()
        analysis_id = result["data"]["id"]

        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=VT_HEADERS
        ).json()

        stats = analysis["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            risk = "High Risk"
        elif suspicious > 0:
            risk = "Suspicious"
        else:
            risk = "Safe"

        return jsonify({
            "risk": risk,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": malicious + suspicious + harmless + undetected
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------------------------
# 2. File Malware Scanner (VirusTotal)
# -------------------------------------------------

@app.route("/api/scan-file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    try:
        VT_HEADERS = {"x-apikey": os.environ.get("VT_API_KEY")}

        response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=VT_HEADERS,
            files={"file": (file.filename, file.read(), file.content_type)}
        )
        result = response.json()
        analysis_id = result["data"]["id"]

        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=VT_HEADERS
        ).json()

        stats = analysis["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            risk = "High Risk"
        elif suspicious > 0:
            risk = "Suspicious"
        else:
            risk = "Safe"

        return jsonify({
            "risk": risk,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": malicious + suspicious + harmless + undetected
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------------------------
# 3. Password Strength (Server Side)
# -------------------------------------------------

@app.route("/api/check-password", methods=["POST"])
def check_password():
    data = request.get_json()
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "No password provided"}), 400

    score = 0
    feedback = []

    if len(password) >= 8:
        score += 20
    else:
        feedback.append("Password should be at least 8 characters")

    if len(password) >= 12:
        score += 10

    if len(password) >= 16:
        score += 10

    if any(c.isupper() for c in password):
        score += 15
    else:
        feedback.append("Add uppercase letters")

    if any(c.islower() for c in password):
        score += 15
    else:
        feedback.append("Add lowercase letters")

    if any(c.isdigit() for c in password):
        score += 15
    else:
        feedback.append("Add numbers")

    special = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")
    if any(c in special for c in password):
        score += 15
    else:
        feedback.append("Add special characters (!@#$...)")

    common = ["password", "123456", "qwerty", "abc123", "letmein", "admin"]
    if password.lower() in common:
        score = 0
        feedback = ["This is a commonly used password — extremely dangerous!"]

    score = min(100, score)

    if score < 40:
        strength = "Weak"
    elif score < 75:
        strength = "Medium"
    else:
        strength = "Strong"

    return jsonify({
        "score": score,
        "strength": strength,
        "feedback": feedback
    })


# -------------------------------------------------
# Run Server
# -------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
