import os
import time
import hashlib
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/", methods=["GET", "OPTIONS"])
def home():
    return jsonify({"status": "BlackICE Backend Running"})


@app.route("/api/check-url", methods=["POST", "OPTIONS"])
def check_url():
    if request.method == "OPTIONS":
        return jsonify({}), 200
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
        time.sleep(15)
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


@app.route("/api/scan-file", methods=["POST", "OPTIONS"])
def scan_file():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    file_bytes = file.read()

    # Calculate SHA-256 hash of the file
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    try:
        VT_HEADERS = {"x-apikey": os.environ.get("VT_API_KEY")}

        # Step 1 - check if hash already exists in VirusTotal database
        hash_response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
            headers=VT_HEADERS
        )

        if hash_response.status_code == 200:
            # Hash found - instant result, no upload needed
            data = hash_response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
        else:
            # Hash not found - upload the full file
            upload_response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=VT_HEADERS,
                files={"file": (file.filename, file_bytes, file.content_type)}
            )
            result = upload_response.json()
            analysis_id = result["data"]["id"]
            time.sleep(20)
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


@app.route("/api/check-password", methods=["POST", "OPTIONS"])
def check_password():
    if request.method == "OPTIONS":
        return jsonify({}), 200
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
    return jsonify({"score": score, "strength": strength, "feedback": feedback})

@app.route("/api/chat", methods=["POST", "OPTIONS"])
def chat():
    if request.method == "OPTIONS":
        return jsonify({}), 200
        
    data = request.get_json()
    user_message = data.get("message", "")
    
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
        
    # Get the Gemini key from Railway environment variables safely
    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_api_key:
        return jsonify({"error": "GEMINI_API_KEY not found on server"}), 500
        
    # This is your prompt, hidden securely on the backend!
    system_prompt = """You are BlackICE Assistant, a cybersecurity chatbot built into the BlackICE toolkit. You have two areas of expertise:
1. About BlackICE project:
BlackICE is a free web-based cybersecurity toolkit built by students Adarsh S, Prachi N and Swanandi N. It has 5 tools:
Password Analyzer, SHA-256 Hash Generator, Caesar Cipher, Phishing URL Checker, and File Analyzer.
The frontend is hosted on GitHub Pages. The backend is Python Flask hosted on Railway. Live at: adarshx001.github.io/blackice-2.0

2. About cybersecurity in general:
Answer any cybersecurity question clearly and simply. Keep all answers educational. If asked something unrelated to cybersecurity, politely say you can only help with cybersecurity."""
        
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_api_key}"
        payload = {
            "contents": [{"parts": [{"text": user_message}]}],
            "systemInstruction": {"parts": [{"text": system_prompt}]}
        }
        headers = {"Content-Type": "application/json"}
        
        # Send securely from the backend to Google
        response = requests.post(url, json=payload, headers=headers)
        result = response.json()
        
        if response.status_code == 200 and "candidates" in result:
            reply_text = result["candidates"][0]["content"]["parts"][0]["text"]
            return jsonify({"reply": reply_text})
        else:
            print("Gemini API Error:", result)
            return jsonify({"error": "Failed to get response from AI"}), 500
            
    except Exception as e:
        print("Backend Error:", str(e))
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
