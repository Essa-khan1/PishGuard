
from flask import Flask, render_template, request, jsonify
from scanner import auto_scan
app = Flask(__name__)
@app.route("/")
def index(): return render_template("index.html")
@app.post("/api/scan")
def scan():
    data = request.get_json()
    user_input = data.get("input", "").strip()
    if not user_input: return jsonify({"error": "Please enter a value"}), 400
    result = auto_scan(user_input)
    return jsonify(result)
@app.get("/healthz")
def health(): return "ok"
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
