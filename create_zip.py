import os, zipfile, textwrap

files = {
"requirements.txt": """flask==3.0.3
requests==2.32.3
python-dotenv==1.0.1
psycopg2-binary>=2.9.11
customtkinter==5.2.2
""",
".env.example": """# Get free key from: https://www.virustotal.com/gui/join-us
VT_API_KEY=your_virustotal_api_key_here

# Get from https://neon.tech -> Dashboard -> Connection String
# Example: postgresql://neondb_owner:npg_xxx@ep-xxx.neon.tech/neondb?sslmode=require
DATABASE_URL=postgresql://user:password@ep-xxxx.neon.tech/neondb?sslmode=require
""",
"scanner.py": open(__file__).read().split("# --- SCANNER.PY START ---")[1].split("# --- SCANNER.PY END ---")[0] if False else r'''
import re, os, base64, requests, psycopg2
from dotenv import load_dotenv
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
VT_BASE = "https://www.virustotal.com/api/v3"

def detect_input_type(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"[a-fA-F0-9]{64}", value): return "hash_sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value): return "hash_sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value): return "hash_md5"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value): return "email"
    if re.match(r"^(https?://|hxxp://|www\.)", value, re.I) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/.*)?$", value, re.I):
        return "url"
    return "unknown"

def extract_domain_from_email(email: str) -> str:
    return email.split("@")[-1].lower().strip()

def _headers(): return {"x-apikey": VT_API_KEY}

def scan_url(url: str):
    if not VT_API_KEY: return {"error": "VT_API_KEY not set"}
    url = re.sub(r"^hxxp", "http", url, flags=re.I)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=_headers(), timeout=15)
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": stats["malicious"], "suspicious": stats["suspicious"], "harmless": stats["harmless"], "undetected": stats["undetected"], "total": sum(stats.values()), "stats": stats}
    r = requests.post(f"{VT_BASE}/urls", headers=_headers(), data={"url": url}, timeout=15)
    if r.status_code in [200,201]: return {"malicious": 0, "suspicious": 0, "total": 0, "msg": "URL submitted, scan pending. Try again in 30s."}
    return {"error": f"VT Error {r.status_code}"}

def scan_hash(hash_val: str):
    if not VT_API_KEY: return {"error": "VT_API_KEY not set"}
    r = requests.get(f"{VT_BASE}/files/{hash_val}", headers=_headers(), timeout=15)
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": stats["malicious"], "suspicious": stats["suspicious"], "harmless": stats["harmless"], "undetected": stats["undetected"], "total": sum(stats.values()), "stats": stats}
    return {"malicious": 0, "total": 0, "msg": "No report found for this hash"}

def scan_domain(domain: str):
    if not VT_API_KEY: return {"error": "VT_API_KEY not set"}
    r = requests.get(f"{VT_BASE}/domains/{domain}", headers=_headers(), timeout=15)
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": stats["malicious"], "suspicious": stats["suspicious"], "harmless": stats["harmless"], "undetected": stats["undetected"], "total": sum(stats.values()), "stats": stats}
    return {"error": "Domain not found on VT"}

def init_db():
    if not DATABASE_URL: return
    try:
        con = psycopg2.connect(DATABASE_URL)
        with con, con.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id SERIAL PRIMARY KEY,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    input_value TEXT NOT NULL,
                    input_type TEXT NOT NULL,
                    malicious INT NOT NULL,
                    total INT NOT NULL,
                    status TEXT NOT NULL
                );
            """)
        con.close()
    except Exception as e: print("Neon Init Error:", e)

def log_to_neon(input_value, input_type, malicious, total, status):
    if not DATABASE_URL: return
    try:
        con = psycopg2.connect(DATABASE_URL)
        with con, con.cursor() as cur:
            cur.execute("INSERT INTO scans (input_value, input_type, malicious, total, status) VALUES (%s,%s,%s,%s,%s)", (input_value[:500], input_type, malicious, total, status))
        con.close()
    except Exception as e: print("Neon Log Error:", e)

def auto_scan(user_input: str):
    input_type = detect_input_type(user_input)
    if input_type.startswith("hash"): vt = scan_hash(user_input)
    elif input_type == "email": vt = scan_domain(extract_domain_from_email(user_input))
    elif input_type == "url":
        if not user_input.startswith("http"): user_input = "https://" + user_input
        vt = scan_url(user_input)
    else: return {"input": user_input, "type": "unknown", "error": "Invalid input. Enter a valid URL, Email or Hash."}
    malicious = vt.get("malicious", 0)
    total = vt.get("total", 0)
    if vt.get("error"): status = "error"
    elif malicious >= 3: status = "malicious"
    elif malicious > 0: status = "suspicious"
    else: status = "clean"
    log_to_neon(user_input, input_type, malicious, total, status)
    return {"input": user_input, "type": input_type, "malicious": malicious, "total": total, "status": status, "vt_raw": vt}
init_db()
''',
"app_web.py": r'''
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
''',
"app_desktop.py": r'''
import customtkinter as ctk
from scanner import auto_scan
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
app = ctk.CTk()
app.geometry("650x480")
app.title("PhishGuard - Desktop")
ctk.CTkLabel(app, text="🛡️ PhishGuard Desktop", font=("Arial", 22, "bold")).pack(pady=20)
ctk.CTkLabel(app, text="Auto-detects URL / Email / Hash + VirusTotal + Neon").pack()
entry = ctk.CTkEntry(app, width=520, height=45, placeholder_text="Paste URL, Email or Hash here...")
entry.pack(pady=20)
result_label = ctk.CTkLabel(app, text="", font=("Arial", 14), wraplength=520, justify="left")
result_label.pack(pady=20)
def do_scan():
    val = entry.get().strip()
    if not val:
        result_label.configure(text="Please enter a value"); return
    result_label.configure(text="Scanning with VirusTotal...", text_color="white")
    app.update()
    data = auto_scan(val)
    if "error" in data and "type" not in data:
        result_label.configure(text=f"Error: {data['error']}", text_color="red")
    elif data.get("error"):
        result_label.configure(text=f"VT Error: {data['vt_raw'].get('error')}", text_color="orange")
    else:
        color = {"clean":"#16a34a", "malicious":"#dc2626", "suspicious":"#f59e0b", "error":"orange"}[data["status"]]
        result_label.configure(text_color=color, text=f"Type: {data['type']}\nStatus: {data['status'].upper()}\nVirusTotal: {data['malicious']} / {data['total']} engines malicious")
ctk.CTkButton(app, text="Scan Now", height=42, command=do_scan).pack(pady=10)
app.mainloop()
''',
"templates/index.html": r'''
<!DOCTYPE html><html><head><title>PhishGuard - Phishing Detector</title>
<style>
body{font-family:Arial;background:#0f172a;color:white;text-align:center;padding:40px}
.card{background:#1e293b;padding:30px;border-radius:15px;max-width:600px;margin:auto}
input{width:90%;padding:14px;border-radius:8px;border:none;font-size:16px}
button{margin-top:15px;padding:12px 25px;background:#38bdf8;border:none;border-radius:8px;font-weight:bold;cursor:pointer}
.result{margin-top:20px;padding:15px;border-radius:8px}
.clean{background:#16a34a} .malicious{background:#dc2626} .suspicious{background:#f59e0b} .error{background:#64748b}
</style></head><body>
<h1>🛡️ PhishGuard</h1>
<p>Phishing URL / Email / Hash Detector with VirusTotal</p>
<div class="card">
<input id="inputBox" placeholder="Paste URL, Email or Hash here (auto-detects)...">
<button onclick="scan()">Scan Now</button>
<div id="output"></div>
</div>
<script>
async function scan(){
  const val=document.getElementById('inputBox').value;
  document.getElementById('output').innerHTML="Scanning...";
  const res=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({input:val})});
  const data=await res.json();
  const out=document.getElementById('output');
  if(data.error) out.innerHTML=`<p style="color:red">${data.error}</p>`;
  else out.innerHTML=`<div class="result ${data.status}"><b>Type:</b> ${data.type}<br><b>Status:</b> ${data.status.toUpperCase()}<br><b>VirusTotal:</b> ${data.malicious} / ${data.total} engines flagged</div>`;
}
</script></body></html>
''',
".gitignore": ".env\n__pycache__/\n*.pyc\nvenv/\n*.db\ndist/\nbuild/\n",
"README.md": "Run: pip install -r requirements.txt && python app_web.py"
}

os.makedirs("templates", exist_ok=True)
for path, content in files.items():
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "w", encoding="utf-8").write(content)

with zipfile.ZipFile("PhishGuard-Fixed.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for path in files: z.write(path)
    z.write("templates/index.html")

print("✅ Created PhishGuard-Fixed.zip with all files!")
