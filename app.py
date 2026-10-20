"""
PhishGuard - phishing URL detector with explainable risk scores.
Flask app: scans URLs, pasted emails and file hashes using
  1. a local rule engine (features.py)   - instant, offline, explainable
  2. VirusTotal (vt_client.py)           - 60+ real security engines
  3. free threat feeds + domain age (intel.py)
and blends them into one risk score (scoring.py). History is kept in SQLite.

Safety: the scanned URL is never opened or fetched by this server; it is only
sent (as text) to the threat-intel APIs.
"""
import csv
import io
import json
import os
import re
import sqlite3
import sys
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template, request

import emailscan
import features
import intel
import scoring
import vt_client

if getattr(sys, "frozen", False):
    BASE_DIR = sys._MEIPASS
    DATA_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = DATA_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, "templates"),
            static_folder=os.path.join(BASE_DIR, "static"))
app.config["DB_PATH"] = os.environ.get("PHISHGUARD_DB", os.path.join(DATA_DIR, "phishguard.db"))
def _clean_db_url(raw: str) -> str:
    m = re.search(r"postgres(?:ql)?://[^\s'\"]+", raw or "")
    return m.group(0) if m else ""

app.config["DATABASE_URL"] = _clean_db_url(os.environ.get("DATABASE_URL", ""))
if os.environ.get("BEHIND_PROXY") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024
app.config["RATE_LIMIT_PER_MIN"] = 30
EMAIL_DEEP_LINKS = 3

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    return resp

_hits = defaultdict(deque)
def rate_limited() -> bool:
    now, q = time.time(), _hits[request.remote_addr]
    while q and now - q[0] > 60: q.popleft()
    if len(q) >= app.config["RATE_LIMIT_PER_MIN"]: return True
    q.append(now)
    return False

_COLS = "(ts, kind, target, verdict, score, payload)"
_SCHEMA = ("CREATE TABLE IF NOT EXISTS scans (id {pk}, ts TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, verdict TEXT NOT NULL, score INTEGER NOT NULL, payload TEXT NOT NULL)")
_schema_ready = set()
class DBError(Exception): pass
def db_mode() -> str: return "neon" if app.config["DATABASE_URL"] else "local"
def run(sql, params=(), fetch="none"):
    url = app.config["DATABASE_URL"]
    if url:
        try:
            import psycopg2, psycopg2.extras
        except ImportError: raise DBError("Neon needs psycopg2-binary: pip install psycopg2-binary")
        try: con = psycopg2.connect(url, connect_timeout=8)
        except psycopg2.Error: raise DBError("Could not connect to Neon DB. Check DATABASE_URL")
        try:
            with con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if url not in _schema_ready:
                    cur.execute(_SCHEMA.format(pk="SERIAL PRIMARY KEY"))
                    _schema_ready.add(url)
                cur.execute(sql.replace("?", "%s") + (" RETURNING id" if fetch == "id" else ""), params)
                if fetch == "all": return [dict(r) for r in cur.fetchall()]
                if fetch == "one":
                    r = cur.fetchone(); return dict(r) if r else None
                if fetch == "id": return cur.fetchone()["id"]
        except psycopg2.Error: raise DBError("Neon DB error")
        finally: con.close()
    else:
        con = sqlite3.connect(app.config["DB_PATH"])
        con.row_factory = sqlite3.Row
        try:
            with con:
                con.execute(_SCHEMA.format(pk="INTEGER PRIMARY KEY AUTOINCREMENT"))
                cur = con.execute(sql, params)
                if fetch == "all": return [dict(r) for r in cur.fetchall()]
                if fetch == "one":
                    r = cur.fetchone(); return dict(r) if r else None
                if fetch == "id": return cur.lastrowid
        finally: con.close()

def save_scan(kind: str, target: str, result: dict) -> int:
    return run(f"INSERT INTO scans {_COLS} VALUES (?,?,?,?,?,?)", (datetime.now(timezone.utc).isoformat(timespec="seconds"), kind, target[:500], result["verdict"], int(result["score"]), json.dumps(result)), fetch="id")

def _safe(fn, *args):
    try: return fn(*args), None
    except vt_client.VTError as e: return None, str(e)
    except Exception: return None, "Lookup failed unexpectedly."
def _store(kind: str, target: str, result: dict) -> dict:
    try: result["id"] = save_scan(kind, target, result)
    except DBError as e: result["id"] = None; result["db_warning"] = str(e)
    return result

def scan_one(raw_url: str, deep: bool = True) -> dict:
    url, assumed = features.normalize_url(raw_url)
    local = features.analyze(url, scheme_assumed=assumed)
    vt = vt_err = None; feeds, age = [], None
    if deep:
        with ThreadPoolExecutor(max_workers=3) as ex:
            f_vt = ex.submit(_safe, vt_client.scan_url, url)
            f_feeds = ex.submit(intel.check_feeds, url)
            f_age = None if features.is_ip(local["host"]) else ex.submit(intel.domain_age_days, local["registered_domain"])
            vt, vt_err = f_vt.result(); feeds = f_feeds.result(); age = f_age.result() if f_age else None
    else: vt_err = "Skipped for this link (VT quota reserved for riskiest links)."
    out = scoring.combine(local, vt, vt_err, feeds, age)
    out.update({"type": "url", "target": url, "host": local["host"], "registered_domain": local["registered_domain"], "features": local["features"]})
    return out

def scan_email(text: str) -> dict:
    text = text[:emailscan.MAX_EMAIL_CHARS]
    links = emailscan.extract_links(text)
    sender = emailscan.analyze_sender(text)
    mism = emailscan.mismatched_links(text)
    results = [scan_one(u, deep=False) for u in links]
    order = sorted(range(len(results)), key=lambda i: -results[i]["score"])[:EMAIL_DEEP_LINKS]
    for i in order: results[i] = scan_one(links[i], deep=True)
    findings = list(sender["findings"])
    dom = sender.get("from_domain")
    if dom and not any(f["id"] == "sender_domain" for f in findings):
        reg = features.split_host(dom)[0]
        if reg not in features.TRUSTED_DOMAINS and reg not in emailscan.FREE_MAIL:
            f, _ = scoring.age_finding(_safe(intel.domain_age_days, reg)[0])
            if f and f["severity"] != "ok":
                f["title"] = "Sender's " + f["title"][0].lower() + f["title"][1:]; findings.append(f)
    for m in mism[:3]: findings.append({"id": "link_mismatch", "severity": "bad", "title": "Link text does not match its destination", "detail": f'The email shows "{m["shown"]}" but the link goes to {m["goes_to"]}.', "points": 25})
    cues = emailscan.language_cues(text); findings += cues; findings += emailscan.body_findings(text, results, sender)
    bad_links = [r for r in results if r["verdict"] != "safe"]
    if bad_links: findings.append({"id": "bad_links", "severity": "bad", "title": f"{len(bad_links)} of {len(results)} link(s) look dangerous", "detail": "See the link list below.", "points": 0})
    if not links: findings.append({"id": "no_links", "severity": "ok", "title": "No links found in the text", "detail": "Nothing to scan.", "points": 0})
    signal_pts = sum(f["points"] for f in findings); top = max((r["score"] for r in results), default=0); score = min(100, top + signal_pts)
    ids = {f["id"] for f in findings}; floor = 0
    if ids & {"link_mismatch", "display_spoof"}: floor = 60
    if ids & {"reply_to_diff", "auth_fail", "sender_domain"}: floor = max(floor, 45)
    if any(c["points"] >= 20 for c in cues): floor = max(floor, 60)
    if "display_spoof" in ids and (ids & {"cue", "brand_claim"} or cues): floor = max(floor, 65)
    score = max(score, floor); order_ = {"bad": 0, "warn": 1, "ok": 2}; findings.sort(key=lambda f: order_.get(f["severity"], 3))
    label = sender["subject"] or (f"Email with {len(links)} link(s)")
    return {"type": "email", "target": label, "score": score, "verdict": features.verdict_for(score), "findings": findings, "links": results, "sender": {k: sender[k] for k in ("present", "from_name", "from_addr", "from_domain", "reply_domain", "auth", "subject")}, "cues": [c["title"] for c in cues], "mismatches": mism, "vt": None, "feeds": []}

@app.errorhandler(DBError)
def db_error(e): return jsonify(error=str(e)), 503
@app.get("/healthz")
def healthz(): return "ok"
@app.route("/")
def index(): return render_template("index.html", vt_configured=vt_client.is_configured(), db_mode=db_mode())
def _guard():
    if rate_limited(): return jsonify(error="Too many scans - please wait a minute."), 429
    return None

# --- AUTO-DETECT: URL / Email / Hash in ONE input ---
@app.post("/api/scan")
def api_scan_auto():
    if (g := _guard()): return g
    data = request.get_json(silent=True) or {}
    raw = str(data.get("input", "") or data.get("url", "") or data.get("text", "") or data.get("hash", "")).strip()
    if not raw: return jsonify(error="Paste URL, Email or Hash"), 400
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", raw, re.I):
        h = features.validate_hash(raw)
        if not h: return jsonify(error="Invalid hash"), 400
        vt, err = _safe(vt_client.scan_file_hash, h)
        findings, score, verdict = [], 0, "unknown"
        if vt and vt.get("found"):
            score = scoring.vt_points(vt)
            if vt["malicious"] >= 3: score = max(score, 85)
            elif vt["flagged_count"]: score = max(score, 30)
            verdict = features.verdict_for(score)
            label = vt.get("threat_label")
            findings.append({"id": "vt", "severity": "bad" if vt["flagged_count"] else "ok", "title": f"VirusTotal: {vt['flagged_count']} of {vt['total_engines']} engines flag this file", "detail": (f"Threat label: {label}. " if label else "") + f"File type: {vt.get('file_type', 'unknown')}.", "points": 0})
        elif vt: findings.append({"id": "vt", "severity": "warn", "title": "No VirusTotal report for this hash", "detail": vt["message"], "points": 0})
        result = {"type": "hash", "target": h, "score": score, "verdict": verdict, "findings": findings, "vt": vt, "vt_error": err, "feeds": []}
        return jsonify(_store("hash", h, result))
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", raw) or ("From:" in raw and "@" in raw) or ("Subject:" in raw):
        result = scan_email(raw)
        return jsonify(_store("email", result["target"], result))
    try: result = scan_one(raw)
    except ValueError as e: return jsonify(error=str(e)), 400
    return jsonify(_store("url", result["target"], result))

@app.post("/api/scan-url")
def api_scan_url():
    if (g := _guard()): return g
    data = request.get_json(silent=True) or {}
    try: result = scan_one(str(data.get("url", "")))
    except ValueError as e: return jsonify(error=str(e)), 400
    return jsonify(_store("url", result["target"], result))
@app.post("/api/scan-email")
def api_scan_email():
    if (g := _guard()): return g
    text = str((request.get_json(silent=True) or {}).get("text", "")).strip()
    if not text: return jsonify(error="Paste the email text first."), 400
    result = scan_email(text)
    return jsonify(_store("email", result["target"], result))
@app.post("/api/scan-hash")
def api_scan_hash():
    if (g := _guard()): return g
    h = features.validate_hash(str((request.get_json(silent=True) or {}).get("hash", "")))
    if not h: return jsonify(error="Enter a valid MD5, SHA-1 or SHA-256 hash."), 400
    vt, err = _safe(vt_client.scan_file_hash, h)
    findings, score, verdict = [], 0, "unknown"
    if vt and vt.get("found"):
        score = scoring.vt_points(vt)
        if vt["malicious"] >= 3: score = max(score, 85)
        elif vt["flagged_count"]: score = max(score, 30)
        verdict = features.verdict_for(score)
        label = vt.get("threat_label")
        findings.append({"id": "vt", "severity": "bad" if vt["flagged_count"] else "ok", "title": f"VirusTotal: {vt['flagged_count']} of {vt['total_engines']} engines flag this file", "detail": (f"Threat label: {label}. " if label else "") + f"File type: {vt.get('file_type', 'unknown')}.", "points": 0})
    elif vt: findings.append({"id": "vt", "severity": "warn", "title": "No VirusTotal report for this hash", "detail": vt["message"], "points": 0})
    result = {"type": "hash", "target": h, "score": score, "verdict": verdict, "findings": findings, "vt": vt, "vt_error": err, "feeds": []}
    return jsonify(_store("hash", h, result))
@app.get("/api/history")
def api_history():
    limit = max(1, min(int(request.args.get("limit", 12) or 12), 200))
    rows = run("SELECT id, ts, kind, target, verdict, score FROM scans ORDER BY id DESC LIMIT ?", (limit,), fetch="all")
    return jsonify(rows)
@app.get("/api/history/<int:scan_id>")
def api_history_item(scan_id):
    row = run("SELECT payload FROM scans WHERE id=?", (scan_id,), fetch="one")
    if not row: return jsonify(error="Not found"), 404
    data = json.loads(row["payload"]); data["id"] = scan_id; return jsonify(data)
@app.get("/api/stats")
def api_stats():
    rows = run("SELECT verdict, COUNT(*) AS c FROM scans GROUP BY verdict", fetch="all")
    counts = {r["verdict"]: r["c"] for r in rows}
    return jsonify({"phishing": counts.get("phishing", 0), "suspicious": counts.get("suspicious", 0), "safe": counts.get("safe", 0), "total": sum(counts.values())})
def _csv_safe(v):
    v = str(v); return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
@app.get("/api/history.csv")
def api_history_csv():
    rows = run("SELECT id, ts, kind, target, verdict, score FROM scans ORDER BY id DESC", fetch="all")
    buf = io.StringIO(); w = csv.writer(buf); w.writerow(["id", "time_utc", "type", "target", "verdict", "risk_score"])
    for r in rows: w.writerow([r["id"], r["ts"], r["kind"], _csv_safe(r["target"]), r["verdict"], r["score"]])
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=phishguard_history.csv"})
@app.delete("/api/history")
def api_history_clear(): run("DELETE FROM scans"); return jsonify(ok=True)
if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)


