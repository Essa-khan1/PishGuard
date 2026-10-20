"""
PhishGuard - VirusTotal integration (public API v3).

Returns real multi-engine verdicts, the same data virustotal.com shows.
Free API key: https://www.virustotal.com/gui/join-us  ->  put it in .env as
VT_API_KEY=...   (free tier = 4 requests/minute, 500/day).
"""
import os
import sys
import base64
import time
import requests
from dotenv import load_dotenv

# .env lives next to the .exe when frozen with PyInstaller, else next to this file
_env_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) \
    else os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_env_dir, ".env"))

VT_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 20
NET_ERR = "Could not reach VirusTotal. Check your internet connection and try again."


class VTError(Exception):
    pass


def api_key() -> str:
    return os.environ.get("VT_API_KEY", "").strip()


def is_configured() -> bool:
    k = api_key()
    return bool(k) and k != "your_virustotal_api_key_here"


def _headers():
    if not is_configured():
        raise VTError("No VirusTotal API key set. Add VT_API_KEY to your .env file.")
    return {"x-apikey": api_key(), "accept": "application/json"}


def url_id(url: str) -> str:
    """VirusTotal identifies a URL by its url-safe base64 (no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _get(path):
    try:
        return requests.get(f"{VT_BASE}{path}", headers=_headers(), timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        raise VTError(NET_ERR)


def _check_status(resp):
    if resp.status_code == 401:
        raise VTError("VirusTotal rejected the API key (401). Check VT_API_KEY in .env.")
    if resp.status_code == 429:
        raise VTError("VirusTotal rate limit reached (free tier: 4 requests/minute). Wait a minute and retry.")
    if resp.status_code >= 400 and resp.status_code != 404:
        raise VTError(f"VirusTotal error {resp.status_code}: {resp.text[:160]}")


def _flagged(results: dict, limit=12):
    out = [{"engine": n, "category": r.get("category"), "result": r.get("result")}
           for n, r in (results or {}).items()
           if r.get("category") in ("malicious", "suspicious")]
    out.sort(key=lambda e: (e["category"] != "malicious", e["engine"].lower()))
    return out[:limit]


def _summary(stats, flagged, fresh, permalink, extra=None):
    m, s = stats.get("malicious", 0), stats.get("suspicious", 0)
    h, u = stats.get("harmless", 0), stats.get("undetected", 0)
    out = {
        "found": True, "fresh_scan": fresh,
        "malicious": m, "suspicious": s, "harmless": h, "undetected": u,
        "total_engines": m + s + h + u, "flagged_count": m + s,
        "engines_flagged": flagged, "permalink": permalink,
    }
    out.update(extra or {})
    return out


def scan_url(url: str) -> dict:
    """Fetch VT's existing report for a URL; if none exists, submit it and poll."""
    uid = url_id(url)
    permalink = f"https://www.virustotal.com/gui/url/{uid}"
    resp = _get(f"/urls/{uid}")
    _check_status(resp)

    if resp.status_code == 200:
        a = resp.json()["data"]["attributes"]
        return _summary(a["last_analysis_stats"], _flagged(a.get("last_analysis_results")),
                        False, permalink)

    # 404: VT has never seen it -> submit for analysis
    try:
        sub = requests.post(f"{VT_BASE}/urls", headers=_headers(), data={"url": url}, timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        raise VTError(NET_ERR)
    _check_status(sub)
    analysis_id = sub.json()["data"]["id"]

    for _ in range(8):
        time.sleep(3)
        r = _get(f"/analyses/{analysis_id}")
        _check_status(r)
        a = r.json()["data"]["attributes"]
        if a.get("status") == "completed":
            return _summary(a["stats"], _flagged(a.get("results")), True, permalink)
    raise VTError("Scan was submitted but VirusTotal has not finished yet. Try again in a minute.")


def scan_file_hash(h: str) -> dict:
    """Look up an existing file report by MD5 / SHA-1 / SHA-256."""
    resp = _get(f"/files/{h}")
    _check_status(resp)
    if resp.status_code == 404:
        return {"found": False,
                "message": "VirusTotal has no report for this hash. It only knows files that "
                           "have been uploaded before - upload the file at virustotal.com for a verdict."}
    a = resp.json()["data"]["attributes"]
    return _summary(a["last_analysis_stats"], _flagged(a.get("last_analysis_results")), False,
                    f"https://www.virustotal.com/gui/file/{h}",
                    {"file_names": (a.get("names") or [])[:5],
                     "file_type": a.get("type_description", "unknown"),
                     "threat_label": (a.get("popular_threat_classification") or {})
                     .get("suggested_threat_label")})
