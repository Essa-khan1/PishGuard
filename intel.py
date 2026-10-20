"""
PhishGuard - extra free threat-intel sources (picked from the public-apis list).

  * RDAP            - domain registration date  (no key)         domain age signal
  * PhishStats      - community phishing database (no key)
  * URLhaus         - abuse.ch malware-URL database (free Auth-Key, optional)
  * Google Safe Browsing - Google's blocklist   (free API key, optional)

Every lookup fails soft: if a source is unreachable or not configured, the
scan still completes and the UI shows that source as "skipped" / "error".
"""
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

TIMEOUT = 8
UA = {"User-Agent": "PhishGuard/1.0 (student security project)"}


def _src(name, status, detail=""):
    return {"name": name, "status": status, "detail": detail}


# ---------------------------------------------------------------- domain age
def domain_age_days(domain: str):
    """Days since the domain was registered (via RDAP), or None if unknown."""
    if not domain or re.fullmatch(r"[\d.:a-f]+", domain):
        return None
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=UA, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                reg = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if reg.tzinfo is None:
                    reg = reg.replace(tzinfo=timezone.utc)
                return max(0, (datetime.now(timezone.utc) - reg).days)
    except (requests.exceptions.RequestException, ValueError, KeyError):
        return None
    return None


# ------------------------------------------------------------------ feeds
def phishstats(url: str):
    name = "PhishStats"
    try:
        r = requests.get("https://api.phishstats.info/api/phishing",
                         params={"_where": f"(url,eq,{url})", "_size": 1},
                         headers=UA, timeout=TIMEOUT)
        if r.status_code != 200:
            return _src(name, "error", f"HTTP {r.status_code}")
        hits = r.json()
        if isinstance(hits, list) and hits:
            return _src(name, "listed", "URL is in the PhishStats phishing database")
        return _src(name, "clean", "Not listed")
    except (requests.exceptions.RequestException, ValueError):
        return _src(name, "error", "Source unreachable")


def urlhaus(url: str):
    name = "URLhaus"
    key = os.environ.get("URLHAUS_API_KEY", "").strip()
    if not key:
        return _src(name, "skipped", "No URLHAUS_API_KEY set (optional)")
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                          headers={**UA, "Auth-Key": key}, timeout=TIMEOUT)
        if r.status_code != 200:
            return _src(name, "error", f"HTTP {r.status_code}")
        j = r.json()
        if j.get("query_status") == "ok":
            return _src(name, "listed", f"Malware URL ({j.get('threat', 'unknown threat')}), "
                                        f"status: {j.get('url_status', 'unknown')}")
        return _src(name, "clean", "Not listed")
    except (requests.exceptions.RequestException, ValueError):
        return _src(name, "error", "Source unreachable")


def google_safe_browsing(url: str):
    name = "Google Safe Browsing"
    key = os.environ.get("GSB_API_KEY", "").strip()
    if not key:
        return _src(name, "skipped", "No GSB_API_KEY set (optional)")
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                          params={"key": key}, json=body, timeout=TIMEOUT)
        if r.status_code != 200:
            return _src(name, "error", f"HTTP {r.status_code}")
        matches = r.json().get("matches")
        if matches:
            kinds = sorted({m.get("threatType", "?") for m in matches})
            return _src(name, "listed", "Flagged as " + ", ".join(kinds).lower().replace("_", " "))
        return _src(name, "clean", "Not listed")
    except (requests.exceptions.RequestException, ValueError):
        return _src(name, "error", "Source unreachable")


def check_feeds(url: str):
    """Query all feeds in parallel."""
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(f, url) for f in (phishstats, urlhaus, google_safe_browsing)]
        return [f.result() for f in futs]
