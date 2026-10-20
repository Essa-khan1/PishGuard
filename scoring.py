"""
PhishGuard - combines local rules + VirusTotal + threat feeds + domain age
into one explainable 0-100 risk score.

How the blend works (kept simple on purpose so it can be explained in a demo):

  local_score  = rule engine score (+ domain-age points)
  vt_points    = 20 per malicious engine + 8 per suspicious engine, capped at 100
                 (a handful of engines agreeing is already strong evidence)

  VirusTotal available, flagged:  score = 0.35*local + 0.65*vt_points
  VirusTotal available, clean:    score = 0.75*local   (clean reports lower the
                                  score, but new phishing sites are often not
                                  detected yet, so local red flags still show)
  VirusTotal unavailable:         score = local

  Overrides: >=3 malicious engines OR any blocklist hit  -> at least 85 (phishing)
             1-2 engines flagging                         -> at least 30 (suspicious)
"""
from features import verdict_for


def vt_points(vt):
    if not vt or not vt.get("found"):
        return None
    return min(100, vt.get("malicious", 0) * 20 + vt.get("suspicious", 0) * 8)


def age_finding(days):
    """Return (finding|None, points) for a domain age in days."""
    if days is None:
        return None, 0
    if days < 30:
        return ({"id": "new_domain", "severity": "bad", "title": "Brand-new domain",
                 "detail": f"Registered only {days} day(s) ago. Most phishing domains are under a month old.",
                 "points": 25}, 25)
    if days < 180:
        return ({"id": "young_domain", "severity": "warn", "title": "Recently registered domain",
                 "detail": f"Registered {days} days ago (under 6 months).", "points": 10}, 10)
    return ({"id": "old_domain", "severity": "ok", "title": "Established domain",
             "detail": f"Registered about {days // 365} year(s) ago." if days >= 365
             else f"Registered {days} days ago.", "points": 0}, 0)


def combine(local: dict, vt=None, vt_error=None, feeds=None, age_days=None) -> dict:
    feeds = feeds or []
    findings = list(local["findings"])

    # domain age (external signal, but scored like a rule)
    af, age_pts = age_finding(age_days)
    if af:
        findings.append(af)
    local_score = local["score"]
    if not local.get("trusted"):
        local_score = min(100, local_score + age_pts)

    # VirusTotal
    vtp = vt_points(vt)
    if vt and vt.get("found"):
        flagged, total = vt["flagged_count"], vt["total_engines"]
        if flagged:
            names = ", ".join(e["engine"] for e in vt["engines_flagged"][:5])
            findings.append({"id": "vt_hit", "severity": "bad",
                             "title": f"VirusTotal: {flagged} of {total} engines flag this URL",
                             "detail": f"Flagged by {names}." if names else "Multiple security engines flagged it.",
                             "points": 0})
        else:
            note = " (fresh scan - brand-new URLs may not be detected yet)" if vt.get("fresh_scan") else ""
            findings.append({"id": "vt_clean", "severity": "ok",
                             "title": f"VirusTotal: 0 of {total} engines flag this URL",
                             "detail": "No security vendor reports it as malicious" + note + ".", "points": 0})

    # blocklist feeds
    listed = [f for f in feeds if f["status"] == "listed"]
    for f in listed:
        findings.append({"id": "feed_" + f["name"].lower().replace(" ", "_"), "severity": "bad",
                         "title": f"{f['name']}: listed", "detail": f["detail"], "points": 0})

    # blend
    if vtp is None:
        score = local_score
    elif vtp == 0:
        score = round(0.75 * local_score)
    else:
        score = round(0.35 * local_score + 0.65 * vtp)

    if (vt and vt.get("malicious", 0) >= 3) or listed:
        score = max(score, 85)
    elif vt and vt.get("flagged_count", 0) >= 1:
        score = max(score, 30)
    if local.get("trusted") and not listed and not (vt and vt.get("flagged_count")):
        score = min(score, 10)
    score = max(0, min(100, int(score)))

    order = {"bad": 0, "warn": 1, "ok": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))

    return {
        "score": score,
        "verdict": verdict_for(score),
        "local_score": local_score,
        "findings": findings,
        "vt": vt,
        "vt_error": vt_error,
        "feeds": feeds,
        "domain_age_days": age_days,
    }
