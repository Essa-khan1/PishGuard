"""
PhishGuard - URL feature extraction + rule engine.

Pulls ~16 signals out of a URL, turns each one into an explainable finding
(with the points it adds to the risk score), and applies a few "instant red
flag" rules. Everything here is offline and deterministic: no network calls,
and the scanned URL is never fetched (so scanning a malicious link is safe).
"""
import re
import ipaddress
from urllib.parse import urlparse, unquote

MAX_URL_LENGTH = 2048

# Two-part public suffixes we need to get the "registered domain" right
# without shipping the full public-suffix list.
MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.pk", "net.pk", "org.pk",
    "edu.pk", "gov.pk", "com.au", "net.au", "org.au", "co.in", "net.in",
    "co.jp", "com.br", "co.za", "com.tr", "com.mx", "com.sa", "com.eg",
    "com.bd", "com.my", "com.sg", "co.nz", "co.id", "com.ng",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "log-in", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "banking", "password",
    "suspended", "wallet", "invoice", "payment", "billing", "unlock",
    "recover", "validate", "authenticate", "webscr",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rb.gy", "tiny.cc", "rebrand.ly",
    "shorturl.at", "t.ly", "bl.ink",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "support",
    "link", "click", "zip", "mov", "country", "kim", "loan", "men", "icu",
    "buzz", "rest", "monster",
}

# brand -> registered domains that legitimately belong to it
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.com.pk", "google.co.uk", "gmail.com",
               "youtube.com", "goo.gl", "googleapis.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com",
                  "microsoftonline.com", "office365.com", "msn.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazon.de",
               "amazon.ca", "amazon.com.au", "amazonaws.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "telegram": {"telegram.org", "t.me"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "easypaisa": {"easypaisa.com.pk"},
    "jazzcash": {"jazzcash.com.pk"},
    "meezan": {"meezanbank.com"},
}

# Well-known sites that aren't in BRANDS; used only to keep false alarms low.
EXTRA_TRUSTED = {
    "github.com", "wikipedia.org", "stackoverflow.com", "python.org",
    "anthropic.com", "claude.ai", "twitter.com", "x.com", "reddit.com",
    "zoom.us", "mozilla.org", "cloudflare.com", "virustotal.com",
}
TRUSTED_DOMAINS = set().union(*BRANDS.values()) | EXTRA_TRUSTED

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a",
                      "7": "t", "$": "s", "@": "a"})

HOST_RE = re.compile(r"^[a-z0-9._-]+$|^xn--[a-z0-9.-]+$")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_url(raw: str):
    """Clean user input into a scannable http(s) URL.

    Returns (url, scheme_assumed). Raises ValueError for input we refuse to
    scan (empty, too long, non-http schemes such as javascript: or file:).
    """
    raw = (raw or "").strip().strip("<>\"'")
    if not raw:
        raise ValueError("Please enter a URL to scan.")
    if len(raw) > MAX_URL_LENGTH:
        raise ValueError(f"URL is too long (max {MAX_URL_LENGTH} characters).")
    if re.search(r"\s", raw):
        raise ValueError("A URL cannot contain spaces.")

    # undo "defanging" people use when sharing bad links
    raw = re.sub(r"^hxxp", "http", raw, flags=re.I)
    raw = raw.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")

    assumed = False
    m = re.match(r"^([a-z][a-z0-9+.-]*):", raw, re.I)
    has_scheme = bool(m) and raw[m.end():m.end() + 2] == "//"
    if has_scheme:
        scheme = m.group(1).lower()
        if scheme not in ("http", "https"):
            raise ValueError("Only http:// and https:// links can be scanned.")
    elif m and m.group(1).lower() in ("javascript", "data", "file", "vbscript", "mailto", "ftp"):
        raise ValueError("Only http:// and https:// links can be scanned.")
    else:
        raw = "https://" + raw.lstrip("/")
        assumed = True

    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        parsed.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError:
        raise ValueError("That does not look like a valid URL.")
    if not host or not (HOST_RE.match(host) or is_ip(host)):
        raise ValueError("That does not look like a valid URL.")
    return raw, assumed


def split_host(host: str):
    """Return (registered_domain, subdomain_labels, sld_label, tld)."""
    if is_ip(host):
        return host, [], host, ""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIX:
        reg_labels = labels[-3:]
    else:
        reg_labels = labels[-2:] if len(labels) >= 2 else labels
    sub = labels[: len(labels) - len(reg_labels)]
    sld = reg_labels[0]
    tld = labels[-1]
    return ".".join(reg_labels), sub, sld, tld


def damerau_1(a: str, b: str) -> bool:
    """True if a and b differ by exactly one edit (insert, delete, replace
    or swap of two adjacent letters)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(short) and j < len(long_):
        if short[i] == long_[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def _tokens(text: str):
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _brand_in_tokens(brand: str, tokens):
    for t in tokens:
        if t == brand or (len(brand) >= 6 and brand in t):
            return True
        if t.translate(LEET) == brand and t != brand:
            return True
    return False


def verdict_for(score: int) -> str:
    if score >= 60:
        return "phishing"
    if score >= 30:
        return "suspicious"
    return "safe"


# --------------------------------------------------------------------------
# main analysis
# --------------------------------------------------------------------------
def analyze(url: str, scheme_assumed: bool = False) -> dict:
    """Run every local rule against an already-normalised URL."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path_q = unquote((parsed.path or "") + "?" + (parsed.query or "")).lower()
    registered, sub_labels, sld, tld = split_host(host)
    host_is_ip = is_ip(host)

    findings = []

    def add(fid, severity, title, detail, points):
        findings.append({"id": fid, "severity": severity, "title": title,
                         "detail": detail, "points": points})

    # 1. raw IP instead of domain
    if host_is_ip:
        add("ip_host", "bad", "Raw IP address used instead of a domain",
            f"The link points straight at {host}. Legitimate services use domain names; "
            "throwaway phishing hosts often use bare IPs.", 35)

    # 2. HTTPS
    if parsed.scheme != "https":
        add("no_https", "bad", "No HTTPS encryption",
            "The connection is not encrypted, so anything typed here can be intercepted.", 12)
    elif scheme_assumed:
        pass  # user typed a bare domain; we assumed https, so no penalty

    # 3. shortener
    if host in SHORTENERS or registered in SHORTENERS:
        add("shortener", "warn", "URL shortening service",
            "Shorteners hide the real destination and are often abused in phishing campaigns.", 25)

    # 4. risky TLD
    if tld in SUSPICIOUS_TLDS and not host_is_ip:
        add("bad_tld", "bad", "High-abuse top-level domain",
            f".{tld} domains are cheap or free and heavily used for disposable phishing sites.", 18)

    # 5. suspicious keywords (host + path/query)
    haystack = _tokens(host) + _tokens(path_q) + [host.replace(".", "-")]
    kws = sorted({k for k in SUSPICIOUS_KEYWORDS
                  if any(k.replace("-", "") in t.replace("-", "") for t in haystack)})
    if kws:
        add("keywords", "warn", "Credential-bait keywords in the URL",
            "Contains: " + ", ".join(kws[:6]) + ".", min(15, 5 * len(kws)))

    # 6. brand impersonation
    host_tokens = _tokens(".".join(sub_labels + [sld]))
    impersonated = None
    for brand, legit in BRANDS.items():
        if registered in legit:
            continue
        if _brand_in_tokens(brand, host_tokens):
            impersonated = brand
            add("brand_host", "bad", "Possible brand impersonation",
                f'The hostname mentions "{brand}" but the real owner of this domain is '
                f'{registered}, not {sorted(legit)[0]}.', 30)
            break
    if not impersonated:
        for brand, legit in BRANDS.items():
            if registered not in legit and len(brand) >= 5 and brand in _tokens(path_q):
                add("brand_path", "warn", "Brand name used in the URL path",
                    f'"{brand}" appears in the path of a domain ({registered}) that does not belong to it.', 10)
                break

    # 7. typosquatting / look-alike characters
    typo = None
    if not host_is_ip and registered not in TRUSTED_DOMAINS:
        for part in _tokens(sld.replace("-", " ")):
            for brand, legit in BRANDS.items():
                if len(brand) < 6 or part == brand:
                    continue
                if part.translate(LEET) == brand or damerau_1(part, brand):
                    typo = (part, brand)
                    break
            if typo:
                break
    if typo:
        add("typosquat", "bad", "Look-alike of a known brand (typosquatting)",
            f'"{typo[0]}" is one character away from "{typo[1]}" - a classic attacker trick.', 28)

    # 8. subdomain chain ("dots")
    if len(sub_labels) >= 3:
        add("subdomains", "warn", "Long subdomain chain",
            f"{len(sub_labels)} subdomain levels; attackers bury the real domain on the right.", 10)
    elif brand_like_subdomain(sub_labels, registered):
        add("fake_subdomain", "bad", "Trusted name used as a subdomain",
            f'"{".".join(sub_labels)}" looks like a trusted site, but the page really lives on {registered}.', 20)

    # 9. @ trick
    if "@" in (parsed.netloc or ""):
        add("at_symbol", "bad", "'@' symbol in the address",
            "Browsers ignore everything before '@' when picking the server - a classic disguise.", 25)

    # 10. hyphens
    hyphens = host.replace("xn--", "").count("-")
    if hyphens >= 3:
        add("hyphens", "warn", "Many hyphens in the domain",
            f"{hyphens} hyphens - typical of auto-generated phishing domains.", 10)

    # 11. length
    if len(url) > 75:
        add("long_url", "warn", "Very long URL",
            f"{len(url)} characters; long URLs hide the important part.", 8 if len(url) <= 150 else 12)

    # 12. punycode / IDN
    if "xn--" in host:
        add("punycode", "bad", "Internationalised (punycode) domain",
            "xn-- domains can use look-alike letters from other alphabets to imitate real sites.", 20)

    # 13. unusual port
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        add("odd_port", "warn", "Non-standard port",
            f"Port {port} is unusual for a public website.", 10)

    # 14. obfuscation / encoding
    pct = len(re.findall(r"%[0-9a-f]{2}", url.lower()))
    if pct >= 3:
        add("encoded", "warn", "Heavily percent-encoded URL",
            f"{pct} encoded characters - often used to hide keywords from filters.", 8)

    # 15. digits mixed into the domain name
    if not host_is_ip and sum(c.isdigit() for c in sld) >= 4:
        add("digits", "warn", "Many digits in the domain name",
            "Random-looking numbers in a domain are common in generated phishing hosts.", 8)

    # 16. another URL embedded in the path/query (open-redirect style)
    if re.search(r"https?(://|%3a%2f%2f)", (parsed.path + "?" + parsed.query).lower()):
        add("embedded_url", "warn", "Another URL is embedded inside this one",
            "Redirect-style links are used to launder a bad destination behind a good-looking domain.", 12)

    trusted = (registered in TRUSTED_DOMAINS and parsed.scheme == "https"
               and not host_is_ip and "@" not in parsed.netloc)

    total = sum(f["points"] for f in findings)

    # "Instant red flag" rules set a floor under the weighted score
    floor = 0
    ids = {f["id"] for f in findings}
    if "ip_host" in ids:
        floor = 45
        if "keywords" in ids:
            floor = 65
    if "at_symbol" in ids:
        floor = max(floor, 60)
    if {"punycode", "brand_host"} <= ids or {"typosquat", "keywords"} <= ids:
        floor = max(floor, 60)
    score = min(100, max(total, floor))

    if trusted:
        score = min(score, 10)
        findings = [f for f in findings if f["severity"] == "bad"] or []
        findings.append({"id": "trusted", "severity": "ok", "title": "Well-known domain over HTTPS",
                         "detail": f"{registered} belongs to a well-known service.", "points": 0})
    else:
        if parsed.scheme == "https":
            findings.append({"id": "https_ok", "severity": "ok", "title": "HTTPS in use",
                             "detail": "The connection is encrypted (this alone does not make a site safe).",
                             "points": 0})
        if not host_is_ip:
            findings.append({"id": "domain_ok", "severity": "ok", "title": "Uses a domain name, not a raw IP",
                             "detail": "Hostname is a normal domain.", "points": 0})

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "dot_count": host.count("."),
        "hyphen_count": hyphens,
        "subdomain_count": len(sub_labels),
        "digit_count": sum(c.isdigit() for c in host),
        "has_ip": host_is_ip,
        "has_https": parsed.scheme == "https",
        "has_at": "@" in (parsed.netloc or ""),
        "is_shortener": host in SHORTENERS,
        "has_punycode": "xn--" in host,
        "keyword_hits": len(kws),
        "tld": tld,
    }

    return {
        "url": url,
        "host": host,
        "registered_domain": registered,
        "score": score,
        "verdict": verdict_for(score),
        "findings": findings,
        "features": features,
        "trusted": trusted,
    }


def brand_like_subdomain(sub_labels, registered):
    """e.g. paypal.com.evil.xyz  or  accounts.google.com.evil.tk"""
    joined = ".".join(sub_labels)
    return bool(re.search(r"(^|\.)[a-z0-9-]+\.(com|net|org|co|gov|edu)(\.|$)", joined)) \
        and registered not in TRUSTED_DOMAINS


# --------------------------------------------------------------------------
# file hashes
# --------------------------------------------------------------------------
def validate_hash(h: str):
    """Return a lowercase hash if it is MD5 / SHA-1 / SHA-256, else None."""
    h = (h or "").strip().lower()
    return h if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", h) else None
