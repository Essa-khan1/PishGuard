"""
PhishGuard - decide whether a pasted email looks fake.

Pure text analysis (nothing is fetched). Four kinds of evidence:
  1. LINKS        - extracted so each can be scored (done in app.py)
  2. SENDER       - From / Reply-To / SPF-DKIM-DMARC results, spoofed display names,
                    look-alike sender domains (needs the email headers)
  3. WORDING      - pressure, credential / OTP / payment requests, prize bait
  4. BODY CHECKS  - link text that lies, risky attachments, brand claims that
                    don't match anything in the email

Every finding has points; app.py adds them up into the email's risk score.
"""
import re
from urllib.parse import urlparse

import features

MAX_LINKS = 15
MAX_EMAIL_CHARS = 100_000

URL_RE = re.compile(r"""(?ix)
    \b(?: (?:https?|hxxps?)://  |  www\. )
    [^\s<>"'`\)\]]+
""")
ANCHOR_RE = re.compile(r"""(?is)<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""")
EMAIL_ADDR_RE = re.compile(r"([\w.+'-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")

FREE_MAIL = {"gmail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com", "live.com",
             "aol.com", "icloud.com", "proton.me", "protonmail.com", "mail.com", "gmx.com",
             "yandex.com", "zoho.com"}
OFFICIAL_WORDS = re.compile(r"(?i)\b(support|security|service|help ?desk|billing|payments?|accounts?|"
                            r"bank|admin|verification|no-?reply|team|customer care|official)\b")
RISKY_EXT = r"(?:exe|scr|bat|cmd|pif|js|jse|vbs|vbe|wsf|lnk|iso|img|jar|msi|docm|xlsm|pptm|html?|hta|zip|rar|7z|ace)"

# (regex, title, detail, points)
CUES = [
    (r"\burgent(ly)?\b|\bimmediately\b|\bact now\b|\bfinal notice\b|\blast warning\b",
     "Pressure / urgency wording", "Scammers rush you so you don't think.", 5),
    (r"within\s+\d+\s*(hours?|hrs?|days?|minutes?)|expires? (today|soon|in)",
     "Deadline threat", 'A countdown such as "within 24 hours" is a classic pressure tactic.', 8),
    (r"account.{0,40}(suspend|lock|limit|clos|deactivat|compromis|restrict|terminat|blocked)",
     "Threat to your account", "Real companies rarely threaten to close your account by email.", 10),
    (r"verify (your )?(account|identity|information|details|email)|confirm your (account|identity|password|details)|update your (account|billing|payment|password|details)",
     "Asks you to verify or update details", "Legitimate services send you to their app or site, not a link in an email.", 10),
    (r"(send|share|give|reply with|provide|enter|tell)\b.{0,30}\b(otp|one[- ]time (code|password)|pin|cvv|password|passcode|card number|security code|cnic|login details)",
     "Asks for a password, PIN or OTP", "No real bank or service ever asks for these by email, SMS or phone.", 20),
    (r"unusual (sign.?in|activity|login)|suspicious (activity|login|transaction)|unauthori[sz]ed (access|transaction|login)",
     "Claims of suspicious activity", "A common trick to make you panic and click.", 8),
    (r"gift ?cards?|wire transfer|western union|bitcoin|crypto(currency)? wallet|bank (details|transfer)|(send|transfer) (the )?(money|funds|payment)|easypaisa|jazzcash",
     "Unusual payment request", "Requests for gift cards, wire or crypto payments are typical scam payments.", 12),
    (r"you(\'ve| have)? (won|been selected)|claim your (prize|reward|refund|gift)|lucky (draw|winner)|lottery|jeeto pakistan|bisp|ehsaas|benazir income",
     "Prize / refund / lottery bait", "Unexpected winnings are almost always a scam.", 15),
    (r"dear (customer|user|client|member|valued|account holder|sir/?madam|friend)",
     "Generic greeting", "Real companies usually use your name.", 4),
    (r"click (here|the link|below|on the)|log ?in (here|below|now)|sign ?in (here|below|now)|follow (this|the) link",
     "Pushes you to click", "Be careful with emails that tell you to click rather than go to the site yourself.", 4),
    (r"do not (tell|share|inform)|keep (this|it) (secret|confidential)|(confidential|private) (matter|business)",
     "Asks for secrecy", "Scammers isolate their targets.", 8),
    (r"\bkindly\b.{0,60}\b(do the needful|revert|update|confirm|send)\b|i am (a )?(barrister|prince|diplomat|manager at)|next of kin|inheritance|beneficiary",
     "Advance-fee scam wording", "Matches classic '419' / inheritance scam language.", 12),
    (r"(your|the) (parcel|package|shipment|delivery).{0,50}(held|failed|pending|customs|fee|address)|customs (fee|charge)|redelivery",
     "Fake delivery notice", "Parcel scams ask for a small 'fee' to steal your card.", 10),
]


# --------------------------------------------------------------------- links
def extract_links(text: str):
    text = (text or "")[:MAX_EMAIL_CHARS]
    text = re.sub(r"hxxp", "http", text, flags=re.I).replace("[.]", ".").replace("(.)", ".")
    found = [m.group(1).strip() for m in ANCHOR_RE.finditer(text)]
    found += [m.group(0) for m in URL_RE.finditer(text)]
    out, seen = [], set()
    for raw in found:
        raw = raw.rstrip(".,;:!?)>]}'\"")
        try:
            url, _ = features.normalize_url(raw)
        except ValueError:
            continue
        if url not in seen:
            seen.add(url)
            out.append(url)
        if len(out) >= MAX_LINKS:
            break
    return out


def mismatched_links(text: str):
    """HTML emails: the visible text shows one site but the href goes to another."""
    out = []
    for m in ANCHOR_RE.finditer(text or ""):
        href, shown = m.group(1).strip(), re.sub(r"<[^>]+>", "", m.group(2)).strip()
        if not re.match(r"(?i)^(https?://)?[\w.-]+\.[a-z]{2,}(/|$)", shown):
            continue
        try:
            h_url, _ = features.normalize_url(href)
            s_url, _ = features.normalize_url(shown)
        except ValueError:
            continue
        h_reg = features.split_host(urlparse(h_url).hostname or "")[0]
        s_reg = features.split_host(urlparse(s_url).hostname or "")[0]
        if h_reg != s_reg:
            out.append({"shown": shown[:80], "goes_to": h_reg})
    return out


# -------------------------------------------------------------------- headers
def _hdr(text, name):
    """Value of a header (handles folded continuation lines); '' if absent."""
    m = re.search(rf"(?im)^{re.escape(name)}:[ \t]*(.*(?:\r?\n[ \t]+.*)*)", text or "")
    return " ".join(m.group(1).split()) if m else ""


def _f(fid, sev, title, detail, pts):
    return {"id": fid, "severity": sev, "title": title, "detail": detail, "points": pts}


def analyze_sender(text: str) -> dict:
    """Check the From / Reply-To / authentication headers, if the user pasted them."""
    frm, reply = _hdr(text, "From"), _hdr(text, "Reply-To")
    subject = _hdr(text, "Subject")
    auth_blob = " ".join([_hdr(text, "Authentication-Results"), _hdr(text, "ARC-Authentication-Results")])
    spf_hdr = _hdr(text, "Received-SPF")

    out = {"present": bool(frm), "subject": subject[:120], "from_name": "", "from_addr": "",
           "from_domain": "", "reply_domain": "", "auth": {}, "findings": []}
    fs = out["findings"]
    if not frm:
        fs.append(_f("no_headers", "warn", "Sender not checked - no email headers pasted",
                     "Paste the full email source for a sender check (Gmail: open the email, "
                     "menu with three dots, 'Show original'; Outlook: File, Properties).", 0))
        return out

    am = EMAIL_ADDR_RE.search(frm)
    if am:
        out["from_addr"] = am.group(0).lower()
        out["from_domain"] = am.group(2).lower()
    name = re.sub(r"<.*?>", "", frm).replace(EMAIL_ADDR_RE.search(frm).group(0) if am else "", "")
    out["from_name"] = name.strip(' "\'')
    dom = out["from_domain"]
    reg = features.split_host(dom)[0] if dom else ""

    # display name claims to be a brand, address says otherwise
    if reg and out["from_name"]:
        toks = features._tokens(out["from_name"])
        for brand, legit in features.BRANDS.items():
            if reg not in legit and features._brand_in_tokens(brand, toks):
                fs.append(_f("display_spoof", "bad", f'Sender name says "{brand.title()}" but the address is {out["from_addr"]}',
                             f"The real {brand.title()} sends from {sorted(legit)[0]}, not {reg}. "
                             "Anyone can type any name into the 'From' line.", 30))
                break
        else:
            if reg in FREE_MAIL and OFFICIAL_WORDS.search(out["from_name"]):
                fs.append(_f("freemail_official", "warn", "Official-sounding sender using free email",
                             f'"{out["from_name"]}" writes from {reg}. Banks and companies use their own domain.', 15))

    # look-alike / suspicious sender domain
    if reg and reg not in features.TRUSTED_DOMAINS and reg not in FREE_MAIL:
        a = features.analyze("https://" + dom)
        bad = [f for f in a["findings"] if f["id"] in
               ("brand_host", "typosquat", "punycode", "bad_tld", "fake_subdomain", "digits", "ip_host")]
        if bad:
            fs.append(_f("sender_domain", "bad", f"Suspicious sender domain: {dom}",
                         "; ".join(f["title"] for f in bad[:3]) + ".", 25))

    # reply-to goes somewhere else
    rm = EMAIL_ADDR_RE.search(reply) if reply else None
    if rm:
        out["reply_domain"] = rm.group(2).lower()
        if features.split_host(out["reply_domain"])[0] != reg:
            fs.append(_f("reply_to_diff", "bad", "Replies go to a different address",
                         f"From {dom} but 'Reply-To' is {rm.group(0).lower()}. Scammers use this to collect your answer.", 20))

    # SPF / DKIM / DMARC verdicts written by the receiving mail server
    auth = {}
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{k}=(\w+)", auth_blob, re.I)
        if m:
            auth[k] = m.group(1).lower()
    m = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)", spf_hdr, re.I)
    if m and "spf" not in auth:
        auth["spf"] = m.group(1).lower()
    out["auth"] = auth
    failed = [k.upper() + " " + v for k, v in auth.items() if v in ("fail", "softfail", "permerror")]
    if failed:
        fs.append(_f("auth_fail", "bad", "Sender could not be verified: " + ", ".join(failed),
                     "The receiving mail server says this message may not really come from the domain it claims "
                     "(a sign of spoofing).", 15 * min(2, len(failed))))
    elif auth and all(v == "pass" for v in auth.values()):
        fs.append(_f("auth_ok", "ok", "Sender checks passed (" + ", ".join(k.upper() for k in auth) + ")",
                     "Passing proves the mail came from that domain, not that the domain is honest.", 0))
    elif not auth:
        fs.append(_f("no_auth", "warn", "No SPF / DKIM / DMARC results in the headers",
                     "Paste the full original source to see whether the sender was verified.", 0))
    return out


# ---------------------------------------------------------------- wording etc
def language_cues(text: str):
    """Social-engineering wording found in the email, as findings."""
    body = re.sub(r"https?://\S+", " ", text or "")
    return [_f("cue", "warn" if pts < 15 else "bad", title, detail, pts)
            for pat, title, detail, pts in CUES if re.search(pat, body, re.I | re.S)]


def body_findings(text: str, link_results, sender: dict):
    """Attachment names and brand claims that do not match the email's links/sender."""
    out = []
    body = re.sub(r"https?://\S+", " ", text or "")
    body = EMAIL_ADDR_RE.sub(" ", body)                                    # addresses are not file names
    body = re.sub(r"(?im)^(from|to|cc|reply-to|return-path|received|message-id|subject|authentication-results|"
                  r"received-spf|dkim-signature|x-[\w-]+):.*$", " ", body)  # header lines either

    files = sorted({m.group(0).lower() for m in re.finditer(rf"(?i)\b[\w\- ]{{1,40}}\.{RISKY_EXT}\b", body)
                    if not re.match(r"(?i)^(www|mail|smtp|localhost)", m.group(0))})
    files = [f.strip() for f in files if not f.strip().startswith(("from:", "to:")) and "@" not in f]
    if files:
        out.append(_f("attachment", "warn", "Mentions a risky file type: " + ", ".join(files[:3]),
                      "Executables, scripts, HTML and archives are how malware arrives by email. "
                      "Do not open unexpected attachments.", 12))

    # claims to be a brand but nothing in the email belongs to that brand
    regs = {r["registered_domain"] for r in link_results if r.get("registered_domain")}
    if sender.get("from_domain"):
        regs.add(features.split_host(sender["from_domain"])[0])
    if regs:
        low = body.lower() + " " + (sender.get("subject") or "").lower()
        for brand, legit in features.BRANDS.items():
            if re.search(rf"\b{re.escape(brand)}\b", low) and not (regs & legit):
                out.append(_f("brand_claim", "warn", f'Talks about "{brand.title()}" but nothing here belongs to {brand.title()}',
                              f"No link or sender uses a real {brand.title()} domain ({sorted(legit)[0]}).", 15))
                break
    return out
