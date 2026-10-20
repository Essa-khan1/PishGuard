import re, os, base64, requests, psycopg2
from dotenv import load_dotenv
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY","").strip()
DATABASE_URL = os.getenv("DATABASE_URL","").strip()
VT_BASE = "https://www.virustotal.com/api/v3"

def detect_input_type(value: str) -> str:
    value = value.strip()
    if not value: return "unknown"
    # 1. Hash first
    if re.fullmatch(r"[a-fA-F0-9]{64}", value): return "hash_sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value): return "hash_sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value): return "hash_md5"
    # 2. Email BODY - if pasted full email with headers/newlines
    if "From:" in value or "Subject:" in value or value.count("\n") >= 2:
        return "email_body"
    # 3. Single Email address
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value): return "email"
    # 4. Contains @ but not URL -> treat as email domain scan
    if "@" in value and "." in value.split("@")[-1] and " " not in value:
        return "email"
    # 5. URL
    if re.match(r"^(https?://|hxxp://|www\.)", value, re.I) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/.*)?$", value, re.I):
        return "url"
    return "unknown"
