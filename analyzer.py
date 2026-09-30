import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account",
    "update", "password", "bank", "signin", "confirm"
]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"]

def analyze_url(url):
    score = 0
    findings = []

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if parsed.scheme == "https":
        findings.append(("safe", "HTTPS connection detected"))
    else:
        score += 15
        findings.append(("warning", "URL does not use HTTPS"))

    if len(url) > 100:
        score += 15
        findings.append(("warning", "Unusually long URL"))
    else:
        findings.append(("safe", "URL length looks normal"))

    try:
        ipaddress.ip_address(hostname)
        score += 25
        findings.append(("danger", "URL uses an IP address instead of a domain"))
    except ValueError:
        findings.append(("safe", "Normal domain format detected"))

    found_keywords = [w for w in SUSPICIOUS_KEYWORDS if w in url.lower()]
    if found_keywords:
        score += min(len(found_keywords) * 8, 25)
        findings.append(("warning", "Suspicious keyword(s): " + ", ".join(found_keywords)))
    else:
        findings.append(("safe", "No common suspicious keywords detected"))

    if hostname.count(".") >= 3:
        score += 15
        findings.append(("warning", "Multiple subdomains detected"))
    else:
        findings.append(("safe", "Domain structure looks normal"))

    if "@" in url:
        score += 20
        findings.append(("danger", "URL contains an @ symbol"))
    else:
        findings.append(("safe", "No @ symbol detected"))

    if any(s in hostname.lower() for s in SHORTENERS):
        score += 20
        findings.append(("warning", "URL shortening service detected"))

    score = min(score, 100)
    risk = "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH"

    return {"url": url, "score": score, "risk": risk, "findings": findings}
