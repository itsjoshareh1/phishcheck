"""phishcheck: paste an email or link, get a phishing risk score and the reasons why.

Starter version: rule-based scoring only. Build steps are in the README.
Run:  python phishcheck.py sample_phish.txt
      cat some_email.txt | python phishcheck.py
"""
import re
import sys
from urllib.parse import urlparse

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "within 24 hours", "account suspended",
    "verify your account", "final notice", "limited time", "password expires",
]
CREDENTIAL_WORDS = ["password", "login", "sign in", "ssn", "card number", "otp", "verification code"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".click", ".work", ".gq", ".tk"}
BRANDS = ["paypal", "google", "apple", "microsoft", "amazon", "netflix", "instagram", "mtn", "vodafone"]

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


def find_urls(text):
    return URL_RE.findall(text)


def check_url(url):
    """Return a list of (points, reason) for one URL."""
    findings = []
    host = (urlparse(url).hostname or "").lower()
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        findings.append((30, f"Link points to a raw IP address ({host})"))
    if host in SHORTENERS:
        findings.append((15, f"Link uses a URL shortener ({host}), the real destination is hidden"))
    if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
        findings.append((15, f"Link uses a TLD often seen in scams ({host})"))
    # Lookalike: brand name appears in the host but the registered domain isn't the brand's own.
    for brand in BRANDS:
        if brand in host and not host.endswith(f"{brand}.com"):
            findings.append((30, f"Domain {host} mentions '{brand}' but is not {brand}.com"))
    if host.count("-") >= 2:
        findings.append((10, f"Domain {host} has many hyphens"))
    # TODO (step 2): detect digit-for-letter lookalikes like paypa1.com or g00gle.com
    return findings


def score_text(text):
    """Return (score 0-100, list of reasons)."""
    findings = []
    lower = text.lower()
    for word in URGENCY_WORDS:
        if word in lower:
            findings.append((10, f"Urgency pressure: '{word}'"))
    for word in CREDENTIAL_WORDS:
        if word in lower:
            findings.append((5, f"Asks about credentials: '{word}'"))
    for url in find_urls(text):
        findings.extend(check_url(url))
    # TODO (step 3): compare the link text with the real href for HTML emails
    # TODO (step 4): parse From / Reply-To headers and flag mismatches
    score = min(100, sum(points for points, _ in findings))
    return score, [reason for _, reason in findings]


def label(score):
    if score >= 60:
        return "HIGH RISK"
    if score >= 30:
        return "SUSPICIOUS"
    return "LOOKS OK"


def main():
    text = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else sys.stdin.read()
    score, reasons = score_text(text)
    print(f"Score: {score}/100 -> {label(score)}")
    for reason in reasons:
        print(f"  - {reason}")
    if not reasons:
        print("  - No red flags found by the rules (that does not guarantee it is safe)")


if __name__ == "__main__":
    main()
