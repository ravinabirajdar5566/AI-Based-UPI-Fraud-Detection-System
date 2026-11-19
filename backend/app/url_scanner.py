"""Layer 3: payment-link scanner (offline heuristics + blocklist).

Heuristics only - this is a prototype. A production system would add Google Safe Browsing /
VirusTotal lookups, domain-age (WHOIS) checks and URL expansion for shorteners.
"""
import ipaddress
import re
from urllib.parse import urlparse

from . import lists

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"}
BAD_TLDS = {"xyz", "top", "click", "icu", "tk", "ml", "ga", "cf", "gq", "work", "support", "loan",
            "buzz", "monster", "rest", "cyou", "sbs"}
KEYWORDS = ["kyc", "verify", "refund", "reward", "cashback", "lottery", "prize", "blocked", "suspend",
            "urgent", "claim", "gift", "otp", "pin", "update-account", "winner"]
BRANDS = {"phonepe": "phonepe.com", "paytm": "paytm.com", "googlepay": "pay.google.com",
          "gpay": "pay.google.com", "bhim": "bhimupi.org.in", "npci": "npci.org.in",
          "sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com", "axisbank": "axisbank.com"}


def _official(host, dom):
    return host == dom or host.endswith("." + dom)


def scan_url(url):
    """Returns dict(risk 0-1, verdict, reasons)."""
    reasons, score = [], 0.0
    raw = (url or "").strip()
    if not raw:
        return {"risk": 0.0, "verdict": "none", "reasons": []}
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urlparse(raw)
        host = (u.hostname or "").lower()
        port = u.port
    except ValueError:
        return {"risk": 0.9, "verdict": "malicious", "reasons": ["URL is malformed"]}
    if not host:
        return {"risk": 0.9, "verdict": "malicious", "reasons": ["URL has no valid host"]}

    def add(points, msg):
        nonlocal score
        score += points
        reasons.append(msg)

    if host in {d.lower() for d in lists.blacklist()["domains"]}:
        add(1.0, "Domain is on the phishing blocklist")
    if u.scheme != "https":
        add(0.25, "Link does not use HTTPS")
    try:
        ipaddress.ip_address(host)
        add(0.4, "Link uses a raw IP address instead of a domain name")
    except ValueError:
        pass
    if "@" in raw.split("//", 1)[-1].split("/", 1)[0]:
        add(0.3, "Link contains '@' (can hide the real destination)")
    if "xn--" in host:
        add(0.4, "Domain uses punycode (look-alike characters)")
    if len(raw) > 75:
        add(0.15, "Very long URL")
    if host.count(".") >= 4:
        add(0.2, "Too many sub-domains")
    if host in SHORTENERS:
        add(0.3, "Shortened link hides the real destination")
    tld = host.rsplit(".", 1)[-1]
    if tld in BAD_TLDS:
        add(0.25, f"Domain ends with a high-abuse TLD '.{tld}'")
    if host.count("-") >= 3:
        add(0.15, "Domain has many hyphens")
    if port not in (None, 80, 443):
        add(0.15, f"Unusual port {port}")

    hits = [k for k in KEYWORDS if k in (host + u.path + (u.query or "")).lower()]
    if hits:
        add(min(0.3, 0.1 * len(hits)), "Scam-style keywords in link: " + ", ".join(hits[:4]))
    for brand, official in BRANDS.items():
        if brand in host and not _official(host, official):
            add(0.6, f"Looks like '{brand}' but is not the official domain ({official})")
            break

    score = round(min(1.0, score), 3)
    verdict = "safe" if score < 0.3 else "suspicious" if score < 0.6 else "malicious"
    if not reasons:
        reasons.append("No suspicious pattern found (heuristic check only)")
    return {"risk": score, "verdict": verdict, "reasons": reasons, "host": host}
