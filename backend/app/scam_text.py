"""Scam-message checker: paste an SMS / WhatsApp text or describe what a caller asked you to do.
Looks for the classic social-engineering moves and scans every link inside the text."""
import re

from . import url_scanner

URL_RE = re.compile(r"(https?://[^\s]+|\b[a-z0-9\-]+\.(?:xyz|top|click|icu|tk|ml|ga|cf|gq|work|support|loan|buzz)\b[^\s]*)", re.I)

RULES = [
    (r"\b(share|send|tell|give|read out)\b.{0,25}\b(otp|pin|cvv|password|upi pin)\b", 0.95,
     "Asks you to share an OTP / PIN / password - no bank or UPI app ever does this"),
    (r"\b(anydesk|teamviewer|quicksupport|screen ?share|remote access|airdroid)\b", 0.9,
     "Asks you to install a screen-sharing app - scammers use these to control your phone"),
    (r"\b(enter|type|put)\b.{0,20}\b(upi )?pin\b.{0,30}\b(receive|get|refund|credit|collect)\b", 0.95,
     "You never enter your UPI PIN to RECEIVE money"),
    (r"\b(collect request|request money|approve the request)\b", 0.6,
     "Asks you to approve a collect request - approving sends money out"),
    (r"\b(kyc|know your customer)\b.{0,40}\b(expire|update|pending|suspend|block)", 0.8,
     "Fake KYC-expiry pressure"),
    (r"\b(lottery|lucky draw|you (have )?won|prize|reward points?)\b", 0.7, "Prize / lottery bait"),
    (r"\b(refund|cashback)\b.{0,40}\b(claim|click|link|verify)", 0.65, "Refund / cashback bait"),
    (r"\b(urgent|immediately|within \d+ ?(minutes?|hours?)|last chance|account (will be )?(blocked|suspended|closed))\b", 0.5,
     "Artificial urgency to stop you thinking"),
    (r"\b(wrong(ly)? (sent|transferred)|sent .{0,15} by mistake|return (the )?money)\b", 0.55,
     "'Money sent by mistake' trick"),
    (r"\b(customer care|helpline|support) (number|no\.?)\b.{0,25}\b\d{8,}", 0.5, "Unofficial 'customer care' number"),
    (r"\b(work from home|part[- ]time job|earn \d+)\b", 0.45, "Task / job scam wording"),
]


def analyze_message(text):
    text = (text or "").strip()
    if len(text) < 5:
        raise ValueError("Paste the message or describe what the caller asked")
    reasons, risk = [], 0.0
    for pat, score, why in RULES:
        if re.search(pat, text, re.I | re.S):
            reasons.append({"text": why, "severity": score})
            risk = max(risk, score)
    links = []
    for m in URL_RE.findall(text)[:5]:
        url = m if m.lower().startswith("http") else "http://" + m
        r = url_scanner.scan_url(url)
        links.append({"url": m, "risk": r["risk"], "verdict": r["verdict"]})
        if r["risk"] >= 0.3:
            reasons.append({"text": f"Link {m[:50]} looks {r['verdict']}", "severity": r["risk"]})
        risk = max(risk, r["risk"])
    n = len([r for r in reasons if r["severity"] >= 0.5])
    if n >= 2:
        risk = min(1.0, risk + 0.1 * (n - 1))
    reasons.sort(key=lambda r: -r["severity"])
    verdict = "scam" if risk >= 0.7 else "suspicious" if risk >= 0.35 else "no red flags found"
    return {"risk": round(risk, 2), "verdict": verdict, "reasons": reasons, "links": links}
