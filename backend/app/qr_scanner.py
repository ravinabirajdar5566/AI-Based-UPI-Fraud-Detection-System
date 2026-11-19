"""Layer 2: QR scanner. Decodes a QR image and verifies the UPI payment details inside it."""
import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

import numpy as np

from . import lists

try:
    import cv2
except ImportError:
    cv2 = None

VPA_RE = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$")
KNOWN_HANDLES = {
    "okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl", "paytm", "upi", "apl",
    "sbi", "hdfcbank", "icici", "axisbank", "pnb", "boi", "cnrb", "unionbank", "barodampay",
    "fbl", "kotak", "postbank", "airtel", "jio", "idfcbank", "indus", "yesbank", "federal",
}
SCAM_WORDS = [
    "refund", "kyc", "cashback", "lottery", "reward", "prize", "helpdesk", "customercare",
    "support", "winner", "claim", "gift"
]


def decode_qr_image(image_bytes: bytes) -> Optional[str]:
    """Return the text inside a QR image (PNG/JPG/WEBP bytes) or None.

    Employs OpenCV's ArUco & standard QRCodeDetector with multi-scale,
    quiet zone padding, and transparency alpha blending.
    """
    if cv2 is None or not image_bytes:
        return None

    try:
        # 1. Read unchanged to inspect channels (handles transparency in PNG)
        arr = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_UNCHANGED)
        if arr is None:
            return None

        # 2. Alpha blending: blend transparent pixels onto pure white background
        if len(arr.shape) == 3 and arr.shape[2] == 4:
            alpha = arr[:, :, 3].astype(float) / 255.0
            bgr = arr[:, :, :3].astype(float)
            white_bg = np.ones_like(bgr) * 255.0
            blended = (bgr * alpha[:, :, None] + white_bg * (1.0 - alpha[:, :, None])).astype(np.uint8)
            gray = cv2.cvtColor(blended, cv2.COLOR_BGR2GRAY)
        elif len(arr.shape) == 3:
            gray = cv2.cvtColor(arr, cv2.COLOR_BGR2GRAY)
        else:
            gray = arr

        # 3. Setup detectors
        detectors = []
        if hasattr(cv2, "QRCodeDetectorAruco"):
            try:
                detectors.append(cv2.QRCodeDetectorAruco())
            except Exception:
                pass
        detectors.append(cv2.QRCodeDetector())

        # 4. Generate variants: raw, padded quiet zone, and thresholded
        variants = [gray]

        # White border (quiet zone) is essential for tightly cropped QR codes
        bordered = cv2.copyMakeBorder(gray, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=255)
        variants.append(bordered)

        # Otsu binarization
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.append(otsu)
        variants.append(cv2.copyMakeBorder(otsu, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=255))

        # 5. Search across variants, scales, and detector models
        scales = (1.0, 1.5, 2.0, 0.75, 0.5)
        for var in variants:
            for scale in scales:
                img = var if scale == 1.0 else cv2.resize(var, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
                for det in detectors:
                    # Single decode
                    text, _, _ = det.detectAndDecode(img)
                    if text and text.strip():
                        return text.strip()

                    # Multi decode fallback
                    if hasattr(det, "detectAndDecodeMulti"):
                        ok, decoded_info, _, _ = det.detectAndDecodeMulti(img)
                        if ok and decoded_info:
                            for t in decoded_info:
                                if t and t.strip():
                                    return t.strip()

        return None
    except Exception:
        return None


def generate_qr_png(text: str, box: int = 10, border: int = 4) -> bytes:
    """Make a high-resolution, high-contrast QR PNG image with a 4-module quiet zone."""
    if cv2 is None:
        raise RuntimeError("OpenCV not installed")

    text = (text or "").strip()
    if not text:
        text = "upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40&cu=INR"

    enc = cv2.QRCodeEncoder.create()
    img = enc.encode(text)
    # Resize with INTER_NEAREST to preserve crisp square edges
    img = cv2.resize(img, None, fx=box, fy=box, interpolation=cv2.INTER_NEAREST)
    img = cv2.copyMakeBorder(
        img,
        border * box,
        border * box,
        border * box,
        border * box,
        cv2.BORDER_CONSTANT,
        value=255
    )
    ok, buf = cv2.imencode(".png", img)
    if not ok:
        raise RuntimeError("Failed to encode QR image as PNG")
    return buf.tobytes()


def parse_upi_uri(text: str) -> Optional[Dict[str, str]]:
    """upi://pay?pa=x@bank&pn=Name&am=10&cu=INR  ->  dict or None if not a UPI URI."""
    clean = (text or "").strip()
    try:
        u = urlparse(clean)
    except ValueError:
        return None

    if u.scheme.lower() != "upi":
        return None

    query = u.query
    if not query and "?" in clean:
        query = clean.split("?", 1)[1]

    p = {k.lower(): unquote(v[0]) for k, v in parse_qs(query).items()}
    return {
        "pa": p.get("pa", "").strip(),
        "pn": p.get("pn", "").strip(),
        "am": p.get("am", "").strip(),
        "cu": p.get("cu", "INR").strip(),
        "tn": p.get("tn", "").strip(),
        "action": (u.netloc or "pay").lower(),
    }


def analyze_qr(payload: str, entered_amount: Optional[float] = None, entered_vpa: Optional[str] = None) -> Dict[str, Any]:
    """Check a QR payload. Returns dict(risk 0-1, reasons, parsed, is_upi, verified_merchant)."""
    reasons, risks = [], []
    res = {
        "risk": 0.0,
        "reasons": reasons,
        "parsed": None,
        "is_upi": False,
        "verified_merchant": False,
        "amount_mismatch": False,
        "vpa_mismatch": False,
    }

    if not payload:
        return res

    parsed = parse_upi_uri(payload)
    if parsed is None:
        if re.match(r"^https?://", payload.strip(), re.I):
            reasons.append("QR contains a web link, not a UPI payment - do not open it to pay")
            res["risk"] = 0.7
            res["is_link"] = True
        else:
            reasons.append("QR is not a valid UPI payment QR")
            res["risk"] = 0.6
        return res

    res["parsed"] = parsed
    res["is_upi"] = True
    pa, pn = parsed["pa"].strip(), parsed["pn"].strip()

    if parsed["action"] == "collect":
        risks.append(0.8)
        reasons.append("QR is a COLLECT request - scanning a QR to pay should never pull money from you")

    if not pa:
        risks.append(0.9)
        reasons.append("QR has no receiver UPI ID")
    elif not VPA_RE.match(pa):
        risks.append(0.8)
        reasons.append("Receiver UPI ID has an invalid format")
    else:
        handle = pa.split("@")[1].lower() if "@" in pa else ""
        if handle not in KNOWN_HANDLES:
            risks.append(0.35)
            reasons.append(f"Unknown UPI handle '@{handle}'")
        if lists.vpa_blacklisted(pa):
            risks.append(1.0)
            reasons.append("Receiver UPI ID is blacklisted / reported for fraud")

    low = f"{pa} {pn}".lower()
    hit = [w for w in SCAM_WORDS if w in low]
    if hit:
        risks.append(0.6)
        reasons.append("Receiver name/ID contains scam-style words: " + ", ".join(hit))

    reg = lists.merchants().get(pa.lower()) if pa else None
    if reg:
        if reg.lower() == pn.lower():
            res["verified_merchant"] = True
        else:
            risks.append(0.7)
            reasons.append(f"QR name '{pn}' does not match registered merchant name '{reg}'")

    # Amount verification
    if parsed.get("am") and entered_amount is not None:
        try:
            qr_amt = float(parsed["am"])
            ent_amt = float(entered_amount)
            if abs(qr_amt - ent_amt) > 0.009:
                risks.append(0.85)
                res["amount_mismatch"] = True
                reasons.append(f"Amount mismatch: QR requests Rs {qr_amt:,.2f} but entered amount is Rs {ent_amt:,.2f}")
            else:
                reasons.append(f"Amount verified: Rs {qr_amt:,.2f}")
        except ValueError:
            risks.append(0.5)
            reasons.append("Amount inside QR is not a valid number")

    # Receiver VPA verification
    if entered_vpa and pa:
        if entered_vpa.strip().lower() != pa.lower():
            risks.append(0.95)
            res["vpa_mismatch"] = True
            reasons.append(f"Receiver mismatch: QR routes to '{pa}' but entered UPI ID is '{entered_vpa.strip()}'")
        else:
            reasons.append(f"Receiver UPI ID matches: '{pa}'")

    if risks:
        res["risk"] = round(min(1.0, max(risks) + 0.05 * (len(risks) - 1)), 3)
    elif res["verified_merchant"]:
        reasons.append(f"Verified merchant: {reg}")

    return res
