"""Orchestrates the whole payment check. main.py (FastAPI) is only a thin wrapper around this file."""
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from . import blockchain, bus, config, db, device, lists, model_service, network_check, notify, qr_scanner, risk_engine, url_scanner
from .features import build_features, haversine_km
from .security import h

IST = timedelta(hours=5, minutes=30)


def _hour_ist(ts):
    return (datetime.fromtimestamp(ts, timezone.utc) + IST).hour


def _tx_hash(tx_id, user_id, vpa, amount, ts):
    return h(f"{tx_id}|{user_id}|{vpa}|{amount}|{ts}")


def _complete(tx, user_id):
    """Payment finished -> update behaviour profile and mark as a good (label 0) sample."""
    db.x("INSERT INTO beneficiaries(user_id,vpa,first_seen,count) VALUES(?,?,?,1) "
         "ON CONFLICT(user_id,vpa) DO UPDATE SET count=count+1", (user_id, tx["vpa"], db.now()))
    db.x("UPDATE users SET avg_amount=0.9*avg_amount+0.1*?, txn_count=txn_count+1 WHERE user_id=?",
         (tx["amount"], user_id))
    db.x("UPDATE transactions SET status='COMPLETED', label=COALESCE(label,0) WHERE tx_id=?", (tx["tx_id"],))


def check_payment(p, client_ip=None):
    now = float(p.get("timestamp") or db.now())
    hour = int(p["hour_override"]) if p.get("hour_override") is not None else _hour_ist(now)
    user_id = p.get("user_id", "")
    amount = float(p.get("amount") or 0)
    if amount <= 0:
        raise ValueError("amount must be greater than 0")

    # ---- Layer 1: identity + device + SIM
    dev = device.check_device(user_id, p.get("device_id"), p.get("sim_serial"), p.get("phone"))
    users = db.q("SELECT * FROM users WHERE user_id=?", (user_id,))
    user = users[0] if users else None

    # ---- Layer 2: QR
    qr_payload = p.get("qr_payload") or ""
    vpa = (p.get("receiver_vpa") or "").strip().lower()
    qr = qr_scanner.analyze_qr(qr_payload, entered_amount=amount, entered_vpa=vpa or None) if qr_payload else \
        {"risk": 0.0, "reasons": [], "parsed": None}
    if qr_payload and not vpa and qr.get("parsed"):
        vpa = qr["parsed"]["pa"].lower()
    if not vpa:
        raise ValueError("receiver_vpa (or a QR with a UPI ID) is required")

    # ---- Layer 3: payment link
    link = p.get("payment_link") or ""
    url = url_scanner.scan_url(link) if link else {"risk": 0.0, "reasons": [], "verdict": "none"}

    # ---- Layer 4: network
    n = p.get("network") or {}
    net = network_check.check_network(n.get("ip") or client_ip, n.get("type", "unknown"),
                                      bool(n.get("vpn")), n.get("tls_ok", True))

    # ---- Layer 5: behaviour features
    new_receiver = not (user and db.q("SELECT 1 FROM beneficiaries WHERE user_id=? AND vpa=?", (user_id, vpa)))
    last_hour = db.q("SELECT COUNT(*) AS c FROM transactions WHERE user_id=? AND ts>?", (user_id, now - 3600))[0]["c"]
    dist = 0.0
    if user and p.get("lat") is not None and p.get("lon") is not None:
        dist = haversine_km(user["home_lat"], user["home_lon"], float(p["lat"]), float(p["lon"]))
    reports = lists.report_count(vpa)
    day_start = (now + IST.total_seconds()) // 86400 * 86400 - IST.total_seconds()
    spent_today = db.q("SELECT COALESCE(SUM(amount),0) AS s FROM transactions WHERE user_id=? AND ts>=? "
                       "AND status IN ('COMPLETED','VERIFIED')", (user_id, day_start))[0]["s"]
    daily_limit = float(user["daily_limit"] or config.DEFAULT_DAILY_LIMIT) if user else config.DEFAULT_DAILY_LIMIT
    feat = build_features(amount, user["avg_amount"] if user else 1000, hour, new_receiver,
                          not dev["device_known"], not dev["sim_match"] and dev["device_known"], last_hour,
                          dist, net["risk"], max(qr["risk"], 0.0), url["risk"], reports)
    prob, loaded = model_service.predict(feat)

    layers = {
        "device": {"risk": dev["risk"], "reasons": dev["reasons"], "present": True},
        "qr": {"risk": qr["risk"], "reasons": qr["reasons"], "present": bool(qr_payload)},
        "link": {"risk": url["risk"], "reasons": url["reasons"], "present": bool(link)},
        "network": {"risk": net["risk"], "reasons": net["reasons"], "present": True},
    }
    flags = {
        "receiver_blacklisted": lists.vpa_blacklisted(vpa),
        "user_found": dev["user_found"], "phone_match": dev["phone_match"],
        "sim_swap": dev["device_known"] and not dev["sim_match"],
        "new_device": not dev["device_known"] and dev["user_found"],
        "account_frozen": bool(user and user.get("frozen")),
        "limit_exceeded": bool(user) and spent_today + amount > daily_limit,
    }
    res = risk_engine.decide(prob, layers, feat, amount, flags)

    explain = _explain(res, prob, layers, feat, amount, flags, user["avg_amount"] if user else 1000)

    # ---- store + ledger
    tx_id = "TX" + secrets.token_hex(6).upper()
    status = {"ALLOW": "APPROVED", "VERIFY": "PENDING_VERIFICATION", "BLOCK": "BLOCKED"}[res["decision"]]
    db.x("INSERT INTO transactions(tx_id,user_id,vpa,amount,ts,risk_score,decision,status,reasons,features,label,explain) "
         "VALUES(?,?,?,?,?,?,?,?,?,?,NULL,?)",
         (tx_id, user_id, vpa, amount, now, res["risk_score"], res["decision"], status,
          db.dumps(res["reasons"]), db.dumps(feat), db.dumps(explain)))
    tx = {"tx_id": tx_id, "vpa": vpa, "amount": amount}
    block = blockchain.add_block(_tx_hash(tx_id, user_id, vpa, amount, now), res["risk_score"], status)

    out = {"tx_id": tx_id, "decision": res["decision"], "color": res["color"], "risk_score": res["risk_score"],
           "status": status, "reasons": res["reasons"], "breakdown": res["breakdown"],
           "layers": {k: {"risk": v["risk"], "present": v["present"]} for k, v in layers.items()},
           "model_loaded": loaded, "receiver_vpa": vpa, "ledger_block": block,
           "explain": explain, "spent_today": spent_today, "daily_limit": daily_limit}
    if res["decision"] == "ALLOW":
        _complete(tx, user_id)
        out["status"] = "COMPLETED"
        out["message"] = "Low risk - payment allowed."
    elif res["decision"] == "VERIFY":
        otp = config.DEMO_OTP_FIXED or f"{secrets.randbelow(10**6):06d}"
        db.x("INSERT OR REPLACE INTO otps(tx_id,otp_hash,expires,attempts) VALUES(?,?,?,0)",
             (tx_id, hashlib.sha256(otp.encode()).hexdigest(), now + config.OTP_TTL_SECONDS))
        out["message"] = "Medium risk - additional verification required (OTP)."
        out["verification"] = ["OTP"]
        if config.DEMO_MODE:
            out["demo_otp"] = otp  # a real system sends this by SMS / uses biometric
    else:
        out["message"] = "High risk - payment blocked and an alert was raised."
        out["alert"] = "Security alert sent to the account holder and bank fraud team (simulated)."
    _announce(user, tx_id, vpa, amount, res, out["status"])
    return out


def _explain(res, prob, layers, feat, amount, flags, avg):
    """Explainable AI as a what-if on the FINAL score: neutralise one signal at a time, re-run the whole
    decision (model + layers + rules + overrides) and report how many points the score drops."""
    import math
    avg = max(float(avg or 0), 100.0)
    scen = [
        ("Phone, device or SIM mismatch", {"new_device": 0, "sim_mismatch": 0}, ["device"],
         {"sim_swap": False, "new_device": False, "user_found": True, "phone_match": True}, None),
        ("Suspicious QR code", {"qr_risk": 0.0}, ["qr"], {}, None),
        ("Unsafe payment link", {"url_risk": 0.0}, ["link"], {}, None),
        ("Risky network", {"network_risk": 0.0}, ["network"], {}, None),
        ("New receiver", {"new_receiver": 0}, [], {}, None),
        ("Unusual amount", {"amount_ratio": 1.0, "amount_log": math.log1p(avg)}, [], {}, min(amount, avg)),
        ("Time of day", {"hour": 12, "is_night": 0}, [], {}, None),
        ("Rapid payments", {"txn_last_hour": 0}, [], {}, None),
        ("Far from home", {"distance_km": 0.0}, [], {}, None),
        ("Reported or blacklisted receiver", {"receiver_reports": 0}, [], {"receiver_blacklisted": False}, None),
        ("Daily limit exceeded", {}, [], {"limit_exceeded": False}, None),
        ("Account frozen", {}, [], {"account_frozen": False}, None),
    ]
    feats = [{**feat, **fk} for _, fk, _, _, _ in scen]
    probs = model_service.proba_many(feats)
    out = []
    for (label, _, zero, fl, amt), f, p in zip(scen, feats, probs):
        lay = {k: ({**v, "risk": 0.0} if k in zero else v) for k, v in layers.items()}
        alt = risk_engine.decide(p, lay, f, amt if amt is not None else amount, {**flags, **fl})["risk_score"]
        out.append({"label": label, "impact": round(res["risk_score"] - alt, 1)})
    out = [o for o in out if o["impact"] >= 0.5]
    out.sort(key=lambda o: -o["impact"])
    return out[:6]


def _announce(user, tx_id, vpa, amount, res, status):
    """Push the result to live streams and raise a bell notification for risky payments."""
    uid = user["user_id"] if user else ""
    bus.publish({"type": "tx", "user_id": uid, "uname": user["name"] if user else "unknown", "tx_id": tx_id,
                 "vpa": vpa, "amount": amount, "decision": res["decision"], "score": res["risk_score"],
                 "status": status, "reasons": [r["text"] for r in res["reasons"][:3]]})
    if not uid:
        return
    if res["decision"] == "BLOCK":
        notify.add(uid, "bad", f"Payment of Rs {amount:,.0f} blocked",
                   (res["reasons"][0]["text"] if res["reasons"] else "High fraud risk") + f" ({tx_id})")
    elif res["decision"] == "VERIFY":
        notify.add(uid, "warn", f"Verify payment of Rs {amount:,.0f}", f"OTP needed for {tx_id}")


def verify_otp(tx_id, otp):
    rows = db.q("SELECT * FROM transactions WHERE tx_id=?", (tx_id,))
    if not rows:
        raise ValueError("unknown transaction")
    tx = rows[0]
    if tx["status"] != "PENDING_VERIFICATION":
        raise ValueError(f"transaction is {tx['status']}, nothing to verify")
    o = db.q("SELECT * FROM otps WHERE tx_id=?", (tx_id,))[0]
    now = db.now()

    def finish(status, ok):
        db.x("UPDATE transactions SET status=? WHERE tx_id=?", (status, tx_id))
        b = blockchain.add_block(_tx_hash(tx_id, tx["user_id"], tx["vpa"], tx["amount"], tx["ts"]),
                                 tx["risk_score"], status)
        bus.publish({"type": "tx_update", "user_id": tx["user_id"], "tx_id": tx_id, "status": status})
        return {"tx_id": tx_id, "verified": ok, "status": status, "ledger_block": b}

    if now > o["expires"]:
        r = finish("BLOCKED_OTP_EXPIRED", False)
        r["message"] = "OTP expired - payment cancelled."
        return r
    if hashlib.sha256(str(otp).encode()).hexdigest() == o["otp_hash"]:
        db.x("UPDATE transactions SET status='VERIFIED' WHERE tx_id=?", (tx_id,))
        _complete({"tx_id": tx_id, "vpa": tx["vpa"], "amount": tx["amount"]}, tx["user_id"])
        b = blockchain.add_block(_tx_hash(tx_id, tx["user_id"], tx["vpa"], tx["amount"], tx["ts"]),
                                 tx["risk_score"], "COMPLETED_AFTER_VERIFICATION")
        bus.publish({"type": "tx_update", "user_id": tx["user_id"], "tx_id": tx_id, "status": "COMPLETED"})
        return {"tx_id": tx_id, "verified": True, "status": "COMPLETED", "message": "Verified - payment completed.",
                "ledger_block": b}
    attempts = o["attempts"] + 1
    db.x("UPDATE otps SET attempts=? WHERE tx_id=?", (attempts, tx_id))
    if attempts >= config.OTP_MAX_ATTEMPTS:
        r = finish("BLOCKED_OTP_FAILED", False)
        r["message"] = "Too many wrong OTPs - payment blocked."
        return r
    return {"tx_id": tx_id, "verified": False, "status": "PENDING_VERIFICATION",
            "message": f"Wrong OTP. {config.OTP_MAX_ATTEMPTS - attempts} attempt(s) left."}


def report_fraud(user_id, tx_id=None, vpa=None, reason="user reported"):
    """Feedback loop: reported receivers gain risk, and the transaction becomes a fraud (label 1) training row."""
    tx = None
    if tx_id:
        rows = db.q("SELECT * FROM transactions WHERE tx_id=?", (tx_id,))
        if not rows:
            raise ValueError("unknown transaction")
        tx = rows[0]
        vpa = tx["vpa"]
        db.x("UPDATE transactions SET label=1 WHERE tx_id=?", (tx_id,))
    if not vpa:
        raise ValueError("tx_id or vpa required")
    db.x("INSERT INTO reports(vpa,user_id,reason,ts) VALUES(?,?,?,?)", (vpa.lower(), user_id, reason, db.now()))
    th = _tx_hash(tx["tx_id"], tx["user_id"], tx["vpa"], tx["amount"], tx["ts"]) if tx else h("REPORT|" + vpa)
    block = blockchain.add_block(th, tx["risk_score"] if tx else 100, "REPORTED_FRAUD")
    bus.publish({"type": "report", "user_id": user_id, "vpa": vpa.lower()})
    return {"reported": vpa.lower(), "total_reports": lists.report_count(vpa),
            "auto_blacklisted": lists.vpa_blacklisted(vpa), "ledger_block": block}


def transactions_for(user_id, limit=20):
    rows = db.q("SELECT * FROM transactions WHERE user_id=? ORDER BY ts DESC LIMIT ?", (user_id, limit))
    for r in rows:
        r.pop("features", None)
        r["explain"] = json.loads(r["explain"]) if r.get("explain") else []
        r["reasons"] = json.loads(r["reasons"]) if r.get("reasons") else []
    return rows
