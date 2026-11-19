"""AI Fraud Attack Replay Lab.

Provides safe, interactive simulation of advanced UPI fraud attack vectors
against the live multi-layer detection engine and AI model.
Simulations evaluate real layers and rules without modifying real user balances.
"""
import hashlib
import json
import math
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import (audit, blockchain, config, db, device, features, lists,
               model_service, network_check, qr_scanner, risk_engine, service,
               url_scanner)

# Ensure simulations table exists
db.init_db()

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "phishing_link": {
        "id": "phishing_link",
        "name": "Phishing Payment Link Attack",
        "category": "Social Engineering & Deceptive URLs",
        "severity": "CRITICAL",
        "threat_actor": "Credential & Payment Harvester Syndicate",
        "technique": "CWE-920: Spear Phishing / Insecure Deceptive Link",
        "description": "An urgent payment link sent via SMS/WhatsApp claiming to be KYC verification or lottery claim, utilizing suspicious TLD, insecure HTTP, and brand impersonation.",
        "params": {
            "vpa": "ramesh.kirana@ybl",
            "amount": 2500.0,
            "payment_link": "http://paytm-kyc-update.xyz/verify?otp=1",
            "network_type": "mobile_data",
            "vpn": False,
            "tls_ok": False,
        },
        "target_layer": "Layer 3: Payment Link Scanner",
        "expected_verdict": "BLOCK",
    },
    "tampered_qr": {
        "id": "tampered_qr",
        "name": "Tampered QR Code Amount Injection",
        "category": "QR Hijacking & Amount Tampering",
        "severity": "HIGH",
        "threat_actor": "Physical / Digital QR Manipulator",
        "technique": "CWE-345: Insufficient Verification of Data Authenticity",
        "description": "A merchant's static QR code encoded for a small payment (e.g. ₹40 tea/snacks) is intercepted or swapped, injecting an unauthorized transaction request of ₹4,000.",
        "params": {
            "vpa": "chaiwala@oksbi",
            "amount": 4000.0,
            "qr_payload": "upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40&cu=INR",
            "network_type": "home_wifi",
            "vpn": False,
            "tls_ok": True,
        },
        "target_layer": "Layer 2: QR Integrity & URI Scanner",
        "expected_verdict": "BLOCK",
    },
    "stolen_device": {
        "id": "stolen_device",
        "name": "Stolen Device & Location Anomaly",
        "category": "Device Theft & Account Takeover",
        "severity": "CRITICAL",
        "threat_actor": "Device Thief / Fraud Ring",
        "technique": "CWE-287: Improper Authentication via Compromised Hardware",
        "description": "A stolen phone or account takeover attempted from an untrusted hardware ID and rogue SIM serial in Delhi, 1,200 km away from home, over open unencrypted Wi-Fi.",
        "params": {
            "vpa": "mule.transfers@oksbi",
            "amount": 75000.0,
            "device_id": "DEV-STOLEN-X89",
            "sim_serial": "SIM-ROGUE-404",
            "lat": 28.6139,
            "lon": 77.2090,
            "network_type": "public_wifi_open",
            "vpn": True,
            "tls_ok": True,
        },
        "target_layer": "Layer 1 (Identity/Device) & Layer 4 (Network)",
        "expected_verdict": "BLOCK",
    },
    "sim_swap": {
        "id": "sim_swap",
        "name": "SIM Swap / IMSI Port Hijack",
        "category": "Telecom Fraud & SIM Hijack",
        "severity": "HIGH",
        "threat_actor": "SIM Swapper / Social Engineer",
        "technique": "CWE-384: Session Hijacking via Telecom Port",
        "description": "The device hardware matches the user's phone, but the SIM IMSI serial has changed without bank authentication, attempting an abnormal fund transfer.",
        "params": {
            "vpa": "friend.new@oksbi",
            "amount": 18000.0,
            "sim_serial": "SIM-SWAPPED-999",
            "network_type": "mobile_data",
            "vpn": False,
            "tls_ok": True,
        },
        "target_layer": "Layer 1: SIM Binding Verification",
        "expected_verdict": "BLOCK",
    },
    "high_value_burst": {
        "id": "high_value_burst",
        "name": "Midnight High-Value Velocity Burst",
        "category": "Behavioral Anomaly & Rapid Burst",
        "severity": "HIGH",
        "threat_actor": "Compromised Account Drainer",
        "technique": "CWE-799: Improper Control of Interaction Frequency",
        "description": "Sudden abnormal ₹85,000 transaction (70x average) initiated at 2:30 AM to a brand new beneficiary with multiple rapid prior payments, testing account balance exhaustion.",
        "params": {
            "vpa": "quick.cashout@okaxis",
            "amount": 85000.0,
            "hour_override": 2,
            "network_type": "home_wifi",
            "vpn": False,
            "tls_ok": True,
        },
        "target_layer": "Layer 5: Behavioral AI & Rules Engine",
        "expected_verdict": "BLOCK",
    },
    "merchant_impersonation": {
        "id": "merchant_impersonation",
        "name": "Impersonated Merchant & Name Mismatch",
        "category": "Merchant Spoofing & Phishing",
        "severity": "CRITICAL",
        "threat_actor": "Scam Syndicate / Impersonator",
        "technique": "CWE-1007: Insufficient Visual Discrimination of Displayed Information",
        "description": "A fraudulent payment request displays the name 'MSEB Electricity Support' to mimic a genuine utility, but routes the funds to a blacklisted scam UPI ID.",
        "params": {
            "vpa": "refund.helpdesk@ybl",
            "amount": 3200.0,
            "qr_payload": "upi://pay?pa=refund.helpdesk@ybl&pn=MSEB%20Electricity%20Support&am=3200&cu=INR",
            "network_type": "public_wifi_secured",
            "vpn": False,
            "tls_ok": True,
        },
        "target_layer": "Layer 2: QR Scanner & Receiver Blacklist",
        "expected_verdict": "BLOCK",
    },
}


def list_scenarios() -> List[Dict[str, Any]]:
    """Return all available predefined scenarios with metadata."""
    return list(SCENARIOS.values())


def _get_user_context(account: Dict[str, Any]) -> tuple[Dict[str, Any], str]:
    """Retrieve user record and trusted identifiers."""
    user_id = account.get("user_id") or ""
    users = db.q("SELECT * FROM users WHERE user_id=?", (user_id,)) if user_id else []
    if users:
        return users[0], user_id

    # Fallback to demo user U1001 if admin account without user profile
    fallback = db.q("SELECT * FROM users WHERE user_id='U1001'")
    if fallback:
        return fallback[0], "U1001"

    # Minimal in-memory fallback user
    return {
        "user_id": "U1001",
        "name": account.get("name") or "Demo User",
        "home_lat": 18.5204,
        "home_lon": 73.8567,
        "avg_amount": 1000.0,
        "txn_count": 5,
        "daily_limit": 50000.0,
        "frozen": 0,
    }, "U1001"


def evaluate_payload(p: Dict[str, Any], user: Dict[str, Any], now: float, is_normal: bool = False) -> Dict[str, Any]:
    """Evaluates a transaction payload using the real 5-layer pipeline and risk engine

    without executing state mutations or balance updates.
    """
    user_id = user.get("user_id", "U1001")
    amount = float(p.get("amount") or 0)
    hour = int(p["hour_override"]) if p.get("hour_override") is not None else service._hour_ist(now)

    # Layer 1: Device & SIM
    if is_normal:
        dev = {"risk": 0.0, "reasons": [], "user_found": True, "phone_match": True,
               "device_known": True, "sim_match": True}
    else:
        dev = device.check_device(user_id, p.get("device_id"), p.get("sim_serial"), p.get("phone"))

    # Layer 2: QR Scanner
    qr_payload = p.get("qr_payload") or ""
    vpa = (p.get("receiver_vpa") or "").strip().lower()
    qr = (qr_scanner.analyze_qr(qr_payload, entered_amount=amount, entered_vpa=vpa or None)
          if qr_payload else {"risk": 0.0, "reasons": [], "parsed": None})
    if qr_payload and not vpa and qr.get("parsed"):
        vpa = qr["parsed"]["pa"].lower()
    if not vpa:
        vpa = "unknown.merchant@ybl"

    # Layer 3: Payment link
    link = p.get("payment_link") or ""
    url = url_scanner.scan_url(link) if link else {"risk": 0.0, "reasons": [], "verdict": "none"}

    # Layer 4: Network check
    net_info = p.get("network") or {}
    net = network_check.check_network(
        net_info.get("ip"),
        net_info.get("type", "unknown"),
        bool(net_info.get("vpn")),
        net_info.get("tls_ok", True)
    )

    # Layer 5: Behavioral features & ML
    new_receiver = False if is_normal else not db.q("SELECT 1 FROM beneficiaries WHERE user_id=? AND vpa=?", (user_id, vpa))
    last_hour = int(p.get("txn_last_hour_override") or 0)
    dist = 0.0
    if p.get("lat") is not None and p.get("lon") is not None and user.get("home_lat") is not None:
        dist = features.haversine_km(user["home_lat"], user["home_lon"], float(p["lat"]), float(p["lon"]))

    reports = 0 if is_normal else lists.report_count(vpa)
    daily_limit = float(user.get("daily_limit") or config.DEFAULT_DAILY_LIMIT)

    feat = features.build_features(
        amount,
        user.get("avg_amount") or 1000.0,
        hour,
        new_receiver,
        not dev["device_known"],
        not dev["sim_match"] and dev["device_known"],
        last_hour,
        dist,
        net["risk"],
        max(qr["risk"], 0.0),
        url["risk"],
        reports
    )
    prob, loaded = model_service.predict(feat)

    layers = {
        "device": {"risk": dev["risk"], "reasons": dev["reasons"], "present": True},
        "qr": {"risk": qr["risk"], "reasons": qr["reasons"], "present": bool(qr_payload)},
        "link": {"risk": url["risk"], "reasons": url["reasons"], "present": bool(link)},
        "network": {"risk": net["risk"], "reasons": net["reasons"], "present": True},
    }

    flags = {
        "receiver_blacklisted": False if is_normal else lists.vpa_blacklisted(vpa),
        "user_found": dev["user_found"],
        "phone_match": dev["phone_match"],
        "sim_swap": dev["device_known"] and not dev["sim_match"],
        "new_device": not dev["device_known"] and dev["user_found"],
        "account_frozen": bool(user.get("frozen")),
        "limit_exceeded": amount > daily_limit,
    }

    res = risk_engine.decide(prob, layers, feat, amount, flags)
    explain = service._explain(res, prob, layers, feat, amount, flags, user.get("avg_amount") or 1000.0)

    # Compile layer detection summary
    layer_summary = {
        "device": {
            "name": "Identity, Device & SIM Binding",
            "risk": dev["risk"],
            "status": "INTERCEPTED" if dev["risk"] >= 0.7 else ("FLAGGED" if dev["risk"] >= 0.3 else "PASSED"),
            "reasons": dev["reasons"],
        },
        "qr": {
            "name": "QR Scanner & URI Integrity",
            "risk": qr["risk"],
            "status": "SKIPPED" if not qr_payload else ("INTERCEPTED" if qr["risk"] >= 0.7 else ("FLAGGED" if qr["risk"] >= 0.3 else "PASSED")),
            "reasons": qr["reasons"],
        },
        "link": {
            "name": "Payment Link & Domain Reputation",
            "risk": url["risk"],
            "status": "SKIPPED" if not link else ("INTERCEPTED" if url["risk"] >= 0.7 else ("FLAGGED" if url["risk"] >= 0.3 else "PASSED")),
            "reasons": url["reasons"],
        },
        "network": {
            "name": "Network & Threat Intelligence",
            "risk": net["risk"],
            "status": "INTERCEPTED" if net["risk"] >= 0.7 else ("FLAGGED" if net["risk"] >= 0.3 else "PASSED"),
            "reasons": net["reasons"],
        },
        "behavior": {
            "name": "Behavioral AI & Rules Engine",
            "risk": round(prob, 3),
            "status": "INTERCEPTED" if prob >= 0.65 or res["breakdown"]["rule_points"] >= 40 else ("FLAGGED" if prob >= 0.35 else "PASSED"),
            "reasons": [r["text"] for r in res["reasons"] if r["layer"] in ("behavior", "rule")],
        },
    }

    return {
        "vpa": vpa,
        "amount": amount,
        "risk_score": res["risk_score"],
        "decision": res["decision"],
        "color": res["color"],
        "reasons": res["reasons"],
        "breakdown": res["breakdown"],
        "explain": explain,
        "layers": layers,
        "layer_summary": layer_summary,
        "features": {k: round(float(v), 3) if isinstance(v, float) else v for k, v in feat.items()},
        "model_loaded": loaded,
    }


def simulate(account: Dict[str, Any], scenario_id: str, custom_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute safe side-by-side attack replay simulation."""
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario ID '{scenario_id}'. Available: {list(SCENARIOS.keys())}")

    scenario = SCENARIOS[scenario_id]
    user, user_id = _get_user_context(account)
    now = db.now()

    # Find registered identifiers if user is Rahul or Priya
    trusted_dev = "DEV-RAHUL-S23" if user_id == "U1001" else ("DEV-PRIYA-PIXEL" if user_id == "U1002" else "DEV-TRUSTED-01")
    trusted_sim = "SIM-RAHUL-8991" if user_id == "U1001" else ("SIM-PRIYA-8992" if user_id == "U1002" else "SIM-TRUSTED-01")

    # 1. Normal Baseline Payload
    normal_payload = {
        "receiver_vpa": "ramesh.kirana@ybl",
        "amount": 500.0,
        "qr_payload": "",
        "payment_link": "",
        "device_id": trusted_dev,
        "sim_serial": trusted_sim,
        "phone": None,
        "lat": user.get("home_lat") or 18.5204,
        "lon": user.get("home_lon") or 73.8567,
        "hour_override": 14,
        "network": {"type": "home_wifi", "ip": "49.36.10.5", "vpn": False, "tls_ok": True},
        "txn_last_hour_override": 0,
    }

    # 2. Attack Simulation Payload
    attack_params = dict(scenario["params"])
    if custom_params:
        attack_params.update(custom_params)

    attack_payload = {
        "receiver_vpa": attack_params.get("vpa", "scam.mule@ybl"),
        "amount": float(attack_params.get("amount", 2000.0)),
        "qr_payload": attack_params.get("qr_payload", ""),
        "payment_link": attack_params.get("payment_link", ""),
        "device_id": attack_params.get("device_id", trusted_dev),
        "sim_serial": attack_params.get("sim_serial", trusted_sim),
        "phone": attack_params.get("phone", None),
        "lat": attack_params.get("lat", user.get("home_lat") or 18.5204),
        "lon": attack_params.get("lon", user.get("home_lon") or 73.8567),
        "hour_override": attack_params.get("hour_override", None),
        "network": {
            "type": attack_params.get("network_type", "home_wifi"),
            "ip": attack_params.get("ip", "103.21.244.2"),
            "vpn": bool(attack_params.get("vpn", False)),
            "tls_ok": bool(attack_params.get("tls_ok", True)),
        },
        "txn_last_hour_override": attack_params.get("txn_last_hour_override", 0),
    }

    # Evaluate both using real engine
    normal_result = evaluate_payload(normal_payload, user, now, is_normal=True)
    attack_result = evaluate_payload(attack_payload, user, now, is_normal=False)

    # Generate simulation ID and anchor in ledger (clearly marked SIMULATION)
    sim_id = "SIM" + secrets.token_hex(6).upper()
    tx_hash = hashlib.sha256(f"{sim_id}|{user_id}|{attack_result['vpa']}|{attack_result['amount']}|{now}".encode()).hexdigest()
    
    # Store proof-of-work simulation block on the chain
    ledger_block = blockchain.add_block(tx_hash, attack_result["risk_score"], f"SIM_{attack_result['decision']}")
    ledger_status = blockchain.verify_chain()

    # Record audit log entry
    audit.log(
        account.get("username", user_id),
        "replay_simulation",
        scenario_id,
        f"Simulated {scenario['name']} -> {attack_result['decision']} (score={attack_result['risk_score']})"
    )

    # Persist simulation in simulations table
    full_data = {
        "sim_id": sim_id,
        "scenario": scenario,
        "normal": normal_result,
        "attack": attack_result,
        "normal_payload": normal_payload,
        "attack_payload": attack_payload,
        "ledger_block": ledger_block,
        "ledger_status": ledger_status,
        "audit_hash": tx_hash,
    }

    db.x(
        "INSERT INTO simulations(id, user_id, scenario_id, scenario_name, ts, risk_score, decision, normal_score, normal_decision, data_json, ledger_block, ledger_hash) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            sim_id,
            user_id,
            scenario["id"],
            scenario["name"],
            now,
            attack_result["risk_score"],
            attack_result["decision"],
            normal_result["risk_score"],
            normal_result["decision"],
            json.dumps(full_data),
            ledger_block["index"],
            ledger_block["hash"]
        )
    )

    return {
        "sim_id": sim_id,
        "is_simulation": True,
        "timestamp": now,
        "scenario": scenario,
        "normal": normal_result,
        "attack": attack_result,
        "normal_payload": normal_payload,
        "attack_payload": attack_payload,
        "audit_hash": tx_hash,
        "ledger_block": ledger_block,
        "ledger_status": ledger_status,
        "explanation": attack_result["explain"],
        "layers_triggered": [
            k for k, v in attack_result["layer_summary"].items()
            if v["status"] in ("INTERCEPTED", "FLAGGED")
        ]
    }


def get_history(account: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
    """Fetch previous simulations for the current user or admin."""
    user_id = account.get("user_id")
    is_admin = account.get("role") == "admin"
    
    if is_admin:
        rows = db.q("SELECT * FROM simulations ORDER BY ts DESC LIMIT ?", (limit,))
    else:
        rows = db.q("SELECT * FROM simulations WHERE user_id=? ORDER BY ts DESC LIMIT ?", (user_id, limit))

    out = []
    for r in rows:
        try:
            data = json.loads(r["data_json"])
        except Exception:
            data = {}
        out.append({
            "id": r["id"],
            "user_id": r["user_id"],
            "scenario_id": r["scenario_id"],
            "scenario_name": r["scenario_name"],
            "ts": r["ts"],
            "risk_score": r["risk_score"],
            "decision": r["decision"],
            "normal_score": r["normal_score"],
            "normal_decision": r["normal_decision"],
            "ledger_block": r["ledger_block"],
            "ledger_hash": r["ledger_hash"],
            "summary": data.get("attack", {}).get("reasons", [])[:2],
            "detail": data,
        })
    return out


def reset_history(account: Dict[str, Any]) -> Dict[str, Any]:
    """Reset simulation history."""
    user_id = account.get("user_id")
    is_admin = account.get("role") == "admin"
    
    if is_admin:
        count = len(db.q("SELECT id FROM simulations"))
        db.x("DELETE FROM simulations")
    else:
        count = len(db.q("SELECT id FROM simulations WHERE user_id=?", (user_id,)))
        db.x("DELETE FROM simulations WHERE user_id=?", (user_id,))

    audit.log(account.get("username", user_id or "user"), "reset_simulations", f"{count} records cleared")
    return {"reset": True, "deleted_count": count}
