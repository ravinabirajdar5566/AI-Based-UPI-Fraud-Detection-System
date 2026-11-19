"""Combines every layer into ONE fraud-risk score (0-100) and a decision.

final = 1 - (1 - 0.9*ML) * (1 - 0.8*LAYERS) * (1 - 0.7*RULES)      (a "noisy-OR": any strong signal lifts the score)

 ML      fraud probability from the trained model (behavioural pattern)
 LAYERS  0.7*max + 0.3*mean of the active layers: device/SIM, QR, link, network
 RULES   behaviour rule points / 100 (new receiver, odd amount, night, burst, distance, reports)

Then hard overrides can only RAISE the score (e.g. blacklisted receiver -> 100).
"""
from . import config


def behavior_rules(f, amount):
    pts, reasons = 0, []
    if f["new_receiver"]:
        pts += 15
        reasons.append("New receiver - you have never paid this UPI ID before")
    r = f["amount_ratio"]
    if r >= 10:
        pts += 35
        reasons.append(f"Amount is {r:.1f}x your usual average")
    elif r >= 5:
        pts += 25
        reasons.append(f"Amount is {r:.1f}x your usual average")
    elif r >= 3:
        pts += 12
        reasons.append(f"Amount is {r:.1f}x your usual average")
    if f["is_night"] and r >= 2:
        pts += 10
        reasons.append("Unusual late-night payment")
    if f["txn_last_hour"] >= 4:
        pts += 25
        reasons.append(f"{f['txn_last_hour']} payments in the last hour (rapid burst)")
    elif f["txn_last_hour"] >= 3:
        pts += 10
        reasons.append("Several payments in the last hour")
    if f["distance_km"] >= 500:
        pts += 15
        reasons.append(f"Payment location is {f['distance_km']:.0f} km from your usual location")
    if amount >= config.HIGH_AMOUNT:
        pts += 10
        reasons.append(f"High-value payment (Rs {amount:,.0f})")
    if f["receiver_reports"] >= 1:
        pts += min(30, 10 * f["receiver_reports"])
        reasons.append(f"Receiver has been reported for fraud {f['receiver_reports']} time(s)")
    return min(100, pts), reasons


def decide(ml_prob, layers, feat, amount, flags):
    """layers: {name: {risk, reasons, present(bool)}}; flags: dict of booleans for hard overrides."""
    active = [v["risk"] for v in layers.values() if v.get("present", True)]
    layer_max = max(active) if active else 0.0
    layer_mean = sum(active) / len(active) if active else 0.0
    layer_score = 0.7 * layer_max + 0.3 * layer_mean
    rule_pts, rule_reasons = behavior_rules(feat, amount)

    final = 1 - (1 - 0.9 * ml_prob) * (1 - 0.8 * layer_score) * (1 - 0.7 * rule_pts / 100)
    final *= 100

    overrides = []

    def floor(value, why):
        nonlocal final
        overrides.append(why)
        final = max(final, value)

    if flags.get("account_frozen"):
        floor(100, "Your account is frozen - unfreeze it in Security to pay")
    if flags.get("limit_exceeded"):
        floor(config.THRESH_BLOCK, "Daily spending limit would be exceeded")
    if flags.get("receiver_blacklisted"):
        floor(100, "Receiver UPI ID is blacklisted")
    if not flags.get("user_found", True) or not flags.get("phone_match", True):
        floor(100, "Identity check failed (user / mobile number)")
    if flags.get("sim_swap"):
        floor(75, "SIM changed on a trusted device")
    if flags.get("new_device") and amount >= config.HIGH_AMOUNT:
        floor(75, "High-value payment from a new device")
    elif flags.get("new_device"):
        floor(40, "New device always needs extra verification")
    if feat["url_risk"] >= 0.8:
        floor(90, "Malicious payment link")
    if feat["qr_risk"] >= 0.9:
        floor(90, "Fake / tampered QR")
    if layers["network"]["risk"] >= 0.9:
        floor(85, "Network is on a malicious-IP list")
    if amount >= 2 * config.HIGH_AMOUNT and feat["new_receiver"]:
        floor(40, "Very high amount to a new receiver")

    final = round(min(100.0, max(0.0, final)), 1)
    if final >= config.THRESH_BLOCK:
        decision, color = "BLOCK", "red"
    elif final >= config.THRESH_VERIFY:
        decision, color = "VERIFY", "yellow"
    else:
        decision, color = "ALLOW", "green"

    reasons = []
    for name, v in layers.items():
        if v.get("present", True) and v["risk"] > 0.2:
            for t in v["reasons"]:
                reasons.append({"layer": name, "text": t, "severity": v["risk"]})
    for t in rule_reasons:
        reasons.append({"layer": "behavior", "text": t, "severity": 0.5})
    for t in overrides:
        reasons.append({"layer": "rule", "text": t, "severity": 1.0})
    reasons.sort(key=lambda r: -r["severity"])

    return {
        "risk_score": final, "decision": decision, "color": color, "reasons": reasons,
        "breakdown": {"ml_probability": round(ml_prob, 4), "layer_score": round(layer_score * 100, 1),
                      "rule_points": rule_pts, "overrides": overrides},
    }
