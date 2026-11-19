"""Loads the trained scikit-learn model. If none is found, a transparent fallback formula is used
so the API still works (the response says model_loaded=false)."""
import math

import joblib

from . import config
from .features import FEATURES, to_vector

_cache = {"bundle": None, "tried": False}


def load():
    if not _cache["tried"]:
        _cache["tried"] = True
        try:
            _cache["bundle"] = joblib.load(config.MODEL_PATH)
        except Exception:
            _cache["bundle"] = None
    return _cache["bundle"]


def reload():
    _cache.update(bundle=None, tried=False)
    return load()


def _fallback(f):
    z = (-5.0 + 0.25 * min(f["amount_ratio"], 20) + 1.2 * f["new_receiver"] + 1.8 * f["new_device"]
         + 2.2 * f["sim_mismatch"] + 0.4 * f["txn_last_hour"] + 0.9 * f["is_night"]
         + 0.002 * f["distance_km"] + 1.5 * f["network_risk"] + 2.5 * f["qr_risk"]
         + 2.5 * f["url_risk"] + 0.5 * f["receiver_reports"])
    return 1 / (1 + math.exp(-z))


def predict(feat):
    """Returns (fraud_probability 0-1, model_loaded bool)."""
    b = load()
    if b is None:
        return _fallback(feat), False
    p = b["model"].predict_proba([to_vector(feat)])[0][1]
    return float(p), True


def info():
    b = load()
    if not b:
        return {"model_loaded": False}
    return {"model_loaded": True, "metrics": b.get("metrics"), "features": b.get("features", FEATURES)}


# ---- Explainable AI: "what pushed the score up?" (occlusion method) ----
_GROUPS = [
    ("Amount vs your average", ["amount_log", "amount_ratio"]),
    ("Time of day", ["hour", "is_night"]),
    ("New receiver", ["new_receiver"]),
    ("New device", ["new_device"]),
    ("SIM changed", ["sim_mismatch"]),
    ("Payments in last hour", ["txn_last_hour"]),
    ("Distance from home", ["distance_km"]),
    ("Network risk", ["network_risk"]),
    ("QR risk", ["qr_risk"]),
    ("Link risk", ["url_risk"]),
    ("Receiver reports", ["receiver_reports"]),
]


def proba_many(feats):
    b = load()
    if b is None:
        return [_fallback(f) for f in feats]
    return [float(p) for p in b["model"].predict_proba([to_vector(f) for f in feats])[:, 1]]


def explain(feat, amount, avg_amount):
    """For each feature group: reset it to a 'normal' value and see how far the fraud probability drops.
    A big drop = that signal was pushing the score up. Returns [{label, impact(0-100 points)}] sorted."""
    import math
    avg = max(float(avg_amount or 0), 100.0)
    normal = {"amount_log": math.log1p(avg), "amount_ratio": 1.0, "hour": 12, "is_night": 0, "new_receiver": 0,
              "new_device": 0, "sim_mismatch": 0, "txn_last_hour": 0, "distance_km": 0.0, "network_risk": 0.0,
              "qr_risk": 0.0, "url_risk": 0.0, "receiver_reports": 0}
    variants = []
    for _, keys in _GROUPS:
        f = dict(feat)
        for k in keys:
            f[k] = normal[k]
        variants.append(f)
    probs = proba_many([feat] + variants)
    base, rest = probs[0], probs[1:]
    out = [{"label": name, "impact": round(max(0.0, base - p) * 100, 1)} for (name, _), p in zip(_GROUPS, rest)]
    out = [o for o in out if o["impact"] >= 0.5]
    out.sort(key=lambda o: -o["impact"])
    return out[:6]
