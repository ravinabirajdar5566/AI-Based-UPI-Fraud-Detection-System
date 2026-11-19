"""Feature vector shared by training (ml/) and live scoring."""
import math

FEATURES = [
    "amount_log", "amount_ratio", "hour", "is_night", "new_receiver", "new_device", "sim_mismatch",
    "txn_last_hour", "distance_km", "network_risk", "qr_risk", "url_risk", "receiver_reports",
]


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def build_features(amount, avg_amount, hour, new_receiver, new_device, sim_mismatch, txn_last_hour,
                   distance_km, network_risk, qr_risk, url_risk, receiver_reports):
    avg = max(float(avg_amount or 0), 100.0)
    return {
        "amount_log": math.log1p(max(float(amount), 0.0)),
        "amount_ratio": min(float(amount) / avg, 50.0),
        "hour": int(hour),
        "is_night": 1 if (hour >= 23 or hour <= 4) else 0,
        "new_receiver": int(bool(new_receiver)),
        "new_device": int(bool(new_device)),
        "sim_mismatch": int(bool(sim_mismatch)),
        "txn_last_hour": int(txn_last_hour),
        "distance_km": min(float(distance_km), 5000.0),
        "network_risk": float(network_risk),
        "qr_risk": float(qr_risk),
        "url_risk": float(url_risk),
        "receiver_reports": min(int(receiver_reports), 20),
    }


def to_vector(feat):
    return [feat[k] for k in FEATURES]
