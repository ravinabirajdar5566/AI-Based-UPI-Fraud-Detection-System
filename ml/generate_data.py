"""Creates a SYNTHETIC UPI-style fraud dataset with the same features used at runtime.

Why synthetic? Real UPI data is private. This generator mixes normal behaviour with three fraud
patterns (account takeover, scam payment, mule burst). To use real/public data (PaySim, Kaggle),
convert it to the columns in app/features.py FEATURES + 'is_fraud' and pass it to train.py --data.

Run:  python ml/generate_data.py            (writes ml/data/upi_synthetic.csv)
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from app.features import FEATURES  # noqa: E402


def make(n=60000, fraud_rate=0.04, seed=42):
    rng = np.random.default_rng(seed)
    n_f = int(n * fraud_rate)
    n_l = n - n_f

    # ---------- legitimate ----------
    avg = rng.lognormal(7.0, 0.7, n_l)                       # each user's usual amount
    amount = avg * rng.lognormal(0, 0.6, n_l)
    hour = np.clip(rng.normal(14, 5, n_l), 0, 23).astype(int)
    legit = pd.DataFrame({
        "amount": amount, "avg": avg, "hour": hour,
        "new_receiver": rng.random(n_l) < 0.15,
        "new_device": rng.random(n_l) < 0.02,
        "sim_mismatch": rng.random(n_l) < 0.004,
        "txn_last_hour": rng.poisson(0.3, n_l),
        "distance_km": np.where(rng.random(n_l) < 0.05, rng.uniform(100, 1500, n_l), rng.exponential(6, n_l)),
        "network_risk": rng.choice([0, 0.05, 0.1, 0.3, 0.5, 0.8], n_l, p=[.5, .25, .08, .1, .06, .01]),
        "qr_risk": np.where(rng.random(n_l) < 0.04, rng.uniform(0.2, 0.6, n_l), 0),
        "url_risk": np.where(rng.random(n_l) < 0.01, rng.uniform(0.2, 0.5, n_l), 0),
        "receiver_reports": rng.poisson(0.03, n_l),
        "is_fraud": 0,
    })
    # hard negatives: legit payments that look a bit odd
    odd = rng.random(n_l) < 0.06
    legit.loc[odd, "amount"] *= rng.uniform(3, 8, odd.sum())
    legit.loc[odd, "hour"] = rng.choice([0, 1, 2, 23], odd.sum())

    # ---------- fraud ----------
    kind = rng.choice(3, n_f, p=[.35, .40, .25])
    f = pd.DataFrame({
        "amount": 0.0, "avg": rng.lognormal(7.0, 0.7, n_f), "hour": rng.integers(0, 24, n_f),
        "new_receiver": True, "new_device": False, "sim_mismatch": False, "txn_last_hour": rng.poisson(0.5, n_f),
        "distance_km": rng.exponential(10, n_f), "network_risk": rng.choice([0, 0.05, 0.3, 0.5], n_f),
        "qr_risk": 0.0, "url_risk": 0.0, "receiver_reports": rng.poisson(0.3, n_f), "is_fraud": 1,
    })
    f["amount"] = f["avg"] * rng.lognormal(1.2, 0.8, n_f)
    t = kind == 0  # account takeover
    f.loc[t, "new_device"] = rng.random(t.sum()) < 0.85
    f.loc[t, "sim_mismatch"] = rng.random(t.sum()) < 0.35
    f.loc[t, "amount"] = f.loc[t, "avg"] * rng.uniform(3, 25, t.sum())
    f.loc[t, "hour"] = rng.choice([0, 1, 2, 3, 4, 23, 12, 15], t.sum())
    f.loc[t, "distance_km"] = rng.uniform(50, 2500, t.sum())
    f.loc[t, "network_risk"] = rng.choice([0.3, 0.5, 0.8, 0.95], t.sum())
    s = kind == 1  # scam payment (fake QR / phishing link)
    f.loc[s, "qr_risk"] = np.where(rng.random(s.sum()) < 0.6, rng.uniform(0.6, 1.0, s.sum()), 0)
    f.loc[s, "url_risk"] = np.where(rng.random(s.sum()) < 0.5, rng.uniform(0.5, 1.0, s.sum()), 0)
    f.loc[s, "amount"] = f.loc[s, "avg"] * rng.uniform(1, 12, s.sum())
    f.loc[s, "receiver_reports"] = rng.poisson(1.5, s.sum())
    m = kind == 2  # mule / burst
    f.loc[m, "txn_last_hour"] = rng.integers(3, 12, m.sum())
    f.loc[m, "receiver_reports"] = rng.integers(1, 10, m.sum())
    f.loc[m, "amount"] = f.loc[m, "avg"] * rng.uniform(1.5, 8, m.sum())

    df = pd.concat([legit, f], ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)
    flip = rng.random(len(df)) < 0.01  # 1% label noise (real data is never clean)
    df.loc[flip, "is_fraud"] = 1 - df.loc[flip, "is_fraud"]

    out = pd.DataFrame({
        "amount_log": np.log1p(df["amount"]),
        "amount_ratio": np.minimum(df["amount"] / np.maximum(df["avg"], 100), 50),
        "hour": df["hour"].astype(int),
        "is_night": ((df["hour"] >= 23) | (df["hour"] <= 4)).astype(int),
        "new_receiver": df["new_receiver"].astype(int),
        "new_device": df["new_device"].astype(int),
        "sim_mismatch": df["sim_mismatch"].astype(int),
        "txn_last_hour": df["txn_last_hour"].astype(int),
        "distance_km": np.minimum(df["distance_km"], 5000),
        "network_risk": df["network_risk"],
        "qr_risk": df["qr_risk"],
        "url_risk": df["url_risk"],
        "receiver_reports": np.minimum(df["receiver_reports"], 20).astype(int),
        "is_fraud": df["is_fraud"].astype(int),
    })
    return out[FEATURES + ["is_fraud"]]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=60000)
    ap.add_argument("--out", default=str(ROOT / "ml" / "data" / "upi_synthetic.csv"))
    a = ap.parse_args()
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    d = make(a.rows)
    d.to_csv(a.out, index=False)
    print(f"wrote {len(d)} rows -> {a.out}   fraud rate = {d['is_fraud'].mean():.2%}")
