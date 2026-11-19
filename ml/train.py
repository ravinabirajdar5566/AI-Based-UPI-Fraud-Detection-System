"""Train the fraud model.

  python ml/train.py                       # generates synthetic data if needed, trains, saves backend/models/model.pkl
  python ml/train.py --data my.csv         # your own CSV (columns = FEATURES + is_fraud)
  python ml/train.py --with-feedback       # also use labelled transactions from the app database (feedback loop)

Fraud is rare, so we use class_weight='balanced_subsample' and judge with precision / recall / F1 / PR-AUC,
NOT accuracy (a model that always says "safe" is ~96% accurate and useless).
"""
import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "ml"))
from app.features import FEATURES  # noqa: E402
import generate_data  # noqa: E402


def feedback_rows():
    from app import db
    rows = db.q("SELECT features,label FROM transactions WHERE label IS NOT NULL")
    recs = []
    for r in rows:
        d = json.loads(r["features"])
        d["is_fraud"] = r["label"]
        recs.append(d)
    return pd.DataFrame(recs, columns=FEATURES + ["is_fraud"]) if recs else pd.DataFrame(columns=FEATURES + ["is_fraud"])


def evaluate(name, model, X, y):
    p = model.predict_proba(X)[:, 1]
    pred = (p >= 0.5).astype(int)
    m = {
        "model": name,
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred), 4),
        "f1": round(f1_score(y, pred), 4),
        "roc_auc": round(roc_auc_score(y, p), 4),
        "pr_auc": round(average_precision_score(y, p), 4),
        "confusion_matrix [[TN,FP],[FN,TP]]": confusion_matrix(y, pred).tolist(),
    }
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data")
    ap.add_argument("--rows", type=int, default=60000)
    ap.add_argument("--with-feedback", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "backend" / "models" / "model.pkl"))
    a = ap.parse_args()

    df = pd.read_csv(a.data) if a.data else generate_data.make(a.rows)
    if a.with_feedback:
        fb = feedback_rows()
        print(f"feedback rows added: {len(fb)}")
        if len(fb):
            df = pd.concat([df, fb], ignore_index=True)
    # concat with an empty / object-typed frame can turn columns into 'object'; force numeric types
    df[FEATURES] = df[FEATURES].astype(float)
    df["is_fraud"] = df["is_fraud"].astype(int)
    X, y = df[FEATURES].values, df["is_fraud"].values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=7)
    print(f"train={len(Xtr)} test={len(Xte)} fraud rate={y.mean():.2%}")

    lr = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=1000)).fit(Xtr, ytr)
    rf = RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_leaf=3, n_jobs=-1,
                                class_weight="balanced_subsample", random_state=7).fit(Xtr, ytr)

    results = [evaluate("LogisticRegression (baseline)", lr, Xte, yte), evaluate("RandomForest (used)", rf, Xte, yte)]
    for r in results:
        print(json.dumps(r, indent=2))

    imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda t: -t[1])
    print("\nTop features:")
    for k, v in imp[:8]:
        print(f"  {k:18s} {v:.3f}")

    metrics = {"results": results, "feature_importance": {k: round(float(v), 4) for k, v in imp},
               "rows": int(len(df)), "fraud_rate": round(float(y.mean()), 4)}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": rf, "features": FEATURES, "metrics": metrics}, a.out)
    (Path(a.out).parent / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nsaved model -> {a.out}")


if __name__ == "__main__":
    main()
