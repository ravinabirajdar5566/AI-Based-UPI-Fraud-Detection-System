"""Administrator tools: live statistics, user control, review queue, blacklist, thresholds, retraining."""
import json
import subprocess
import sys
import threading
import time

from . import audit, blockchain, bus, config, db, lists, model_service, notify, service
from .security import h

SETTING_KEYS = {"thresh_verify": ("THRESH_VERIFY", float), "thresh_block": ("THRESH_BLOCK", float),
                "high_amount": ("HIGH_AMOUNT", float)}


# ---------- settings (persist in DB, apply live) ----------
def load_settings():
    for r in db.q("SELECT key,value FROM settings"):
        if r["key"] in SETTING_KEYS:
            attr, cast = SETTING_KEYS[r["key"]]
            setattr(config, attr, cast(r["value"]))


def get_settings():
    return {"thresh_verify": config.THRESH_VERIFY, "thresh_block": config.THRESH_BLOCK, "high_amount": config.HIGH_AMOUNT}


def set_settings(actor, data):
    new = {**get_settings(), **{k: float(v) for k, v in data.items() if k in SETTING_KEYS and v is not None}}
    if not (5 <= new["thresh_verify"] < new["thresh_block"] <= 100):
        raise ValueError("Thresholds must satisfy 5 <= verify < block <= 100")
    if new["high_amount"] < 1000:
        raise ValueError("High-amount rule must be at least Rs 1,000")
    for k, v in new.items():
        db.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
        setattr(config, SETTING_KEYS[k][0], v)
    audit.log(actor, "settings_changed", "", json.dumps(new))
    bus.publish({"type": "admin", "what": "settings"})
    return get_settings()


# ---------- statistics ----------
def stats():
    t = db.q("SELECT decision, COUNT(*) AS c, COALESCE(SUM(amount),0) AS amt FROM transactions GROUP BY decision")
    by = {r["decision"]: r for r in t}
    total = sum(r["c"] for r in t)
    detected_frauds = db.q("SELECT COUNT(*) AS c FROM transactions WHERE decision!='ALLOW' OR review='fraud'")[0]["c"]
    qr_scans_cnt = db.q("SELECT COUNT(*) AS c FROM qr_scans")[0]["c"]
    fraud_rate = round((detected_frauds / total * 100), 2) if total else 0.0
    now = db.now()
    since = now - 24 * 3600
    hours = [{"h": i, "ALLOW": 0, "VERIFY": 0, "BLOCK": 0} for i in range(24)]
    for r in db.q("SELECT ts, decision FROM transactions WHERE ts>?", (since,)):
        slot = int((r["ts"] - since) // 3600)
        if 0 <= slot < 24:
            hours[slot][r["decision"]] += 1
    top = db.q("SELECT vpa, COUNT(*) AS n, ROUND(AVG(risk_score),1) AS avg_risk FROM transactions "
               "WHERE decision!='ALLOW' GROUP BY vpa ORDER BY n DESC, avg_risk DESC LIMIT 5")
    avg = db.q("SELECT COALESCE(AVG(risk_score),0) AS a FROM transactions")[0]["a"]
    ledger = blockchain.verify_chain()
    return {
        "total": total,
        "total_transactions": total,
        "detected_frauds": detected_frauds,
        "blocked_transactions": by.get("BLOCK", {}).get("c", 0),
        "qr_scans": qr_scans_cnt,
        "fraud_detection_rate": fraud_rate,
        "allowed": by.get("ALLOW", {}).get("c", 0), "verify": by.get("VERIFY", {}).get("c", 0),
        "blocked": by.get("BLOCK", {}).get("c", 0),
        "money_protected": round(by.get("BLOCK", {}).get("amt", 0), 2),
        "money_flowing": round(by.get("ALLOW", {}).get("amt", 0), 2),
        "avg_risk": round(avg, 1),
        "users": db.q("SELECT COUNT(*) AS c FROM accounts WHERE role='user'")[0]["c"],
        "frozen": db.q("SELECT COUNT(*) AS c FROM users WHERE frozen=1")[0]["c"],
        "queue": db.q("SELECT COUNT(*) AS c FROM transactions WHERE decision!='ALLOW' AND review IS NULL")[0]["c"],
        "blacklist": len(lists.blacklist()["vpas"]) + db.q("SELECT COUNT(*) AS c FROM blacklist")[0]["c"],
        "hours": hours, "top_receivers": top, "ledger": ledger, "live_viewers": bus.listeners(),
        "feed": [e for e in bus.recent() if e.get("type") == "tx"][-25:],
    }


# ---------- users ----------
def users():
    rows = db.q("""SELECT a.id, a.username, a.email, a.name, a.role, a.user_id, a.created_at, a.last_login,
                          a.disabled, a.locked_until, u.frozen, u.daily_limit, u.txn_count, u.avg_amount,
                          (SELECT COUNT(*) FROM transactions t WHERE t.user_id=a.user_id AND t.decision='BLOCK') AS blocked,
                          (SELECT COUNT(*) FROM devices d WHERE d.user_id=a.user_id AND d.trusted=1) AS devices
                   FROM accounts a LEFT JOIN users u ON u.user_id=a.user_id ORDER BY a.id""")
    for r in rows:
        r["locked"] = r.pop("locked_until") > time.time()
        r["is_active"] = not r.get("disabled", 0)
    return rows


def _acc(account_id):
    rows = db.q("SELECT * FROM accounts WHERE id=?", (account_id,))
    if not rows:
        raise ValueError("unknown account")
    return rows[0]


def set_freeze(actor, account_id, frozen):
    a = _acc(account_id)
    if not a["user_id"]:
        raise ValueError("Admin accounts have no payment profile")
    db.x("UPDATE users SET frozen=? WHERE user_id=?", (1 if frozen else 0, a["user_id"]))
    audit.log(actor["username"], "freeze" if frozen else "unfreeze", a["username"])
    notify.add(a["user_id"], "bad" if frozen else "ok", "Account frozen by administrator" if frozen else "Account unfrozen",
               "All payments are blocked until it is unfrozen." if frozen else "Payments are working again.")


def set_account_status(actor, account_id, active: bool):
    a = _acc(account_id)
    if a["id"] == actor["id"]:
        raise ValueError("You cannot change your own account status")
    disabled = 0 if active else 1
    db.x("UPDATE accounts SET disabled=? WHERE id=?", (disabled, a["id"]))
    audit.log(actor["username"], "user_activated" if active else "user_deactivated", a["username"])
    bus.publish({"type": "admin", "what": "users"})
    return {"id": a["id"], "username": a["username"], "active": bool(active), "disabled": disabled}


def set_disabled(actor, account_id, disabled):
    return set_account_status(actor, account_id, not disabled)


def set_role(actor, account_id, role):
    a = _acc(account_id)
    if role not in ("user", "admin"):
        raise ValueError("role must be user or admin")
    if a["id"] == actor["id"]:
        raise ValueError("You cannot change your own role")
    db.x("UPDATE accounts SET role=? WHERE id=?", (role, a["id"]))
    audit.log(actor["username"], "role_change", a["username"], role)


def unlock(actor, account_id):
    a = _acc(account_id)
    db.x("UPDATE accounts SET failed=0, locked_until=0 WHERE id=?", (a["id"],))
    audit.log(actor["username"], "unlock", a["username"])


# ---------- transactions / review queue ----------
def transactions(decision=None, only_open=False, limit=100, offset=0, search=None, status=None, min_risk=None, max_risk=None):
    sql, args = "SELECT t.*, u.name AS uname FROM transactions t LEFT JOIN users u ON u.user_id=t.user_id WHERE 1=1", []
    if decision:
        sql += " AND t.decision=?"
        args.append(decision)
    if status:
        sql += " AND t.status=?"
        args.append(status)
    if only_open:
        sql += " AND t.decision!='ALLOW' AND t.review IS NULL"
    if min_risk is not None:
        sql += " AND t.risk_score >= ?"
        args.append(float(min_risk))
    if max_risk is not None:
        sql += " AND t.risk_score <= ?"
        args.append(float(max_risk))
    if search and str(search).strip():
        s = f"%{str(search).strip().lower()}%"
        sql += " AND (LOWER(t.tx_id) LIKE ? OR LOWER(t.vpa) LIKE ? OR LOWER(t.user_id) LIKE ? OR LOWER(COALESCE(u.name, '')) LIKE ?)"
        args.extend([s, s, s, s])
    sql += " ORDER BY t.ts DESC LIMIT ? OFFSET ?"
    args.extend([int(limit), int(offset)])
    rows = db.q(sql, tuple(args))
    for r in rows:
        r.pop("features", None)
        r["reasons"] = json.loads(r["reasons"]) if r.get("reasons") else []
        r["explain"] = json.loads(r["explain"]) if r.get("explain") else []
    return rows


def alerts(status_filter=None, severity_filter=None, limit=100):
    """Retrieve suspicious transactions formatted as fraud alerts with severity."""
    sql = "SELECT t.*, u.name AS uname FROM transactions t LEFT JOIN users u ON u.user_id=t.user_id WHERE (t.decision!='ALLOW' OR t.risk_score >= ?)"
    args = [config.THRESH_VERIFY]
    if status_filter == "open":
        sql += " AND t.review IS NULL"
    elif status_filter == "reviewed":
        sql += " AND t.review IS NOT NULL"
    sql += " ORDER BY t.ts DESC LIMIT ?"
    args.append(int(limit))
    rows = db.q(sql, tuple(args))
    out = []
    for r in rows:
        r.pop("features", None)
        reasons = json.loads(r["reasons"]) if r.get("reasons") else []
        explain = json.loads(r["explain"]) if r.get("explain") else []
        max_sev = max([(rs.get("severity") or 0.5) for rs in reasons], default=0.5) if reasons else 0.5
        score = float(r.get("risk_score") or 0.0)
        dec = r.get("decision")
        if dec == "BLOCK" or score >= config.THRESH_BLOCK or max_sev >= 0.7:
            sev = "HIGH"
        elif dec == "VERIFY" or score >= config.THRESH_VERIFY or max_sev >= 0.4:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        if severity_filter and severity_filter.upper() != "ALL" and sev != severity_filter.upper():
            continue
        r["reasons"] = reasons
        r["explain"] = explain
        r["severity"] = sev
        r["reviewed"] = r.get("review") is not None
        out.append(r)
    return out


def review(actor, tx_id, verdict):
    """Analyst decision. 'fraud' -> label 1 + a report on the receiver; 'legit' -> label 0;
    'reviewed' -> marks alert as reviewed without training label bias.
    Feeds the next model retraining (human-in-the-loop)."""
    rows = db.q("SELECT * FROM transactions WHERE tx_id=?", (tx_id,))
    if not rows:
        raise ValueError("unknown transaction")
    tx = rows[0]
    verdict = str(verdict or "").lower().strip()
    if verdict not in ("fraud", "legit", "reviewed"):
        raise ValueError("verdict must be fraud, legit, or reviewed")
    lbl = 1 if verdict == "fraud" else (0 if verdict == "legit" else None)
    if lbl is not None:
        db.x("UPDATE transactions SET review=?, label=? WHERE tx_id=?", (verdict, lbl, tx_id))
    else:
        db.x("UPDATE transactions SET review=? WHERE tx_id=?", (verdict, tx_id))
    if verdict == "fraud":
        db.x("INSERT INTO reports(vpa,user_id,reason,ts) VALUES(?,?,?,?)",
             (tx["vpa"], "ADMIN", "confirmed by analyst", db.now()))
    block_status = "ADMIN_CONFIRMED_FRAUD" if verdict == "fraud" else ("ADMIN_MARKED_LEGIT" if verdict == "legit" else "ADMIN_ALERT_REVIEWED")
    blockchain.add_block(service._tx_hash(tx_id, tx["user_id"], tx["vpa"], tx["amount"], tx["ts"]),
                         tx["risk_score"], block_status)
    audit.log(actor["username"], "review_" + verdict, tx_id, tx["vpa"])
    notify_body = "Marked as genuine." if verdict == "legit" else ("Confirmed as fraud. The receiver is now flagged." if verdict == "fraud" else "Alert marked as reviewed by analyst.")
    notify.add(tx["user_id"], "bad" if verdict == "fraud" else "ok",
               f"Analyst reviewed {tx_id}", notify_body)
    bus.publish({"type": "admin", "what": "review"})
    return {"tx_id": tx_id, "review": verdict}


def verify_ledger(actor):
    """Cryptographically verify the blockchain ledger and log to audit."""
    res = blockchain.verify_chain()
    actor_name = actor["username"] if isinstance(actor, dict) else str(actor)
    audit.log(actor_name, "ledger_verification", f"blocks={res['length']}", f"valid={res['valid']}; reason={res.get('reason')}")
    bus.publish({"type": "admin", "what": "ledger"})
    return {**res, "verified_at": db.now()}


def ai_monitoring():
    """Retrieve exact model metrics (from metrics.json) and prediction statistics (from database)."""
    minfo = model_service.info()
    metrics_data = minfo.get("metrics") or {}
    results = metrics_data.get("results") or []
    used_model = next((m for m in results if "used" in m.get("model", "").lower()), results[1] if len(results) > 1 else (results[0] if results else None))
    baseline_model = next((m for m in results if "baseline" in m.get("model", "").lower()), results[0] if results else None)

    total_preds = db.q("SELECT COUNT(*) AS c FROM transactions")[0]["c"]
    by_dec = {r["decision"]: r["c"] for r in db.q("SELECT decision, COUNT(*) AS c FROM transactions GROUP BY decision")}
    avg_score = db.q("SELECT COALESCE(AVG(risk_score), 0) AS a FROM transactions")[0]["a"]
    min_score = db.q("SELECT COALESCE(MIN(risk_score), 0) AS m FROM transactions")[0]["m"] if total_preds else 0.0
    max_score = db.q("SELECT COALESCE(MAX(risk_score), 0) AS m FROM transactions")[0]["m"] if total_preds else 0.0
    feedback = db.q("SELECT COUNT(*) AS c FROM transactions WHERE label IS NOT NULL")[0]["c"]
    rev_fraud = db.q("SELECT COUNT(*) AS c FROM transactions WHERE review='fraud'")[0]["c"]
    rev_legit = db.q("SELECT COUNT(*) AS c FROM transactions WHERE review='legit'")[0]["c"]
    detected = db.q("SELECT COUNT(*) AS c FROM transactions WHERE decision!='ALLOW' OR review='fraud'")[0]["c"]

    low_count = db.q("SELECT COUNT(*) AS c FROM transactions WHERE risk_score < ?", (config.THRESH_VERIFY,))[0]["c"]
    med_count = db.q("SELECT COUNT(*) AS c FROM transactions WHERE risk_score >= ? AND risk_score < ?", (config.THRESH_VERIFY, config.THRESH_BLOCK))[0]["c"]
    high_count = db.q("SELECT COUNT(*) AS c FROM transactions WHERE risk_score >= ?", (config.THRESH_BLOCK,))[0]["c"]

    return {
        "model_loaded": minfo.get("model_loaded", False),
        "model_used": used_model,
        "model_baseline": baseline_model,
        "feature_importance": metrics_data.get("feature_importance", {}),
        "dataset_rows": metrics_data.get("rows", 60000),
        "training_fraud_rate": metrics_data.get("fraud_rate", 0.0491),
        "prediction_statistics": {
            "total_predictions": total_preds,
            "allowed_count": by_dec.get("ALLOW", 0),
            "verify_count": by_dec.get("VERIFY", 0),
            "blocked_count": by_dec.get("BLOCK", 0),
            "detected_frauds": detected,
            "detection_rate": round((detected / total_preds * 100), 2) if total_preds else 0.0,
            "average_risk_score": round(avg_score, 2),
            "min_risk_score": round(min_score, 2),
            "max_risk_score": round(max_score, 2),
            "distribution": {
                "low": low_count,
                "medium": med_count,
                "high": high_count
            },
            "feedback_rows": feedback,
            "analyst_confirmed_fraud": rev_fraud,
            "analyst_marked_legit": rev_legit
        },
        "training": dict(_train),
        "thresholds": {"verify": config.THRESH_VERIFY, "block": config.THRESH_BLOCK}
    }


def audit_logs(search=None, action=None, limit=150):
    sql = "SELECT * FROM audit WHERE 1=1"
    args = []
    if action and str(action).strip():
        sql += " AND action LIKE ?"
        args.append(f"%{str(action).strip()}%")
    if search and str(search).strip():
        s = f"%{str(search).strip().lower()}%"
        sql += " AND (LOWER(actor) LIKE ? OR LOWER(action) LIKE ? OR LOWER(target) LIKE ? OR LOWER(detail) LIKE ?)"
        args.extend([s, s, s, s])
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    return db.q(sql, tuple(args))


# ---------- blacklist ----------
def blacklist_list():
    static = [{"vpa": v, "reason": "built-in list", "added_by": "system", "ts": None, "builtin": True}
              for v in lists.blacklist()["vpas"]]
    return db.q("SELECT *, 0 AS builtin FROM blacklist ORDER BY ts DESC") + static


def blacklist_add(actor, vpa, reason):
    vpa = (vpa or "").strip().lower()
    if "@" not in vpa or len(vpa) < 5:
        raise ValueError("Enter a UPI ID such as name@bank")
    db.x("INSERT OR REPLACE INTO blacklist(vpa,reason,added_by,ts) VALUES(?,?,?,?)",
         (vpa, reason or "added by admin", actor["username"], db.now()))
    audit.log(actor["username"], "blacklist_add", vpa, reason)
    bus.publish({"type": "admin", "what": "blacklist"})


def blacklist_remove(actor, vpa):
    vpa = vpa.lower()
    if vpa in {x.lower() for x in lists.blacklist()["vpas"]}:
        raise ValueError("Built-in entries cannot be removed")
    db.x("DELETE FROM blacklist WHERE vpa=?", (vpa,))
    db.x("DELETE FROM reports WHERE vpa=?", (vpa,))  # also clears crowd-sourced auto-blacklist
    audit.log(actor["username"], "blacklist_remove", vpa)


# ---------- model ----------
_train = {"running": False, "last": None, "message": "idle"}


def retrain(actor):
    if _train["running"]:
        raise ValueError("Training is already running")
    root = config.BASE_DIR.parent
    labelled = db.q("SELECT COUNT(*) AS c FROM transactions WHERE label IS NOT NULL")[0]["c"]

    def work():
        _train.update(running=True, message=f"training with {labelled} feedback rows...")
        try:
            r = subprocess.run([sys.executable, str(root / "ml" / "train.py"), "--with-feedback"], cwd=str(root),
                               capture_output=True, text=True, timeout=600,
                               env={**__import__("os").environ, "UPI_DB": str(config.DB_PATH)})
            if r.returncode == 0:
                model_service.reload()
                _train.update(message="finished - new model is live", last=time.time())
            else:
                _train.update(message="training failed: " + (r.stderr or r.stdout)[-200:])
        except Exception as e:  # noqa: BLE001
            _train.update(message=f"training failed: {e}")
        finally:
            _train["running"] = False
            bus.publish({"type": "admin", "what": "model"})

    audit.log(actor["username"], "retrain", "", f"{labelled} labelled rows")
    threading.Thread(target=work, daemon=True).start()
    return {"started": True, "feedback_rows": labelled}


def model_status():
    return {**model_service.info(), "training": dict(_train),
            "feedback_rows": db.q("SELECT COUNT(*) AS c FROM transactions WHERE label IS NOT NULL")[0]["c"]}
