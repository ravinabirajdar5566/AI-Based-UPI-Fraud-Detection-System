"""Everything a signed-in customer manages about their own security."""
import time

from . import audit, bus, config, db, notify
from .security import h


def trust_score(user_id):
    """0-100 'security health'. Starts at 100; recent trouble and weak setup lower it. Returns score + tips."""
    month = db.now() - 30 * 86400
    blocked = db.q("SELECT COUNT(*) AS c FROM transactions WHERE user_id=? AND decision='BLOCK' AND ts>?", (user_id, month))[0]["c"]
    verify = db.q("SELECT COUNT(*) AS c FROM transactions WHERE user_id=? AND decision='VERIFY' AND ts>?", (user_id, month))[0]["c"]
    devices = db.q("SELECT COUNT(*) AS c FROM devices WHERE user_id=? AND trusted=1", (user_id,))[0]["c"]
    u = db.q("SELECT daily_limit, frozen FROM users WHERE user_id=?", (user_id,))[0]
    score, tips = 100, []
    if blocked:
        score -= min(40, 8 * blocked)
        tips.append(f"{blocked} payment(s) were blocked this month - review them in History.")
    if verify:
        score -= min(20, 4 * verify)
    if devices > 3:
        score -= 10
        tips.append("You trust more than 3 devices. Remove the ones you no longer use.")
    if (u["daily_limit"] or 0) > 100000:
        score -= 10
        tips.append("Your daily limit is very high. A lower limit caps the damage if your phone is stolen.")
    if u["frozen"]:
        tips.append("Your account is frozen - no payments can leave it.")
    if not tips:
        tips.append("Everything looks healthy. Keep using only your trusted device.")
    return {"score": max(0, score), "tips": tips}


def overview(acc):
    uid = acc["user_id"]
    u = db.q("SELECT * FROM users WHERE user_id=?", (uid,))[0]
    day_start = (time.time() + 19800) // 86400 * 86400 - 19800
    spent = db.q("SELECT COALESCE(SUM(amount),0) AS s FROM transactions WHERE user_id=? AND ts>=? AND status IN ('COMPLETED','VERIFIED')",
                 (uid, day_start))[0]["s"]
    c = db.q("SELECT decision, COUNT(*) AS n FROM transactions WHERE user_id=? GROUP BY decision", (uid,))
    counts = {r["decision"]: r["n"] for r in c}
    saved = db.q("SELECT COALESCE(SUM(amount),0) AS s FROM transactions WHERE user_id=? AND decision='BLOCK'", (uid,))[0]["s"]
    return {"profile": {"name": u["name"], "user_id": uid, "bank": u["bank_masked"], "avg_amount": round(u["avg_amount"], 2),
                        "daily_limit": u["daily_limit"], "frozen": bool(u["frozen"]), "txn_count": u["txn_count"]},
            "spent_today": spent, "counts": counts, "protected": saved, "trust": trust_score(uid),
            "unread": notify.unread(uid)}


def devices(uid):
    return db.q("SELECT id,label,trusted,created_at FROM devices WHERE user_id=? ORDER BY id", (uid,))


def revoke_device(acc, dev_id):
    rows = db.q("SELECT * FROM devices WHERE id=? AND user_id=?", (dev_id, acc["user_id"]))
    if not rows:
        raise ValueError("unknown device")
    if db.q("SELECT COUNT(*) AS c FROM devices WHERE user_id=? AND trusted=1", (acc["user_id"],))[0]["c"] <= 1 and rows[0]["trusted"]:
        raise ValueError("Keep at least one trusted device")
    db.x("UPDATE devices SET trusted=0 WHERE id=?", (dev_id,))
    audit.log(acc["username"], "device_revoked", rows[0]["label"])
    notify.add(acc["user_id"], "warn", "Device removed", f"{rows[0]['label']} is no longer trusted.")


def set_freeze(acc, frozen):
    db.x("UPDATE users SET frozen=? WHERE user_id=?", (1 if frozen else 0, acc["user_id"]))
    audit.log(acc["username"], "self_freeze" if frozen else "self_unfreeze", acc["user_id"])
    notify.add(acc["user_id"], "bad" if frozen else "ok", "Panic freeze ON" if frozen else "Freeze lifted",
               "No payment can leave your account." if frozen else "Payments are working again.")
    bus.publish({"type": "admin", "what": "freeze"})


def set_limit(acc, limit):
    if not 100 <= limit <= 1_000_000:
        raise ValueError("Daily limit must be between Rs 100 and Rs 10,00,000")
    db.x("UPDATE users SET daily_limit=? WHERE user_id=?", (limit, acc["user_id"]))
    audit.log(acc["username"], "limit_changed", acc["user_id"], limit)
