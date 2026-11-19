"""Layer 1: identity + device + SIM binding.

A payment is trusted only if registered phone number, device and SIM all match.
In a real system the SIM check is done by the bank/NPCI via silent SMS; here we simulate it
with a SIM identifier sent by the client app.
"""
from . import db
from .security import h, safe_eq


def register_user(user_id, name, phone, bank_masked, home_lat, home_lon, avg_amount=1000.0):
    db.x("INSERT OR REPLACE INTO users(user_id,name,phone_hash,bank_masked,home_lat,home_lon,avg_amount,txn_count) "
         "VALUES(?,?,?,?,?,?,?,COALESCE((SELECT txn_count FROM users WHERE user_id=?),0))",
         (user_id, name, h(phone), bank_masked, home_lat, home_lon, avg_amount, user_id))


def register_device(user_id, device_id, sim_serial, label="My phone"):
    if not db.q("SELECT 1 FROM users WHERE user_id=?", (user_id,)):
        raise ValueError("unknown user")
    db.x("INSERT INTO devices(user_id,device_hash,sim_hash,label,trusted,created_at) VALUES(?,?,?,?,1,?)",
         (user_id, h(device_id), h(sim_serial), label, db.now()))


def check_device(user_id, device_id, sim_serial, phone):
    """Returns dict(risk 0-1, reasons, flags)."""
    out = {"risk": 0.0, "reasons": [], "user_found": True, "phone_match": True,
           "device_known": True, "sim_match": True}
    users = db.q("SELECT * FROM users WHERE user_id=?", (user_id,))
    if not users:
        out.update(risk=1.0, user_found=False, phone_match=False, device_known=False, sim_match=False)
        out["reasons"].append("User is not registered")
        return out
    user = users[0]

    # phone=None means "logged-in session": the server already knows the registered number
    if phone is not None and not safe_eq(user["phone_hash"], h(phone)):
        out["phone_match"] = False
        out["risk"] = max(out["risk"], 0.95)
        out["reasons"].append("Mobile number does not match the registered number")

    dev_hash = h(device_id or "")
    devices = db.q("SELECT * FROM devices WHERE user_id=? AND trusted=1", (user_id,))
    same = [d for d in devices if safe_eq(d["device_hash"], dev_hash)]
    if not same:
        out["device_known"] = False
        out["risk"] = max(out["risk"], 0.7)
        out["reasons"].append("Payment started from a new / untrusted device")
    else:
        if not any(safe_eq(d["sim_hash"], h(sim_serial or "")) for d in same):
            out["sim_match"] = False
            out["risk"] = max(out["risk"], 0.85)
            out["reasons"].append("SIM card changed on a known device (possible SIM swap)")
    return out
