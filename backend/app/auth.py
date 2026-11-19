"""Accounts: register, login, signed session tokens, roles (user / admin). Standard library only.

Passwords : PBKDF2-HMAC-SHA256, 200 000 rounds, random salt per account.
Sessions  : stateless token  base64(json).HMAC  - role is re-read from the DB on every request,
            so disabling an account or changing a role takes effect immediately.
Lockout   : 5 wrong passwords -> account locked for 5 minutes.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import time

from fastapi import Depends, HTTPException, Request

from . import audit, config, db, device, notify
from .security import h

USERNAME_RE = re.compile(r"^[a-z0-9_.]{3,24}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
PHONE_RE = re.compile(r"^[6-9]\d{9}$")


def _pw_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sign(body):
    return hmac.new(config.SECRET_SALT.encode(), body.encode(), hashlib.sha256).hexdigest()


def make_token(account):
    body = _b64(json.dumps({"a": account["id"], "e": int(time.time()) + config.TOKEN_TTL}).encode())
    return body + "." + _sign(body)


def parse_token(token):
    try:
        body, sig = token.split(".", 1)
        if not hmac.compare_digest(sig, _sign(body)):
            return None
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        return data if data["e"] > time.time() else None
    except Exception:
        return None


def check_password_strength(pw):
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        raise ValueError("Password needs at least 8 characters with a letter and a number")


def public(acc):
    """Account fields that are safe to send to the browser."""
    out = {k: acc[k] for k in ("id", "username", "email", "name", "role", "user_id", "created_at", "last_login")}
    return out


def create_account(username, email, name, password, role="user", user_id=None):
    salt = secrets.token_hex(16)
    db.x("INSERT INTO accounts(username,email,name,pw_salt,pw_hash,role,user_id,created_at) VALUES(?,?,?,?,?,?,?,?)",
         (username, email, name, salt, _pw_hash(password, salt), role, user_id, db.now()))
    return db.q("SELECT * FROM accounts WHERE username=?", (username,))[0]


def register(username, email, name, phone, password, device_id, sim_serial, device_label="This browser"):
    username, email, name, phone = username.strip().lower(), email.strip().lower(), name.strip(), phone.strip()
    if not USERNAME_RE.match(username):
        raise ValueError("Username: 3-24 characters, letters, numbers, dot or underscore")
    if not EMAIL_RE.match(email):
        raise ValueError("Enter a valid email address")
    if len(name) < 2:
        raise ValueError("Enter your full name")
    if not PHONE_RE.match(phone):
        raise ValueError("Enter a 10-digit Indian mobile number starting with 6-9")
    check_password_strength(password)
    if not device_id or not sim_serial:
        raise ValueError("Device information missing - reload the page and try again")
    if db.q("SELECT 1 FROM accounts WHERE username=? OR email=?", (username, email)):
        raise ValueError("That username or email is already registered")
    while True:
        user_id = "U" + str(secrets.randbelow(9000) + 1000)
        if not db.q("SELECT 1 FROM users WHERE user_id=?", (user_id,)):
            break
    device.register_user(user_id, name, phone, f"XXXX{secrets.randbelow(9000) + 1000} (Demo Bank)",
                         18.5204, 73.8567, 1000.0)
    db.x("UPDATE users SET daily_limit=? WHERE user_id=?", (config.DEFAULT_DAILY_LIMIT, user_id))
    device.register_device(user_id, device_id, sim_serial, device_label)
    acc = create_account(username, email, name, password, "user", user_id)
    notify.add(user_id, "ok", "Welcome to UPI Shield", "This browser is now your trusted device.")
    audit.log(username, "register", user_id)
    return acc


def login(identifier, password, device_id=None):
    ident = identifier.strip().lower()
    rows = db.q("SELECT * FROM accounts WHERE username=? OR email=?", (ident, ident))
    if not rows:
        _pw_hash(password, "00" * 16)  # same time cost whether or not the user exists
        raise PermissionError("Wrong username or password")
    acc = rows[0]
    if acc["disabled"]:
        raise PermissionError("This account has been disabled. Contact the administrator.")
    if acc["locked_until"] > time.time():
        mins = int((acc["locked_until"] - time.time()) / 60) + 1
        raise PermissionError(f"Too many wrong passwords. Try again in {mins} minute(s).")
    if not hmac.compare_digest(_pw_hash(password, acc["pw_salt"]), acc["pw_hash"]):
        fails = acc["failed"] + 1
        locked = time.time() + config.LOCK_SECONDS if fails >= config.MAX_LOGIN_FAILS else 0
        db.x("UPDATE accounts SET failed=?, locked_until=? WHERE id=?", (0 if locked else fails, locked, acc["id"]))
        audit.log(acc["username"], "login_failed", acc["user_id"] or "", f"attempt {fails}")
        if locked and acc["user_id"]:
            notify.add(acc["user_id"], "bad", "Account locked", "5 wrong passwords in a row. Locked for 5 minutes.")
        raise PermissionError("Wrong username or password" if not locked else "Too many wrong passwords. Locked for 5 minutes.")
    db.x("UPDATE accounts SET failed=0, locked_until=0, last_login=? WHERE id=?", (db.now(), acc["id"]))
    new_device = False
    if acc["user_id"] and device_id:
        known = [d for d in db.q("SELECT device_hash FROM devices WHERE user_id=? AND trusted=1", (acc["user_id"],))
                 if hmac.compare_digest(d["device_hash"], h(device_id))]
        if not known:
            new_device = True
            notify.add(acc["user_id"], "warn", "Sign-in from a new device",
                       "If this was not you, freeze your account in Security. Payments from this device need extra verification.")
    audit.log(acc["username"], "login", acc["user_id"] or "", "new device" if new_device else "")
    return acc, new_device


def change_password(acc, old, new):
    if not hmac.compare_digest(_pw_hash(old, acc["pw_salt"]), acc["pw_hash"]):
        raise ValueError("Current password is wrong")
    check_password_strength(new)
    salt = secrets.token_hex(16)
    db.x("UPDATE accounts SET pw_salt=?, pw_hash=? WHERE id=?", (salt, _pw_hash(new, salt), acc["id"]))
    audit.log(acc["username"], "password_changed", acc["user_id"] or "")


def ensure_admin():
    if not db.q("SELECT 1 FROM accounts WHERE role='admin' LIMIT 1"):
        create_account(config.ADMIN_USER, "admin@upishield.local", "Administrator", config.ADMIN_PASS, "admin", None)


# ---- FastAPI dependencies ----
def current_account(request: Request):
    hdr = request.headers.get("authorization", "")
    token = hdr[7:] if hdr.lower().startswith("bearer ") else request.query_params.get("token", "")
    data = parse_token(token) if token else None
    if not data:
        raise HTTPException(401, "Please sign in")
    rows = db.q("SELECT * FROM accounts WHERE id=?", (data["a"],))
    if not rows or rows[0]["disabled"]:
        raise HTTPException(401, "Session is no longer valid")
    return rows[0]


def require_user(acc=Depends(current_account)):
    if not acc["user_id"]:
        raise HTTPException(403, "Admin accounts have no payment profile")
    return acc


def require_admin(acc=Depends(current_account)):
    if acc["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return acc
