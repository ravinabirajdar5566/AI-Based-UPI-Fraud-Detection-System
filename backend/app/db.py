"""SQLite storage. The schema is plain SQL, so moving to MySQL only needs a different driver."""
import json
import sqlite3
import threading
import time

from . import config

_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY, name TEXT, phone_hash TEXT, bank_masked TEXT,
  home_lat REAL, home_lon REAL, avg_amount REAL DEFAULT 1000, txn_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, device_hash TEXT, sim_hash TEXT,
  label TEXT, trusted INTEGER DEFAULT 1, created_at REAL);
CREATE TABLE IF NOT EXISTS beneficiaries (
  user_id TEXT, vpa TEXT, first_seen REAL, count INTEGER DEFAULT 1, PRIMARY KEY (user_id, vpa));
CREATE TABLE IF NOT EXISTS transactions (
  tx_id TEXT PRIMARY KEY, user_id TEXT, vpa TEXT, amount REAL, ts REAL,
  risk_score REAL, decision TEXT, status TEXT, reasons TEXT, features TEXT, label INTEGER);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT, vpa TEXT, user_id TEXT, reason TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS ledger (
  idx INTEGER PRIMARY KEY, ts REAL, tx_hash TEXT, prev_hash TEXT,
  risk_score REAL, status TEXT, nonce INTEGER, hash TEXT);
CREATE TABLE IF NOT EXISTS otps (
  tx_id TEXT PRIMARY KEY, otp_hash TEXT, expires REAL, attempts INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT UNIQUE, name TEXT,
  pw_salt TEXT, pw_hash TEXT, role TEXT DEFAULT 'user', user_id TEXT, created_at REAL, last_login REAL,
  failed INTEGER DEFAULT 0, locked_until REAL DEFAULT 0, disabled INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS blacklist (
  vpa TEXT PRIMARY KEY, reason TEXT, added_by TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, ts REAL, level TEXT, title TEXT, body TEXT, read INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS simulations (
  id TEXT PRIMARY KEY, user_id TEXT, scenario_id TEXT, scenario_name TEXT,
  ts REAL, risk_score REAL, decision TEXT, normal_score REAL, normal_decision TEXT,
  data_json TEXT, ledger_block INTEGER, ledger_hash TEXT);
CREATE TABLE IF NOT EXISTS qr_scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, ts REAL,
  payload TEXT, risk REAL, status TEXT, reasons TEXT);
"""

# columns added after v1 (kept as migrations so an old upi.db keeps working)
MIGRATIONS = [
    ("users", "frozen", "INTEGER DEFAULT 0"),
    ("users", "daily_limit", "REAL DEFAULT 50000"),
    ("transactions", "review", "TEXT"),
    ("transactions", "explain", "TEXT"),
]
ALL_TABLES = ["users", "devices", "beneficiaries", "transactions", "reports", "ledger", "otps",
              "accounts", "audit", "blacklist", "settings", "notifications", "simulations", "qr_scans"]


def conn():
    c = sqlite3.connect(str(config.DB_PATH), check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        c = conn()
        c.executescript(SCHEMA)
        for table, col, decl in MIGRATIONS:
            cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]
            if col not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        c.commit()
        c.close()


def q(sql, args=()):
    """SELECT -> list of dicts."""
    with _lock:
        c = conn()
        try:
            return [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()


def x(sql, args=()):
    """INSERT/UPDATE/DELETE -> lastrowid."""
    with _lock:
        c = conn()
        try:
            cur = c.execute(sql, args)
            c.commit()
            return cur.lastrowid
        finally:
            c.close()


def reset_all():
    with _lock:
        c = conn()
        for t in ALL_TABLES:
            c.execute(f"DROP TABLE IF EXISTS {t}")
        c.commit()
        c.close()
    init_db()


def dumps(o):
    return json.dumps(o, default=str)


def now():
    return time.time()


def log_qr_scan(user_id, payload, risk, status, reasons):
    """Log an analyzed QR scan to the database."""
    r_str = json.dumps(reasons) if isinstance(reasons, (list, dict)) else str(reasons or "")
    return x("INSERT INTO qr_scans(user_id,ts,payload,risk,status,reasons) VALUES(?,?,?,?,?,?)",
             (user_id or "ANONYMOUS", now(), str(payload or "")[:500], float(risk or 0.0), str(status or "CHECKED"), r_str))

