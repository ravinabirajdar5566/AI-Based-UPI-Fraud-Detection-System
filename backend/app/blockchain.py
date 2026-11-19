"""Tamper-evident ledger (a small proof-of-work blockchain stored in the database).

PRIVACY: a block holds ONLY a salted transaction hash, timestamp, risk score and status.
No account number, UPI PIN, OTP, phone number or name is ever written to the chain.
Each block stores the hash of the previous block, so editing any old record breaks every block after it.
"""
import hashlib
import threading

from . import config, db

GENESIS_PREV = "0" * 64
_lock = threading.RLock()


def _hash(idx, ts, tx_hash, prev_hash, risk_score, status, nonce):
    raw = f"{idx}|{ts:.6f}|{tx_hash}|{prev_hash}|{float(risk_score):.3f}|{status}|{nonce}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _mine(idx, ts, tx_hash, prev_hash, risk_score, status):
    target = "0" * config.CHAIN_DIFFICULTY
    nonce = 0
    while True:
        hh = _hash(idx, ts, tx_hash, prev_hash, risk_score, status, nonce)
        if hh.startswith(target):
            return nonce, hh
        nonce += 1


def ensure_genesis():
    with _lock:
        if not db.q("SELECT 1 FROM ledger LIMIT 1"):
            ts = db.now()
            nonce, hh = _mine(0, ts, "GENESIS", GENESIS_PREV, 0, "GENESIS")
            db.x("INSERT INTO ledger(idx,ts,tx_hash,prev_hash,risk_score,status,nonce,hash) VALUES(?,?,?,?,?,?,?,?)",
                 (0, ts, "GENESIS", GENESIS_PREV, 0, "GENESIS", nonce, hh))


def add_block(tx_hash, risk_score, status):
    with _lock:
        ensure_genesis()
        last = db.q("SELECT * FROM ledger ORDER BY idx DESC LIMIT 1")[0]
        idx, ts = last["idx"] + 1, db.now()
        risk_score = round(float(risk_score), 3)
        nonce, hh = _mine(idx, ts, tx_hash, last["hash"], risk_score, status)
        db.x("INSERT INTO ledger(idx,ts,tx_hash,prev_hash,risk_score,status,nonce,hash) VALUES(?,?,?,?,?,?,?,?)",
             (idx, ts, tx_hash, last["hash"], risk_score, status, nonce, hh))
        return {"index": idx, "hash": hh, "prev_hash": last["hash"]}


def get_chain(limit=50):
    rows = db.q("SELECT * FROM ledger ORDER BY idx DESC LIMIT ?", (limit,))
    return rows


def verify_chain():
    """Re-compute every hash. Returns dict(valid, length, broken_at, reason)."""
    rows = db.q("SELECT * FROM ledger ORDER BY idx ASC")
    target = "0" * config.CHAIN_DIFFICULTY
    prev = GENESIS_PREV
    for r in rows:
        calc = _hash(r["idx"], r["ts"], r["tx_hash"], r["prev_hash"], r["risk_score"], r["status"], r["nonce"])
        if r["prev_hash"] != prev:
            return {"valid": False, "length": len(rows), "broken_at": r["idx"], "reason": "previous-hash link broken"}
        if calc != r["hash"] or not calc.startswith(target):
            return {"valid": False, "length": len(rows), "broken_at": r["idx"], "reason": "block content was modified"}
        prev = r["hash"]
    return {"valid": True, "length": len(rows), "broken_at": None, "reason": "all blocks verified"}


def tamper_demo():
    """DEMO ONLY: silently lowers the risk score of the newest block to show detection."""
    rows = db.q("SELECT idx, risk_score FROM ledger WHERE idx>0 ORDER BY idx DESC LIMIT 1")
    if not rows:
        return None
    db.x("UPDATE ledger SET risk_score=? WHERE idx=?", (0.0 if rows[0]["risk_score"] else 99.0, rows[0]["idx"]))
    return rows[0]["idx"]
