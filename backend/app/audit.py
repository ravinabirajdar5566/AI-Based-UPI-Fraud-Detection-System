"""Append-only admin / security audit trail."""
from . import db


def log(actor, action, target="", detail=""):
    db.x("INSERT INTO audit(ts,actor,action,target,detail) VALUES(?,?,?,?,?)",
         (db.now(), actor, action, str(target), str(detail)[:500]))


def recent(limit=100):
    return db.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
