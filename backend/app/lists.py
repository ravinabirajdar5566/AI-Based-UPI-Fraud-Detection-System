import json
from functools import lru_cache

from . import config, db


@lru_cache(maxsize=None)
def _load(name):
    with open(config.DATA_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def blacklist():
    return _load("blacklist.json")


def merchants():
    return _load("merchants.json")


def network_lists():
    return _load("network_lists.json")


def report_count(vpa):
    rows = db.q("SELECT COUNT(*) AS c FROM reports WHERE vpa=?", ((vpa or "").lower(),))
    return rows[0]["c"] if rows else 0


def vpa_blacklisted(vpa):
    """Static list OR crowd-sourced: 3+ user fraud reports auto-blacklist a UPI ID."""
    v = (vpa or "").lower()
    if v in {x.lower() for x in blacklist()["vpas"]} or report_count(v) >= 3:
        return True
    return bool(db.q("SELECT 1 FROM blacklist WHERE vpa=?", (v,)))
