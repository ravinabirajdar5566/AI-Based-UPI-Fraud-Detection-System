import hashlib
import hmac

from . import config


def h(value: str) -> str:
    """Salted SHA-256. Raw phone / device / SIM values are never stored."""
    return hashlib.sha256((config.SECRET_SALT + str(value)).encode()).hexdigest()


def safe_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
