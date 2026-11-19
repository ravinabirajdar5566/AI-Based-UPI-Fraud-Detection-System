"""Central settings. Override with environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_PATH = Path(os.getenv("UPI_MODEL", BASE_DIR / "models" / "model.pkl"))
DB_PATH = Path(os.getenv("UPI_DB", DATA_DIR / "upi.db"))

# Used to hash phone numbers / device ids / transaction ids. CHANGE in production.
SECRET_SALT = os.getenv("UPI_SALT", "change-me-in-production")

# DEMO_MODE=1 -> OTP is returned in the API response (no real SMS gateway in a college prototype)
DEMO_MODE = os.getenv("DEMO_MODE", "1") == "1"

# Risk thresholds (0-100 scale)
THRESH_VERIFY = 35   # >= this -> extra verification
THRESH_BLOCK = 70    # >= this -> block

HIGH_AMOUNT = 50000          # INR, used by hard rules
CHAIN_DIFFICULTY = 3         # leading zeros required for a block hash (proof-of-work demo)
OTP_TTL_SECONDS = 300
OTP_MAX_ATTEMPTS = 3
DEMO_OTP_FIXED = os.getenv("DEMO_OTP_FIXED", "")  # set e.g. 123456 for predictable demos

# ---- accounts / admin ----
TOKEN_TTL = int(os.getenv("TOKEN_TTL", 60 * 60 * 12))          # login lasts 12 hours
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "Admin@12345")            # CHANGE before any real use
MAX_LOGIN_FAILS = 5
LOCK_SECONDS = 300
DEFAULT_DAILY_LIMIT = 50000
CHAIN_DIFFICULTY = int(os.getenv("CHAIN_DIFFICULTY", CHAIN_DIFFICULTY))
