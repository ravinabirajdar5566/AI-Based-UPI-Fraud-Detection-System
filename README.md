# 🔐 AI-Based Multi-Layer UPI Fraud Detection and Secure Payment Verification System

A working prototype that checks **every payment** through 5 layers and gives one **fraud-risk score (0-100)**:

| # | Layer | What it checks | File |
|---|-------|----------------|------|
| 1 | Identity + Device + SIM binding | registered mobile + trusted device + SIM must match | `backend/app/device.py` |
| 2 | QR scanner | UPI ID format, blacklist, merchant name, amount tampering, "collect" scams | `backend/app/qr_scanner.py` |
| 3 | Link scanner | HTTPS, IP/punycode/shortener, bad TLD, brand look-alike, scam keywords | `backend/app/url_scanner.py` |
| 4 | Network check | IP blacklist, Tor/VPN, public/open Wi-Fi, TLS validity | `backend/app/network_check.py` |
| 5 | Behaviour AI | amount vs your average, time, location, burst, new receiver, reports | `ml/` + `backend/app/model_service.py` |
| + | Blockchain ledger | tamper-evident record (hash + score + status only) | `backend/app/blockchain.py` |

Result: 🟢 **Safe** (<35) → allowed · 🟡 **Verify** (35-69) → OTP · 🔴 **High risk** (≥70) → blocked + alert.


## What is new in v2 (accounts, admin console, live features)

**Sign in / register / admin.** Customers create an account (name, username, email, mobile, password). The browser they register on becomes their **trusted device**. A separate **administrator** role opens the admin console.

| Login | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin@12345` (set `ADMIN_USER` / `ADMIN_PASS` to change) |
| Demo customers | `rahul`, `priya` | `Demo@1234` |

On the sign-in page, the **Customer** and **Administrator** demo buttons log in with one click (shown only while `DEMO_MODE=1`).

| New feature | What it does | Where |
|---|---|---|
| **Live checkpoint lane** | Each payment travels through the five gates and is stamped Cleared / Verify / Blocked. Real payments from any device appear live (Server-Sent Events). | `app/bus.py`, `/api/live/stream` |
| **Explainable AI** | "What pushed the score up": every signal is neutralised one at a time and the whole decision is re-run, so you see exactly how many points each signal added. | `service._explain` |
| **Panic freeze** | One switch blocks every payment from the account (phone lost, scam call in progress). | Security page |
| **Daily spending limit** | A payment that would pass the limit is blocked. | Security page |
| **Trusted-device control** | List, remove, or add trusted devices (password re-entry required). Signing in from an unknown browser raises an alert. | Security page |
| **Security health score** | 0-100 score with tips; falls when payments get blocked or the setup is weak. | Dashboard |
| **Scam check** | Paste an SMS or describe a caller's request: detects OTP/PIN requests, screen-sharing apps, fake KYC, prize bait, urgency, and scans every link inside. | `app/scam_text.py` |
| **Attack lab** | 13 one-click fraud scenarios (stolen phone, SIM swap, fake QR, phishing link...) run through your own checkpoint. | Pay page |
| **Notifications** | Bell with live alerts for blocked payments, OTP requests, new-device sign-ins, freezes. | `app/notify.py` |
| **Review queue (admin)** | Analyst confirms fraud or marks genuine. This writes a ledger block, flags the receiver, and becomes training data (human in the loop). | Admin |
| **Live overview (admin)** | KPIs, live feed with the lane, 24-hour chart, most flagged receivers, ledger integrity. | Admin |
| **Customers (admin)** | Freeze, disable, unlock, promote to admin. | Admin |
| **Blacklist (admin)** | Add / remove receivers at runtime. | Admin |
| **Rules and model (admin)** | Change OTP/block thresholds and the high-value limit live; see model metrics and feature importance; **retrain from feedback with one click**. | Admin |
| **Audit log (admin)** | Every sign-in failure, freeze, role change, review and setting change. | Admin |

**Account security:** PBKDF2-SHA256 (200,000 rounds) password hashing, signed session tokens, account lockout after 5 wrong passwords, identity always taken from the session (a user cannot pay as someone else or verify someone else's OTP), role re-checked on every request, event streams filtered per user.

### New API endpoints
`POST /api/auth/register` · `/api/auth/login` · `GET /api/auth/me` · `POST /api/auth/change-password`
`GET /api/me/overview` · `/api/me/transactions` · `/api/me/devices` · `/api/me/notifications` · `POST /api/me/freeze` · `/api/me/limit`
`POST /api/scan-message` · `GET /api/live/stream?token=...` (Server-Sent Events)
`GET /api/admin/stats` · `/users` · `/transactions` · `/blacklist` · `/settings` · `/audit` · `/model` · `POST /api/admin/review` · `/retrain` · `/settings`

> `/api/check-payment` now needs a login. The Attack lab sends fake device / SIM / phone values on purpose, to act out theft and SIM swap (see limits below).

## Quick start

```bash
# Linux / macOS
bash run.sh
# Windows
run.bat
```
Then open **http://127.0.0.1:8000** (web demo) and **http://127.0.0.1:8000/docs** (API docs).

Manual steps (if you prefer):
```bash
pip install -r backend/requirements.txt
python ml/train.py                 # trains the model (~10 s) -> backend/models/model.pkl
cd backend && uvicorn app.main:app --reload
```
Run the tests (no server needed): `python -m unittest discover -s tests -v` (50 tests: engine, accounts, admin, live bus)

> If you see "model_loaded: false" in `/api/health`, run `python ml/train.py` again (the saved model must match your scikit-learn version).

## How a payment is processed

```
User starts payment
 → Layer 1: registered mobile + device + SIM match?        (device.py)
 → Layer 2: scan QR  → verify UPI ID, merchant, amount     (qr_scanner.py)
 → Layer 3: scan payment link                              (url_scanner.py)
 → Layer 4: network risk                                   (network_check.py)
 → Layer 5: behaviour features → Random Forest probability (features.py, model_service.py)
 → risk_engine.py: combine everything → score + reasons
 → blockchain.py: store hash/score/status
 → 🟢 allow | 🟡 OTP | 🔴 block + alert
```

**Score formula** (`risk_engine.py`):
`final = 1 − (1 − 0.9·ML) × (1 − 0.8·LAYERS) × (1 − 0.7·RULES)` (a noisy-OR: any strong signal raises the score).
Then **hard overrides** can only raise it, e.g. blacklisted receiver → 100, wrong mobile → 100, SIM swap → ≥75,
new device + ₹50,000+ → ≥75, malicious link → ≥90, fake QR → ≥90, new device (any amount) → ≥40.

## Web demo
- **Pay** tab: 13 one-click scenarios (normal, stolen phone, SIM swap, fake QR, phishing link, bad IP …) with the layer bars and the "Why?" list.
- **QR Scanner**: generate a test QR, then upload it to decode and verify.
- **Link Scanner**, **Blockchain Ledger** (with "simulate tampering" button), **History**.

## API (main endpoints)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/check-payment` | full 5-layer check → decision, score, reasons |
| POST | `/api/verify-otp` | complete a 🟡 payment |
| POST | `/api/report-fraud` | feedback loop (3 reports ⇒ UPI ID auto-blacklisted) |
| POST | `/api/scan-qr-image` · `/api/scan-qr-text` · `/api/scan-url` · `/api/network-check` | individual layers |
| POST | `/api/register-user` · `/api/register-device` | bind a user to a trusted device + SIM |
| GET | `/api/ledger` · `/api/ledger/verify` | blockchain blocks / integrity check |
| GET | `/api/transactions/{user}` · `/api/health` · `/api/model` | history, status, model metrics |

Example:
```bash
curl -X POST http://127.0.0.1:8000/api/check-payment -H "Content-Type: application/json" -d '{
 "user_id":"U1001","phone":"9876543210","device_id":"DEV-RAHUL-S23","sim_serial":"SIM-RAHUL-8991",
 "receiver_vpa":"ramesh.kirana@ybl","amount":500,"network":{"type":"home_wifi"},"lat":18.52,"lon":73.85}'
```

## The AI model
- **Data:** `ml/generate_data.py` creates 60,000 **synthetic** UPI-style transactions (4% fraud: account takeover, scam payment, mule burst) with 1% label noise. Real UPI data is private, so this is stated openly. To use PaySim / Kaggle data, convert it to the columns in `FEATURES` + `is_fraud` and run `python ml/train.py --data yourfile.csv`.
- **Model:** Random Forest, `class_weight="balanced_subsample"` (fraud is rare), compared with a Logistic Regression baseline.
- **Metrics (test set, this run):** precision 0.95 · recall 0.79 · F1 0.86 · ROC-AUC 0.89 · PR-AUC 0.82. Accuracy is *not* used, because "always safe" would already score ~96%. See `backend/models/metrics.json`. These numbers are on synthetic data, so they show the pipeline works; they are not a claim about real-world UPI performance.
- **Feedback loop:** completed payments become label 0, reported ones label 1. Run `python ml/train.py --with-feedback` to retrain with them.

## Blockchain part (honest description)
A small **proof-of-work chain stored in the database**: each block = salted tx hash + timestamp + risk score + status + previous hash + nonce. Changing any old block breaks all later blocks (use the **Simulate tampering** button). **No PIN, OTP, account number, phone number or name is ever stored on it.**
Optional: `backend/app/eth_anchor.py` can anchor a block hash on an Ethereum test network (Ganache) with `web3` (not tested in this zip).

## Prototype limits (say these in your viva)
- Passwords/tokens use the Python standard library only. For production add HTTPS, HttpOnly cookies, rate limiting per IP and a secrets manager. **Change `ADMIN_PASS` and `UPI_SALT`.**
- SIM / device binding is **simulated** with IDs sent by the client (the browser keeps a random device ID and SIM ID); real UPI does SIM binding via the bank/NPCI.
- Link scanning is **heuristic + a demo blocklist**; no live Safe Browsing/VirusTotal lookup.
- Network check cannot prove a Wi-Fi is safe; it uses IP lists, VPN/Tor flags, network type and TLS status.
- OTP is shown on screen in `DEMO_MODE`; a real system uses SMS/biometric. Set `DEMO_MODE=0` to hide it.
- Database is SQLite (plain SQL, easy to move to MySQL). Blacklists in `backend/data/*.json` are demo data.
- Change `UPI_SALT` (environment variable) before any real use.

## Project structure
```
upi-fraud/
├── backend/
│   ├── app/            auth.py · admin.py · me.py · bus.py · notify.py · audit.py · scam_text.py (new)
│   │                   main.py (FastAPI) · service.py (orchestration) · risk_engine.py · device.py
│   │                   qr_scanner.py · url_scanner.py · network_check.py · blockchain.py · features.py
│   │                   model_service.py · db.py · seed.py · config.py · eth_anchor.py (optional)
│   ├── data/           blacklist.json · merchants.json · network_lists.json
│   ├── models/         model.pkl · metrics.json
│   ├── static/         index.html (web demo, no build step)
│   └── requirements.txt
├── ml/                 generate_data.py · train.py
├── tests/              test_core.py (32 tests) · test_api.py (18 tests)
├── docs/               VIVA_QA.md
└── run.sh · run.bat
```

## Settings (environment variables)
`ADMIN_USER` / `ADMIN_PASS` first admin login · `TOKEN_TTL` session seconds · `UPI_DB` database path · `UPI_SALT` hash salt · `DEMO_MODE` (1/0) · `DEMO_OTP_FIXED` (e.g. 123456) · `UPI_MODEL` model path.
