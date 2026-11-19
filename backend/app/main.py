"""FastAPI server.  Run from the backend/ folder:   uvicorn app.main:app --reload
Open http://127.0.0.1:8000  (web app)   and   http://127.0.0.1:8000/docs  (interactive API docs)
"""
import asyncio
import base64
import json
from typing import Optional
from urllib.parse import unquote

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import (admin, audit, auth, blockchain, bus, config, db, device, lab, me, model_service, network_check, notify,
               qr_scanner, scam_text, seed, service, url_scanner)

app = FastAPI(title="UPI Shield - Secure AI-Based UPI Fraud Detection System", version="2.0")


def _d(m):
    return m.model_dump() if hasattr(m, "model_dump") else m.dict()


@app.on_event("startup")
def _startup():
    seed.seed_demo()


def guard(fn, *a, **kw):
    """Turn service-layer ValueError into a clean 400 response."""
    try:
        return fn(*a, **kw)
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---------------- request models ----------------
class Network(BaseModel):
    ip: Optional[str] = None
    type: str = "unknown"
    vpn: bool = False
    tls_ok: bool = True


class PaymentIn(BaseModel):
    receiver_vpa: Optional[str] = None
    amount: float
    qr_payload: Optional[str] = None
    payment_link: Optional[str] = None
    network: Network = Network()
    lat: Optional[float] = None
    lon: Optional[float] = None
    hour_override: Optional[int] = None
    # this browser's identity (simulated phone/SIM). The Attack Lab overrides these to act out theft / SIM swap.
    device_id: Optional[str] = None
    sim_serial: Optional[str] = None
    phone: Optional[str] = None


class RegisterIn(BaseModel):
    username: str
    email: str
    name: str
    phone: str
    password: str
    device_id: str
    sim_serial: str


class LoginIn(BaseModel):
    identifier: str
    password: str
    device_id: Optional[str] = None


class PasswordIn(BaseModel):
    old_password: str
    new_password: str


class OtpIn(BaseModel):
    tx_id: str
    otp: str


class ReportIn(BaseModel):
    tx_id: Optional[str] = None
    vpa: Optional[str] = None
    reason: str = "user reported"


class QrImageIn(BaseModel):
    image_base64: str
    amount: Optional[float] = None
    entered_vpa: Optional[str] = None


class QrTextIn(BaseModel):
    payload: str
    amount: Optional[float] = None
    entered_vpa: Optional[str] = None


class UrlIn(BaseModel):
    url: str


class TextIn(BaseModel):
    text: str


class NetIn(BaseModel):
    ip: Optional[str] = None
    type: str = "unknown"
    vpn: bool = False
    tls_ok: bool = True


class BoolIn(BaseModel):
    value: bool


class LimitIn(BaseModel):
    daily_limit: float


class TrustDeviceIn(BaseModel):
    device_id: str
    sim_serial: str
    label: str = "My phone"
    password: str


class RoleIn(BaseModel):
    role: str


class ReviewIn(BaseModel):
    tx_id: str
    verdict: str


class BlacklistIn(BaseModel):
    vpa: str
    reason: str = ""


class SettingsIn(BaseModel):
    thresh_verify: Optional[float] = None
    thresh_block: Optional[float] = None
    high_amount: Optional[float] = None


class LabSimulateIn(BaseModel):
    scenario_id: str
    custom_params: Optional[dict] = None


# ---------------- public ----------------
@app.get("/api/health")
def health():
    return {"status": "ok", "demo_mode": config.DEMO_MODE,
            "thresholds": {"verify": config.THRESH_VERIFY, "block": config.THRESH_BLOCK}, **model_service.info()}


@app.get("/api/public/stats")
def public_stats():
    """Anonymous counters for the sign-in page."""
    r = db.q("SELECT COUNT(*) AS n, COALESCE(SUM(decision='BLOCK'),0) AS b FROM transactions")[0]
    return {"checked": r["n"], "blocked": r["b"], "layers": 5}


# ---------------- auth ----------------
@app.post("/api/auth/register")
def register(r: RegisterIn):
    acc = guard(auth.register, r.username, r.email, r.name, r.phone, r.password, r.device_id, r.sim_serial)
    return {"token": auth.make_token(acc), "account": auth.public(acc)}


@app.post("/api/auth/login")
def login(r: LoginIn):
    try:
        acc, new_device = auth.login(r.identifier, r.password, r.device_id)
    except PermissionError as e:
        raise HTTPException(401, str(e))
    return {"token": auth.make_token(acc), "account": auth.public(acc), "new_device": new_device}


@app.get("/api/auth/me")
def whoami(acc=Depends(auth.current_account)):
    return {"account": auth.public(acc)}


@app.post("/api/auth/change-password")
def change_password(p: PasswordIn, acc=Depends(auth.current_account)):
    guard(auth.change_password, acc, p.old_password, p.new_password)
    return {"changed": True}


# ---------------- customer ----------------
@app.get("/api/me/overview")
def my_overview(acc=Depends(auth.require_user)):
    return me.overview(acc)


@app.get("/api/me/devices")
def my_devices(acc=Depends(auth.require_user)):
    return me.devices(acc["user_id"])


@app.post("/api/me/devices")
def trust_device(d: TrustDeviceIn, acc=Depends(auth.require_user)):
    try:
        auth.login(acc["username"], d.password)  # re-enter password to trust a new device
    except PermissionError as e:
        raise HTTPException(401, str(e))
    guard(device.register_device, acc["user_id"], d.device_id, d.sim_serial, d.label)
    notify.add(acc["user_id"], "ok", "New trusted device", d.label)
    return {"trusted": True}


@app.delete("/api/me/devices/{dev_id}")
def remove_device(dev_id: int, acc=Depends(auth.require_user)):
    guard(me.revoke_device, acc, dev_id)
    return {"removed": dev_id}


@app.post("/api/me/freeze")
def my_freeze(b: BoolIn, acc=Depends(auth.require_user)):
    me.set_freeze(acc, b.value)
    return {"frozen": b.value}


@app.post("/api/me/limit")
def my_limit(b: LimitIn, acc=Depends(auth.require_user)):
    guard(me.set_limit, acc, b.daily_limit)
    return {"daily_limit": b.daily_limit}


@app.get("/api/me/notifications")
def my_notes(acc=Depends(auth.require_user)):
    return {"items": notify.for_user(acc["user_id"]), "unread": notify.unread(acc["user_id"])}


@app.post("/api/me/notifications/read")
def read_notes(acc=Depends(auth.require_user)):
    notify.mark_all_read(acc["user_id"])
    return {"ok": True}


@app.get("/api/me/transactions")
def my_transactions(limit: int = 50, acc=Depends(auth.require_user)):
    return service.transactions_for(acc["user_id"], min(limit, 200))


@app.post("/api/check-payment")
def check_payment(p: PaymentIn, request: Request, acc=Depends(auth.require_user)):
    body = _d(p)
    body["user_id"] = acc["user_id"]  # identity always comes from the session, never from the client
    return guard(service.check_payment, body, client_ip=request.client.host if request.client else None)


def _own_tx(acc, tx_id):
    rows = db.q("SELECT user_id FROM transactions WHERE tx_id=?", (tx_id,))
    if not rows or rows[0]["user_id"] != acc["user_id"]:
        raise HTTPException(404, "unknown transaction")


@app.post("/api/verify-otp")
def verify_otp(o: OtpIn, acc=Depends(auth.require_user)):
    _own_tx(acc, o.tx_id)
    return guard(service.verify_otp, o.tx_id, o.otp)


@app.post("/api/report-fraud")
def report_fraud(r: ReportIn, acc=Depends(auth.require_user)):
    if r.tx_id:
        _own_tx(acc, r.tx_id)
    return guard(service.report_fraud, acc["user_id"], r.tx_id, r.vpa, r.reason)


# ---------------- scanners (signed-in users) ----------------
@app.post("/api/scan-qr-text")
def scan_qr_text(q: QrTextIn, acc=Depends(auth.current_account)):
    res = qr_scanner.analyze_qr(q.payload, q.amount, q.entered_vpa)
    db.log_qr_scan(acc.get("user_id"), q.payload, res.get("risk", 0.0),
                   "SUSPICIOUS" if res.get("risk", 0.0) >= 0.5 else "VALID", res.get("reasons", []))
    return res


@app.post("/api/scan-qr-image")
async def scan_qr_image(request: Request, acc=Depends(auth.current_account)):
    content_type = (request.headers.get("content-type") or "").lower()
    image_bytes = None
    amount = None
    entered_vpa = None

    if "multipart/form-data" in content_type:
        try:
            form = await request.form()
        except Exception as e:
            raise HTTPException(400, f"Invalid multipart form data: {e}")
        upload = form.get("file") or form.get("image") or form.get("qr_image")
        if upload and hasattr(upload, "read"):
            image_bytes = await upload.read()
        elif form.get("image_base64"):
            raw_b64 = str(form.get("image_base64"))
            try:
                image_bytes = base64.b64decode(raw_b64.split(",")[-1])
            except Exception:
                raise HTTPException(400, "invalid base64 image")

        amt_val = form.get("amount") or form.get("entered_amount")
        if amt_val is not None and str(amt_val).strip() != "":
            try:
                amount = float(amt_val)
            except ValueError:
                pass

        vpa_val = form.get("entered_vpa") or form.get("vpa")
        if vpa_val:
            entered_vpa = str(vpa_val).strip()

    elif "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON body")
        raw_b64 = body.get("image_base64")
        if not raw_b64:
            raise HTTPException(400, "image_base64 or file is required")
        try:
            image_bytes = base64.b64decode(raw_b64.split(",")[-1])
        except Exception:
            raise HTTPException(400, "invalid base64 image")

        amt_val = body.get("amount") or body.get("entered_amount")
        if amt_val is not None:
            try:
                amount = float(amt_val)
            except ValueError:
                pass

        vpa_val = body.get("entered_vpa") or body.get("vpa")
        if vpa_val:
            entered_vpa = str(vpa_val).strip()
    else:
        body_bytes = await request.body()
        if body_bytes:
            image_bytes = body_bytes

    if not image_bytes:
        raise HTTPException(400, "No image file or image data provided")

    text = qr_scanner.decode_qr_image(image_bytes)
    if not text:
        import cv2
        import numpy as np
        arr = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_UNCHANGED) if cv2 else None
        if arr is None:
            raise HTTPException(400, "Invalid image format. Supported formats: PNG, JPG, JPEG, WEBP.")
        raise HTTPException(422, "No QR code found in the image. Please ensure the QR code is clearly visible, well-lit, and unblurred.")

    analysis = qr_scanner.analyze_qr(text, entered_amount=amount, entered_vpa=entered_vpa)
    db.log_qr_scan(acc.get("user_id"), text, analysis.get("risk", 0.0),
                   "SUSPICIOUS" if analysis.get("risk", 0.0) >= 0.5 else "VALID", analysis.get("reasons", []))
    return {"decoded": text, **analysis}


@app.get("/api/qr/generate")
def qr_generate(request: Request, text: Optional[str] = None):
    raw_query = request.url.query
    if "text=" in raw_query:
        extracted = raw_query.split("text=", 1)[1]
        text = unquote(extracted) if "%" in extracted else extracted
    if not text:
        text = "upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40&cu=INR"
    return Response(qr_scanner.generate_qr_png(text), media_type="image/png")


@app.post("/api/qr/generate")
async def qr_generate_post(request: Request):
    content_type = (request.headers.get("content-type") or "").lower()
    text = None
    if "application/json" in content_type:
        body = await request.json()
        text = body.get("text") or body.get("payload")
    elif "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        text = form.get("text") or form.get("payload")
    if not text:
        text = "upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40&cu=INR"
    return Response(qr_scanner.generate_qr_png(str(text)), media_type="image/png")


@app.post("/api/scan-url")
def scan_url(u: UrlIn, acc=Depends(auth.current_account)):
    return url_scanner.scan_url(u.url)


@app.post("/api/scan-message")
def scan_message(t: TextIn, acc=Depends(auth.current_account)):
    return guard(scam_text.analyze_message, t.text)


@app.post("/api/network-check")
def net_check(n: NetIn, request: Request, acc=Depends(auth.current_account)):
    return network_check.check_network(n.ip or (request.client.host if request.client else None), n.type, n.vpn, n.tls_ok)


@app.get("/api/ledger")
def ledger(limit: int = 30, acc=Depends(auth.current_account)):
    return {"blocks": blockchain.get_chain(limit), "verification": blockchain.verify_chain()}


@app.get("/api/ledger/verify")
def ledger_verify(acc=Depends(auth.current_account)):
    return blockchain.verify_chain()


@app.get("/api/model")
def model_info(acc=Depends(auth.current_account)):
    return model_service.info()


# ---------------- fraud attack replay lab ----------------
@app.get("/api/lab/scenarios")
def lab_scenarios(acc=Depends(auth.current_account)):
    return {"scenarios": lab.list_scenarios()}


@app.post("/api/lab/simulate")
def lab_simulate(s: LabSimulateIn, acc=Depends(auth.current_account)):
    return guard(lab.simulate, acc, s.scenario_id, s.custom_params)


@app.get("/api/lab/history")
def lab_history(limit: int = 20, acc=Depends(auth.current_account)):
    return {"history": lab.get_history(acc, min(limit, 100))}


@app.post("/api/lab/reset")
def lab_reset(acc=Depends(auth.current_account)):
    return lab.reset_history(acc)


# ---------------- live stream (Server-Sent Events) ----------------
def _sse(e):
    return f"data: {json.dumps(e, default=str)}\n\n"


@app.get("/api/live/stream")
async def live_stream(request: Request, acc=Depends(auth.current_account)):
    """Admins receive every event; customers only receive their own. EventSource cannot set headers, so ?token= is accepted."""
    is_admin = acc["role"] == "admin"
    sub = bus.subscribe()
    q = sub[1]

    def allowed(e):
        return is_admin or e.get("user_id") == acc["user_id"]

    async def gen():
        try:
            yield "retry: 3000\n\n"
            for e in bus.recent():
                if allowed(e):
                    yield _sse({**e, "replay": True})
            while not await request.is_disconnected():
                try:
                    e = await asyncio.wait_for(q.get(), 15)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                if allowed(e):
                    yield _sse(e)
        finally:
            bus.unsubscribe(sub)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------- admin ----------------
@app.get("/api/admin/stats")
def a_stats(acc=Depends(auth.require_admin)):
    return admin.stats()


@app.get("/api/admin/users")
def a_users(acc=Depends(auth.require_admin)):
    return admin.users()


@app.post("/api/admin/users/{account_id}/status")
def a_status(account_id: int, b: BoolIn, acc=Depends(auth.require_admin)):
    return guard(admin.set_account_status, acc, account_id, b.value)


@app.post("/api/admin/users/{account_id}/freeze")
def a_freeze(account_id: int, b: BoolIn, acc=Depends(auth.require_admin)):
    guard(admin.set_freeze, acc, account_id, b.value)
    return {"ok": True}


@app.post("/api/admin/users/{account_id}/disable")
def a_disable(account_id: int, b: BoolIn, acc=Depends(auth.require_admin)):
    guard(admin.set_disabled, acc, account_id, b.value)
    return {"ok": True}


@app.post("/api/admin/users/{account_id}/role")
def a_role(account_id: int, r: RoleIn, acc=Depends(auth.require_admin)):
    guard(admin.set_role, acc, account_id, r.role)
    return {"ok": True}


@app.post("/api/admin/users/{account_id}/unlock")
def a_unlock(account_id: int, acc=Depends(auth.require_admin)):
    guard(admin.unlock, acc, account_id)
    return {"ok": True}


@app.get("/api/admin/transactions")
def a_tx(
    decision: Optional[str] = None,
    open_only: bool = False,
    search: Optional[str] = None,
    status: Optional[str] = None,
    min_risk: Optional[float] = None,
    max_risk: Optional[float] = None,
    limit: int = 100,
    offset: int = 0,
    acc=Depends(auth.require_admin)
):
    return admin.transactions(
        decision=decision,
        only_open=open_only,
        limit=min(limit, 500),
        offset=max(offset, 0),
        search=search,
        status=status,
        min_risk=min_risk,
        max_risk=max_risk
    )


@app.get("/api/admin/alerts")
def a_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    acc=Depends(auth.require_admin)
):
    return admin.alerts(status_filter=status, severity_filter=severity, limit=min(limit, 300))


@app.post("/api/admin/review")
def a_review(r: ReviewIn, acc=Depends(auth.require_admin)):
    return guard(admin.review, acc, r.tx_id, r.verdict)


@app.get("/api/admin/blacklist")
def a_bl(acc=Depends(auth.require_admin)):
    return admin.blacklist_list()


@app.post("/api/admin/blacklist")
def a_bl_add(b: BlacklistIn, acc=Depends(auth.require_admin)):
    guard(admin.blacklist_add, acc, b.vpa, b.reason)
    return {"ok": True}


@app.delete("/api/admin/blacklist/{vpa:path}")
def a_bl_del(vpa: str, acc=Depends(auth.require_admin)):
    guard(admin.blacklist_remove, acc, vpa)
    return {"ok": True}


@app.get("/api/admin/settings")
def a_settings(acc=Depends(auth.require_admin)):
    return admin.get_settings()


@app.post("/api/admin/settings")
def a_settings_set(s: SettingsIn, acc=Depends(auth.require_admin)):
    return guard(admin.set_settings, acc["username"], _d(s))


@app.get("/api/admin/audit")
def a_audit(search: Optional[str] = None, action: Optional[str] = None, limit: int = 150, acc=Depends(auth.require_admin)):
    return admin.audit_logs(search=search, action=action, limit=min(limit, 500))


@app.get("/api/admin/model")
def a_model(acc=Depends(auth.require_admin)):
    return admin.model_status()


@app.get("/api/admin/ai-monitoring")
def a_ai_monitoring(acc=Depends(auth.require_admin)):
    return admin.ai_monitoring()


@app.post("/api/admin/ledger/verify")
def a_ledger_verify(acc=Depends(auth.require_admin)):
    return admin.verify_ledger(acc)


@app.post("/api/admin/retrain")
def a_retrain(acc=Depends(auth.require_admin)):
    return guard(admin.retrain, acc)


@app.post("/api/admin/demo/tamper")
def demo_tamper(acc=Depends(auth.require_admin)):
    if not config.DEMO_MODE:
        raise HTTPException(403, "demo mode off")
    idx = blockchain.tamper_demo()
    audit.log(acc["username"], "demo_tamper", idx)
    return {"tampered_block": idx, "verification": blockchain.verify_chain()}


@app.post("/api/admin/demo/reset")
def demo_reset(acc=Depends(auth.require_admin)):
    if not config.DEMO_MODE:
        raise HTTPException(403, "demo mode off")
    db.reset_all()
    seed.seed_demo()
    return {"reset": True}


# ---------------- web page ----------------
STATIC = config.BASE_DIR / "static"


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
