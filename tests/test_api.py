"""API tests for accounts, admin and live features.  Run: python -m unittest discover -s tests -v"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
os.environ["UPI_DB"] = os.path.join(tempfile.mkdtemp(), "api.db")
os.environ["CHAIN_DIFFICULTY"] = "2"
os.environ["DEMO_OTP_FIXED"] = "123456"

from fastapi.testclient import TestClient  # noqa: E402

from app import bus, config, main, scam_text  # noqa: E402

config.CHAIN_DIFFICULTY = 2


def hdr(tok):
    return {"Authorization": "Bearer " + tok}


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cm = TestClient(main.app)
        cls.c = cls.cm.__enter__()          # runs startup -> seeds admin + demo users
        r = cls.c.post("/api/auth/login", json={"identifier": "admin", "password": config.ADMIN_PASS})
        cls.admin = r.json()["token"]
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.cm.__exit__(None, None, None)

    def setUp(self):
        """A fresh customer per test, so the 'burst' rule from one test cannot affect another."""
        type(self).n += 1
        n = self.n
        self.uname = f"tester{n}"
        self.dev = {"device_id": f"DEV-T{n}", "sim_serial": f"SIM-T{n}"}
        r = self.c.post("/api/auth/register", json={"username": self.uname, "email": f"t{n}@x.in", "name": "Test User",
                                                    "phone": f"98123456{n:02d}", "password": "Test@1234", **self.dev})
        assert r.status_code == 200, r.text
        self.user = r.json()["token"]

    def pay(self, **kw):
        body = {"receiver_vpa": "ramesh.kirana@ybl", "amount": 300, "hour_override": 15,
                "network": {"type": "home_wifi", "ip": "49.36.10.5"}, "lat": 18.5204, "lon": 73.8567, **self.dev}
        body.update(kw)
        return self.c.post("/api/check-payment", json=body, headers=hdr(self.user))

    # ---- auth ----
    def test_protected_routes_need_login(self):
        self.assertEqual(self.c.post("/api/check-payment", json={"amount": 5}).status_code, 401)
        self.assertEqual(self.c.get("/api/admin/stats", headers=hdr(self.user)).status_code, 403)

    def test_register_validation(self):
        base = {"username": "x1", "email": "bad", "name": "A B", "phone": "123", "password": "weak", **self.dev}
        self.assertEqual(self.c.post("/api/auth/register", json=base).status_code, 400)
        dup = {**base, "username": self.uname, "email": "new@x.in", "phone": "9812345678", "password": "Test@1234"}
        self.assertIn("already", self.c.post("/api/auth/register", json=dup).json()["detail"])

    def test_wrong_password_then_lockout(self):
        self.c.post("/api/auth/register", json={"username": "locky", "email": "l@x.in", "name": "Lock Y", "phone": "9822222222",
                                                "password": "Lock@1234", "device_id": "D-L", "sim_serial": "S-L"})
        for _ in range(5):
            r = self.c.post("/api/auth/login", json={"identifier": "locky", "password": "nope"})
        self.assertEqual(r.status_code, 401)
        r = self.c.post("/api/auth/login", json={"identifier": "locky", "password": "Lock@1234"})
        self.assertIn("minute", r.json()["detail"])

    def test_tampered_token_rejected(self):
        bad = self.user[:-3] + ("aaa" if not self.user.endswith("aaa") else "bbb")
        self.assertEqual(self.c.get("/api/auth/me", headers=hdr(bad)).status_code, 401)

    def test_new_device_login_notifies(self):
        r = self.c.post("/api/auth/login", json={"identifier": self.uname, "password": "Test@1234", "device_id": "OTHER-PC"})
        self.assertTrue(r.json()["new_device"])
        notes = self.c.get("/api/me/notifications", headers=hdr(self.user)).json()["items"]
        self.assertTrue(any("new device" in n["title"].lower() for n in notes))

    # ---- payments use the session identity ----
    def test_normal_payment_allowed_and_explained(self):
        j = self.pay().json()
        self.assertEqual(j["decision"], "ALLOW")
        self.assertIn("explain", j)

    def test_cannot_pay_as_someone_else(self):
        j = self.c.post("/api/check-payment", json={"user_id": "U1001", "receiver_vpa": "a@ybl", "amount": 10, **self.dev},
                        headers=hdr(self.user)).json()
        self.assertNotEqual(j.get("receiver_vpa"), None)
        tx = self.c.get("/api/me/transactions", headers=hdr(self.user)).json()
        self.assertTrue(all(t["user_id"] != "U1001" for t in tx))

    def test_attack_lab_stolen_phone_blocked(self):
        j = self.pay(device_id="THIEF", sim_serial="THIEF-SIM", amount=80000).json()
        self.assertEqual(j["decision"], "BLOCK")
        self.assertTrue(any(e["impact"] > 0 for e in j["explain"]))

    def test_daily_limit_and_freeze(self):
        self.assertEqual(self.c.post("/api/me/limit", json={"daily_limit": 100}, headers=hdr(self.user)).status_code, 200)
        self.assertEqual(self.pay(amount=500).json()["decision"], "BLOCK")
        self.c.post("/api/me/limit", json={"daily_limit": 50000}, headers=hdr(self.user))
        self.c.post("/api/me/freeze", json={"value": True}, headers=hdr(self.user))
        j = self.pay(amount=10).json()
        self.assertEqual(j["decision"], "BLOCK")
        self.assertTrue(any("frozen" in r["text"] for r in j["reasons"]))
        self.c.post("/api/me/freeze", json={"value": False}, headers=hdr(self.user))
        self.assertEqual(self.pay(amount=10).json()["decision"], "ALLOW")

    def test_cannot_verify_other_users_tx(self):
        j = self.pay(device_id="NEWDEV-9", amount=200).json()
        self.assertEqual(j["decision"], "VERIFY")
        rahul = self.c.post("/api/auth/login", json={"identifier": "rahul", "password": "Demo@1234"}).json()["token"]
        r = self.c.post("/api/verify-otp", json={"tx_id": j["tx_id"], "otp": "123456"}, headers=hdr(rahul))
        self.assertEqual(r.status_code, 404)
        r = self.c.post("/api/verify-otp", json={"tx_id": j["tx_id"], "otp": "123456"}, headers=hdr(self.user))
        self.assertTrue(r.json()["verified"])

    # ---- admin ----
    def test_admin_stats_users_queue(self):
        self.pay(device_id="THIEF-2", sim_serial="T2", amount=90000)
        st = self.c.get("/api/admin/stats", headers=hdr(self.admin)).json()
        self.assertGreater(st["blocked"], 0)
        self.assertEqual(len(st["hours"]), 24)
        self.assertGreaterEqual(len(self.c.get("/api/admin/users", headers=hdr(self.admin)).json()), 4)
        self.pay(device_id="THIEF-3", sim_serial="T3", amount=95000)
        q = self.c.get("/api/admin/transactions?open_only=true", headers=hdr(self.admin)).json()
        self.assertTrue(q)
        r = self.c.post("/api/admin/review", json={"tx_id": q[0]["tx_id"], "verdict": "fraud"}, headers=hdr(self.admin))
        self.assertEqual(r.json()["review"], "fraud")
        self.assertTrue(self.c.get("/api/ledger/verify", headers=hdr(self.admin)).json()["valid"])

    def test_admin_blacklist_blocks_payment(self):
        self.c.post("/api/admin/blacklist", json={"vpa": "evil.shop@ybl", "reason": "test"}, headers=hdr(self.admin))
        self.assertEqual(self.pay(receiver_vpa="evil.shop@ybl", amount=50).json()["decision"], "BLOCK")
        self.c.delete("/api/admin/blacklist/evil.shop@ybl", headers=hdr(self.admin))
        self.assertNotEqual(self.pay(receiver_vpa="evil.shop@ybl", amount=50).json()["decision"], "BLOCK")

    def test_admin_threshold_change_is_live(self):
        r = self.c.post("/api/admin/settings", json={"thresh_verify": 10, "thresh_block": 20}, headers=hdr(self.admin))
        self.assertEqual(r.json()["thresh_block"], 20)
        bad = self.c.post("/api/admin/settings", json={"thresh_verify": 50, "thresh_block": 40}, headers=hdr(self.admin))
        self.assertEqual(bad.status_code, 400)
        self.c.post("/api/admin/settings", json={"thresh_verify": 35, "thresh_block": 70}, headers=hdr(self.admin))

    def test_admin_freeze_blocks_user(self):
        acc = [u for u in self.c.get("/api/admin/users", headers=hdr(self.admin)).json() if u["username"] == self.uname][0]
        self.c.post(f"/api/admin/users/{acc['id']}/freeze", json={"value": True}, headers=hdr(self.admin))
        self.assertEqual(self.pay(amount=5).json()["decision"], "BLOCK")
        self.c.post(f"/api/admin/users/{acc['id']}/freeze", json={"value": False}, headers=hdr(self.admin))

    def test_admin_cannot_demote_self(self):
        me_id = self.c.get("/api/auth/me", headers=hdr(self.admin)).json()["account"]["id"]
        r = self.c.post(f"/api/admin/users/{me_id}/role", json={"role": "user"}, headers=hdr(self.admin))
        self.assertEqual(r.status_code, 400)

    def test_overview_and_trust(self):
        o = self.c.get("/api/me/overview", headers=hdr(self.user)).json()
        self.assertTrue(0 <= o["trust"]["score"] <= 100)

    # ---- misc ----
    def test_scam_message(self):
        r = scam_text.analyze_message("Sir your KYC will expire, share OTP and install AnyDesk urgently")
        self.assertEqual(r["verdict"], "scam")
        self.assertEqual(scam_text.analyze_message("Lunch at 2pm? I will send the rent on Friday.")["verdict"], "no red flags found")

    def test_event_bus_recent(self):
        bus.publish({"type": "tx", "user_id": "UX"})
        self.assertTrue(any(e.get("user_id") == "UX" for e in bus.recent()))

    # ---- Admin Dashboard & Security Requirements Tests ----
    def test_admin_authorization_enforced(self):
        """Every admin endpoint must reject non-admins with 403 and unauthenticated with 401."""
        endpoints = [
            ("GET", "/api/admin/stats", None),
            ("GET", "/api/admin/users", None),
            ("GET", "/api/admin/transactions", None),
            ("GET", "/api/admin/alerts", None),
            ("GET", "/api/admin/ai-monitoring", None),
            ("POST", "/api/admin/ledger/verify", None),
            ("GET", "/api/admin/audit", None),
            ("GET", "/api/admin/settings", None),
            ("GET", "/api/admin/model", None),
            ("POST", "/api/admin/review", {"tx_id": "TX999", "verdict": "reviewed"}),
        ]
        for method, path, body in endpoints:
            # 1. Unauthenticated (no token) -> 401
            r_noauth = self.c.request(method, path, json=body) if body else self.c.request(method, path)
            self.assertEqual(r_noauth.status_code, 401, f"{path} did not reject unauthenticated with 401")
            # 2. Customer user (non-admin) -> 403
            r_user = self.c.request(method, path, json=body, headers=hdr(self.user)) if body else self.c.request(method, path, headers=hdr(self.user))
            self.assertEqual(r_user.status_code, 403, f"{path} did not reject customer with 403")

    def test_admin_dashboard_overview_stats(self):
        """Dashboard overview displays real counters: total, detected frauds, blocked, QR scans, detection rate."""
        # Create a transaction to ensure fresh DB activity
        self.pay(amount=450)
        st = self.c.get("/api/admin/stats", headers=hdr(self.admin)).json()
        self.assertIn("total_transactions", st)
        self.assertIn("detected_frauds", st)
        self.assertIn("blocked_transactions", st)
        self.assertIn("qr_scans", st)
        self.assertIn("fraud_detection_rate", st)
        self.assertGreaterEqual(st["total_transactions"], 1)
        self.assertGreaterEqual(st["qr_scans"], 1)
        self.assertIsInstance(st["fraud_detection_rate"], (int, float))

    def test_admin_transaction_monitoring_search_filter(self):
        """Transaction monitoring returns searchable, filterable table with required fields."""
        p = self.pay(amount=123.45).json()
        tx_id = p["tx_id"]
        # Search by tx_id
        res = self.c.get(f"/api/admin/transactions?search={tx_id}", headers=hdr(self.admin)).json()
        self.assertTrue(len(res) >= 1)
        item = res[0]
        self.assertEqual(item["tx_id"], tx_id)
        self.assertIn("amount", item)
        self.assertIn("status", item)
        self.assertIn("risk_score", item)
        self.assertIn("ts", item)
        self.assertIn("reasons", item)
        # Filter by decision
        res_allow = self.c.get("/api/admin/transactions?decision=ALLOW", headers=hdr(self.admin)).json()
        self.assertTrue(all(t["decision"] == "ALLOW" for t in res_allow))

    def test_admin_fraud_alerts_and_reviewed_action(self):
        """Fraud alerts display suspicious transactions with severity and allow marking as reviewed."""
        # Trigger suspicious high amount transaction
        j = self.pay(device_id="ALERT-DEV", sim_serial="ALERT-SIM", amount=85000).json()
        self.assertNotEqual(j["decision"], "ALLOW")
        alerts = self.c.get("/api/admin/alerts?status=open", headers=hdr(self.admin)).json()
        self.assertTrue(len(alerts) >= 1)
        matched = [a for a in alerts if a["tx_id"] == j["tx_id"]]
        self.assertTrue(matched)
        alt = matched[0]
        self.assertIn(alt["severity"], ("HIGH", "MEDIUM", "LOW"))
        self.assertTrue(len(alt["reasons"]) >= 1)
        # Mark as reviewed
        rev = self.c.post("/api/admin/review", json={"tx_id": j["tx_id"], "verdict": "reviewed"}, headers=hdr(self.admin)).json()
        self.assertEqual(rev["review"], "reviewed")

    def test_admin_user_activation_deactivation(self):
        """Admins can activate and deactivate user accounts with audit recording."""
        users = self.c.get("/api/admin/users", headers=hdr(self.admin)).json()
        target = [u for u in users if u["username"] == self.uname][0]
        target_id = target["id"]
        # Deactivate
        r = self.c.post(f"/api/admin/users/{target_id}/status", json={"value": False}, headers=hdr(self.admin))
        self.assertEqual(r.status_code, 200)
        # Deactivated user cannot login
        r_login = self.c.post("/api/auth/login", json={"identifier": self.uname, "password": "Test@1234"})
        self.assertEqual(r_login.status_code, 401)
        self.assertIn("disabled", r_login.json()["detail"].lower())
        # Activate again
        r_act = self.c.post(f"/api/admin/users/{target_id}/status", json={"value": True}, headers=hdr(self.admin))
        self.assertEqual(r_act.status_code, 200)
        # Activated user can login
        r_login2 = self.c.post("/api/auth/login", json={"identifier": self.uname, "password": "Test@1234"})
        self.assertEqual(r_login2.status_code, 200)

    def test_admin_ai_monitoring_metrics(self):
        """AI monitoring returns exact model metrics and real database prediction statistics."""
        self.pay(amount=250)
        aim = self.c.get("/api/admin/ai-monitoring", headers=hdr(self.admin)).json()
        self.assertTrue(aim["model_loaded"])
        u_model = aim["model_used"]
        # Verify exact scikit-learn metrics from metrics.json
        self.assertAlmostEqual(u_model["precision"], 0.95, places=2)
        self.assertAlmostEqual(u_model["recall"], 0.79, places=2)
        self.assertAlmostEqual(u_model["f1"], 0.86, places=2)
        self.assertIn("feature_importance", aim)
        self.assertIn("new_receiver", aim["feature_importance"])
        # Verify prediction statistics from DB
        pstats = aim["prediction_statistics"]
        self.assertGreaterEqual(pstats["total_predictions"], 1)
        self.assertIn("average_risk_score", pstats)
        self.assertIn("distribution", pstats)

    def test_admin_ledger_verification_and_audit(self):
        """Admin ledger verification returns integrity result and records in audit trail."""
        r = self.c.post("/api/admin/ledger/verify", headers=hdr(self.admin)).json()
        self.assertTrue(r["valid"])
        self.assertGreaterEqual(r["length"], 1)
        # Check audit trail
        audits = self.c.get("/api/admin/audit?action=ledger_verification", headers=hdr(self.admin)).json()
        self.assertTrue(any(a["action"] == "ledger_verification" for a in audits))


if __name__ == "__main__":
    unittest.main()
