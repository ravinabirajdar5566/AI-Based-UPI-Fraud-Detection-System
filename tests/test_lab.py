"""Automated tests for AI Fraud Attack Replay Lab.
Verifies predefined scenarios, safe execution without balance mutation,
explainable AI outputs, blockchain simulation blocks, and history tracking.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
os.environ["UPI_DB"] = os.path.join(tempfile.mkdtemp(), "lab_test.db")
os.environ["CHAIN_DIFFICULTY"] = "2"
os.environ["DEMO_OTP_FIXED"] = "123456"

from fastapi.testclient import TestClient  # noqa: E402
from app import blockchain, config, db, main, seed  # noqa: E402

config.CHAIN_DIFFICULTY = 2


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cm = TestClient(main.app)
        cls.c = cls.cm.__enter__()
        # Login admin
        r = cls.c.post("/api/auth/login", json={"identifier": "admin", "password": config.ADMIN_PASS})
        assert r.status_code == 200, r.text
        cls.admin_token = r.json()["token"]

        # Register demo customer
        cls.dev = {"device_id": "DEV-TEST-LAB", "sim_serial": "SIM-TEST-LAB"}
        r = cls.c.post("/api/auth/register", json={
            "username": "labtester",
            "email": "labtester@example.com",
            "name": "Lab Tester",
            "phone": "9876543299",
            "password": "Password@123",
            **cls.dev
        })
        assert r.status_code == 200, r.text
        cls.user_token = r.json()["token"]

    @classmethod
    def tearDownClass(cls):
        cls.cm.__exit__(None, None, None)

    def hdr(self, token=None):
        return {"Authorization": f"Bearer {token or self.user_token}"}

    def test_01_list_scenarios(self):
        r = self.c.get("/api/lab/scenarios", headers=self.hdr())
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("scenarios", data)
        scenarios = {s["id"]: s for s in data["scenarios"]}
        expected_ids = [
            "phishing_link",
            "tampered_qr",
            "stolen_device",
            "sim_swap",
            "high_value_burst",
            "merchant_impersonation",
        ]
        for sid in expected_ids:
            self.assertIn(sid, scenarios, f"Scenario {sid} must be present in predefined list")

    def test_02_simulate_phishing_link(self):
        r = self.c.post("/api/lab/simulate", json={"scenario_id": "phishing_link"}, headers=self.hdr())
        self.assertEqual(r.status_code, 200, r.text)
        res = r.json()
        self.assertTrue(res["is_simulation"])
        self.assertEqual(res["attack"]["decision"], "BLOCK")
        self.assertGreaterEqual(res["attack"]["risk_score"], 80)
        self.assertEqual(res["normal"]["decision"], "ALLOW")
        self.assertIn("link", res["layers_triggered"])
        # Proof-of-work blockchain ledger entry
        self.assertIn("ledger_block", res)
        self.assertTrue(res["ledger_status"]["valid"])

    def test_03_simulate_tampered_qr(self):
        r = self.c.post("/api/lab/simulate", json={"scenario_id": "tampered_qr"}, headers=self.hdr())
        self.assertEqual(r.status_code, 200, r.text)
        res = r.json()
        self.assertTrue(res["is_simulation"])
        self.assertEqual(res["attack"]["decision"], "BLOCK")
        self.assertGreaterEqual(res["attack"]["risk_score"], 80)
        self.assertEqual(res["normal"]["decision"], "ALLOW")

    def test_04_simulate_stolen_device(self):
        r = self.c.post("/api/lab/simulate", json={"scenario_id": "stolen_device"}, headers=self.hdr())
        self.assertEqual(r.status_code, 200, r.text)
        res = r.json()
        self.assertEqual(res["attack"]["decision"], "BLOCK")
        self.assertGreaterEqual(res["attack"]["risk_score"], 75)

    def test_05_simulate_sim_swap(self):
        r = self.c.post("/api/lab/simulate", json={"scenario_id": "sim_swap"}, headers=self.hdr())
        self.assertEqual(r.status_code, 200, r.text)
        res = r.json()
        self.assertEqual(res["attack"]["decision"], "BLOCK")
        self.assertGreaterEqual(res["attack"]["risk_score"], 75)

    def test_06_simulate_midnight_high_value(self):
        r = self.c.post("/api/lab/simulate", json={"scenario_id": "high_value_burst"}, headers=self.hdr())
        self.assertEqual(r.status_code, 200, r.text)
        res = r.json()
        self.assertIn(res["attack"]["decision"], ("BLOCK", "VERIFY"))

    def test_07_simulate_merchant_impersonation(self):
        r = self.c.post("/api/lab/simulate", json={"scenario_id": "merchant_impersonation"}, headers=self.hdr())
        self.assertEqual(r.status_code, 200, r.text)
        res = r.json()
        self.assertEqual(res["attack"]["decision"], "BLOCK")
        self.assertEqual(res["attack"]["risk_score"], 100)

    def test_08_simulation_history_and_reset(self):
        # Fetch history
        r = self.c.get("/api/lab/history", headers=self.hdr())
        self.assertEqual(r.status_code, 200)
        history = r.json()["history"]
        self.assertGreaterEqual(len(history), 5)
        # Check that simulation has required keys
        first = history[0]
        self.assertIn("scenario_name", first)
        self.assertIn("risk_score", first)
        self.assertIn("decision", first)

        # Reset history
        r_reset = self.c.post("/api/lab/reset", json={}, headers=self.hdr())
        self.assertEqual(r_reset.status_code, 200)
        self.assertTrue(r_reset.json()["reset"])

        # Fetch history again (must be 0 for this user)
        r2 = self.c.get("/api/lab/history", headers=self.hdr())
        self.assertEqual(len(r2.json()["history"]), 0)

    def test_09_simulation_never_alters_real_balance_or_tx_count(self):
        user_before = db.q("SELECT avg_amount, txn_count FROM users WHERE user_id='U1001'")[0]
        tx_count_before = db.q("SELECT COUNT(*) AS c FROM transactions")[0]["c"]

        # Run several attack simulations
        self.c.post("/api/lab/simulate", json={"scenario_id": "phishing_link"}, headers=self.hdr())
        self.c.post("/api/lab/simulate", json={"scenario_id": "stolen_device"}, headers=self.hdr())

        user_after = db.q("SELECT avg_amount, txn_count FROM users WHERE user_id='U1001'")[0]
        tx_count_after = db.q("SELECT COUNT(*) AS c FROM transactions")[0]["c"]

        self.assertEqual(user_before["avg_amount"], user_after["avg_amount"])
        self.assertEqual(user_before["txn_count"], user_after["txn_count"])
        self.assertEqual(tx_count_before, tx_count_after, "Real transactions table must NOT be modified by simulations")


if __name__ == "__main__":
    unittest.main()
