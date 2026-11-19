"""Run:  python -m unittest discover -s tests -v     (from the project root)"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
_tmp = tempfile.mkdtemp()
os.environ["UPI_DB"] = os.path.join(_tmp, "test.db")
os.environ["CHAIN_DIFFICULTY"] = "2"
os.environ["DEMO_OTP_FIXED"] = "123456"

from app import blockchain, config, db, qr_scanner, seed, service, url_scanner, network_check  # noqa: E402

config.CHAIN_DIFFICULTY = 2  # faster tests

GOOD = dict(user_id="U1001", phone="9876543210", device_id="DEV-RAHUL-S23", sim_serial="SIM-RAHUL-8991",
            lat=18.5204, lon=73.8567, network={"type": "home_wifi", "ip": "49.36.10.5"}, hour_override=15)


def pay(**kw):
    p = dict(GOOD)
    p.update(kw)
    return service.check_payment(p)


class Base(unittest.TestCase):
    def setUp(self):
        db.reset_all()
        seed.seed_demo()


class TestPayments(Base):
    def test_normal_payment_allowed(self):
        r = pay(receiver_vpa="ramesh.kirana@ybl", amount=500)
        self.assertEqual(r["decision"], "ALLOW", r)
        self.assertEqual(r["status"], "COMPLETED")

    def test_new_device_big_amount_blocked(self):
        r = pay(device_id="DEV-UNKNOWN", receiver_vpa="ramesh.kirana@ybl", amount=80000)
        self.assertEqual(r["decision"], "BLOCK", r)

    def test_new_device_small_amount_needs_verification(self):
        r = pay(device_id="DEV-NEW", receiver_vpa="ramesh.kirana@ybl", amount=300)
        self.assertEqual(r["decision"], "VERIFY", r)

    def test_sim_swap_blocked(self):
        r = pay(sim_serial="SIM-OTHER", receiver_vpa="ramesh.kirana@ybl", amount=500)
        self.assertEqual(r["decision"], "BLOCK", r)

    def test_wrong_phone_blocked(self):
        r = pay(phone="9000000000", receiver_vpa="ramesh.kirana@ybl", amount=200)
        self.assertEqual(r["decision"], "BLOCK")

    def test_unknown_user_blocked(self):
        r = pay(user_id="NOPE", receiver_vpa="a@ybl", amount=200)
        self.assertEqual(r["decision"], "BLOCK")

    def test_blacklisted_receiver_blocked(self):
        r = pay(receiver_vpa="refund.helpdesk@ybl", amount=100)
        self.assertEqual(r["decision"], "BLOCK")
        self.assertEqual(r["risk_score"], 100)

    def test_new_receiver_normal_amount_ok_but_scored(self):
        r = pay(receiver_vpa="friend.new@oksbi", amount=800)
        self.assertIn(r["decision"], ("ALLOW", "VERIFY"))

    def test_big_amount_new_receiver_night_verify_or_block(self):
        r = pay(receiver_vpa="friend.new@oksbi", amount=20000, hour_override=2)
        self.assertIn(r["decision"], ("VERIFY", "BLOCK"), r)

    def test_open_wifi_raises_risk(self):
        a = pay(receiver_vpa="friend.new@oksbi", amount=4000, network={"type": "home_wifi"})
        b = pay(receiver_vpa="friend.new@oksbi", amount=4000, network={"type": "public_wifi_open", "vpn": True})
        self.assertGreater(b["risk_score"], a["risk_score"])

    def test_malicious_ip_blocked(self):
        r = pay(receiver_vpa="ramesh.kirana@ybl", amount=200, network={"type": "mobile_data", "ip": "203.0.113.7"})
        self.assertEqual(r["decision"], "BLOCK")

    def test_far_location_raises_risk(self):
        near = pay(receiver_vpa="friend.new@oksbi", amount=5000)
        far = pay(receiver_vpa="friend.new@oksbi", amount=5000, lat=28.61, lon=77.2)
        self.assertGreater(far["risk_score"], near["risk_score"])

    def test_burst_of_payments(self):
        last = None
        for _ in range(6):
            last = pay(receiver_vpa="friend.new@oksbi", amount=900)
        self.assertGreater(last["risk_score"], 30, last)


class TestQR(Base):
    def test_valid_verified_merchant(self):
        q = "upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40&cu=INR"
        r = pay(receiver_vpa="chaiwala@oksbi", amount=40, qr_payload=q)
        self.assertEqual(r["decision"], "ALLOW", r)

    def test_amount_tampered_qr(self):
        q = "upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40"
        r = pay(receiver_vpa="chaiwala@oksbi", amount=4000, qr_payload=q)
        self.assertNotEqual(r["decision"], "ALLOW")

    def test_vpa_mismatch_with_qr_blocked(self):
        q = "upi://pay?pa=scam.person@ybl&pn=Chai"
        r = pay(receiver_vpa="chaiwala@oksbi", amount=40, qr_payload=q)
        self.assertEqual(r["decision"], "BLOCK")

    def test_name_mismatch(self):
        res = qr_scanner.analyze_qr("upi://pay?pa=chaiwala@oksbi&pn=Random%20Guy&am=40", 40)
        self.assertGreaterEqual(res["risk"], 0.7)

    def test_collect_request(self):
        res = qr_scanner.analyze_qr("upi://collect?pa=x.y@ybl&pn=Y&am=100", 100)
        self.assertGreaterEqual(res["risk"], 0.8)

    def test_web_link_qr(self):
        res = qr_scanner.analyze_qr("http://pay-now.xyz/x")
        self.assertGreaterEqual(res["risk"], 0.7)

    def test_decode_image_roundtrip(self):
        text = "upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40"
        png = qr_scanner.generate_qr_png(text)
        self.assertEqual(qr_scanner.decode_qr_image(png), text)

    def test_qr_only_receiver(self):
        q = "upi://pay?pa=ramesh.kirana@ybl&pn=Ramesh%20Kirana%20Store&am=100"
        r = pay(amount=100, qr_payload=q)
        self.assertEqual(r["receiver_vpa"], "ramesh.kirana@ybl")


class TestURL(unittest.TestCase):
    def test_phishing(self):
        r = url_scanner.scan_url("http://paytm-kyc-update.xyz/verify?otp=1")
        self.assertEqual(r["verdict"], "malicious")

    def test_brand_impersonation(self):
        r = url_scanner.scan_url("https://phonepe-secure-login.in/pay")
        self.assertGreaterEqual(r["risk"], 0.6)

    def test_official_ok(self):
        r = url_scanner.scan_url("https://www.phonepe.com/business")
        self.assertEqual(r["verdict"], "safe")

    def test_ip_url(self):
        self.assertGreaterEqual(url_scanner.scan_url("http://192.168.4.4:8080/pay")["risk"], 0.6)

    def test_payment_link_blocked_in_flow(self):
        db.reset_all(); seed.seed_demo()
        r = pay(receiver_vpa="ramesh.kirana@ybl", amount=500, payment_link="http://sbi-kyc-verify.icu/pay")
        self.assertEqual(r["decision"], "BLOCK")


class TestNetwork(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(network_check.check_network(None, "home_wifi")["risk"], 0.0)
        self.assertGreater(network_check.check_network(None, "public_wifi_open")["risk"], 0.4)
        self.assertGreater(network_check.check_network("198.51.100.9", "mobile_data")["risk"], 0.7)


class TestOTPAndLedger(Base):
    def _pending(self):
        r = pay(device_id="DEV-NEW", receiver_vpa="ramesh.kirana@ybl", amount=300)
        self.assertEqual(r["decision"], "VERIFY")
        return r

    def test_otp_success(self):
        r = self._pending()
        self.assertEqual(r["demo_otp"], "123456")
        v = service.verify_otp(r["tx_id"], "123456")
        self.assertTrue(v["verified"])
        self.assertEqual(v["status"], "COMPLETED")

    def test_otp_wrong_three_times_blocks(self):
        r = self._pending()
        for _ in range(2):
            self.assertFalse(service.verify_otp(r["tx_id"], "000000")["verified"])
        v = service.verify_otp(r["tx_id"], "000000")
        self.assertEqual(v["status"], "BLOCKED_OTP_FAILED")

    def test_ledger_valid_then_tamper_detected(self):
        pay(receiver_vpa="ramesh.kirana@ybl", amount=100)
        pay(receiver_vpa="refund.helpdesk@ybl", amount=100)
        self.assertTrue(blockchain.verify_chain()["valid"])
        idx = blockchain.tamper_demo()
        res = blockchain.verify_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["broken_at"], idx)

    def test_ledger_has_no_personal_data(self):
        r = pay(receiver_vpa="ramesh.kirana@ybl", amount=100)
        blob = str(blockchain.get_chain())
        for secret in ["9876543210", "ramesh.kirana", "Rahul", "XXXX1234"]:
            self.assertNotIn(secret, blob)

    def test_report_fraud_feedback_and_autoblacklist(self):
        r = pay(receiver_vpa="friend.new@oksbi", amount=300)
        service.report_fraud("U1001", tx_id=r["tx_id"])
        service.report_fraud("U1002", vpa="friend.new@oksbi")
        out = service.report_fraud("U1002", vpa="friend.new@oksbi")
        self.assertTrue(out["auto_blacklisted"])
        self.assertEqual(pay(receiver_vpa="friend.new@oksbi", amount=100)["decision"], "BLOCK")
        row = db.q("SELECT label FROM transactions WHERE tx_id=?", (r["tx_id"],))[0]
        self.assertEqual(row["label"], 1)


if __name__ == "__main__":
    unittest.main()
