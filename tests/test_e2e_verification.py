import unittest
from backend.app import main, config
from fastapi.testclient import TestClient

class E2EVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cm = TestClient(main.app)
        cls.c = cls.cm.__enter__()
        r_adm = cls.c.post('/api/auth/login', json={'identifier': 'admin', 'password': config.ADMIN_PASS})
        cls.adm_tok = r_adm.json()['token']
        cls.adm_hdr = {'Authorization': 'Bearer ' + cls.adm_tok}

        r_usr = cls.c.post('/api/auth/login', json={'identifier': 'rahul', 'password': 'Demo@1234'})
        cls.usr_tok = r_usr.json()['token']
        cls.usr_hdr = {'Authorization': 'Bearer ' + cls.usr_tok}

    @classmethod
    def tearDownClass(cls):
        cls.cm.__exit__(None, None, None)

    def test_01_logins(self):
        self.assertTrue(bool(self.adm_tok))
        self.assertTrue(bool(self.usr_tok))

    def test_02_payment_verification(self):
        # Genuine payment
        r1 = self.c.post('/api/check-payment', json={'receiver_vpa': 'ramesh.kirana@ybl', 'amount': 300, 'device_id': 'DEV-RAHUL-S23', 'sim_serial': 'SIM-RAHUL-8991'}, headers=self.usr_hdr)
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json()['decision'], 'ALLOW')

        # Fraudulent payment (stolen hardware)
        r2 = self.c.post('/api/check-payment', json={'receiver_vpa': 'mule@ybl', 'amount': 80000, 'device_id': 'DEV-THIEF', 'sim_serial': 'SIM-THIEF'}, headers=self.usr_hdr)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()['decision'], 'BLOCK')

    def test_03_qr_scanner(self):
        r = self.c.post('/api/scan-qr-text', json={'payload': 'upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40&cu=INR'}, headers=self.usr_hdr)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['verified_merchant'])

    def test_04_scam_scanner(self):
        r_scam = self.c.post('/api/scan-message', json={'text': 'Dear customer, your bank KYC will expire today. Update immediately: http://sbi-kyc-verify.icu/update'}, headers=self.usr_hdr)
        self.assertEqual(r_scam.status_code, 200)
        self.assertGreaterEqual(r_scam.json()['risk'], 0.7)

        r_url = self.c.post('/api/scan-url', json={'url': 'http://paytm-kyc-update.xyz/verify'}, headers=self.usr_hdr)
        self.assertEqual(r_url.status_code, 200)
        self.assertEqual(r_url.json()['verdict'], 'malicious')

    def test_05_network_check(self):
        r = self.c.post('/api/network-check', json={'ip': '203.0.113.7', 'type': 'public_wifi_open', 'vpn': True, 'tls_ok': False}, headers=self.usr_hdr)
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.json()['risk'], 0.8)

    def test_06_panic_freeze(self):
        r = self.c.post('/api/me/freeze', json={'value': True}, headers=self.usr_hdr)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['frozen'])

        # Payment while frozen is blocked
        r_pay = self.c.post('/api/check-payment', json={'receiver_vpa': 'ramesh.kirana@ybl', 'amount': 100, 'device_id': 'DEV-RAHUL-S23', 'sim_serial': 'SIM-RAHUL-8991'}, headers=self.usr_hdr)
        self.assertEqual(r_pay.json()['decision'], 'BLOCK')

        # Unfreeze
        self.c.post('/api/me/freeze', json={'value': False}, headers=self.usr_hdr)

    def test_07_admin_and_ledger(self):
        r_stat = self.c.get('/api/admin/stats', headers=self.adm_hdr)
        self.assertEqual(r_stat.status_code, 200)

        r_ledg = self.c.post('/api/admin/ledger/verify', headers=self.adm_hdr)
        self.assertEqual(r_ledg.status_code, 200)
        self.assertTrue(r_ledg.json()['valid'])

    def test_08_attack_lab(self):
        r = self.c.post('/api/lab/simulate', json={'scenario_id': 'phishing_link'}, headers=self.usr_hdr)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['attack']['decision'], 'BLOCK')

if __name__ == '__main__':
    unittest.main()
