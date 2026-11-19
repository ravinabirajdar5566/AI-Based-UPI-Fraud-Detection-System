from . import admin, auth, blockchain, config, db, device


def seed_demo():
    """Creates two demo users with trusted devices. Safe to call many times."""
    db.init_db()
    blockchain.ensure_genesis()
    admin.load_settings()
    auth.ensure_admin()
    if not db.q("SELECT 1 FROM qr_scans LIMIT 1"):
        db.log_qr_scan("U1001", "upi://pay?pa=chaiwala@oksbi&pn=Sharma%20Chai%20Point&am=40&cu=INR", 0.04, "VERIFIED", ["Verified merchant QR"])
        db.log_qr_scan("U1002", "upi://pay?pa=bigbazaar.pune@icici&pn=Big%20Bazaar&am=1200&cu=INR", 0.02, "VERIFIED", ["Verified merchant QR"])
        db.log_qr_scan("U1001", "upi://pay?pa=refund.helpdesk@ybl&am=3200&cu=INR", 0.85, "FLAGGED", ["Receiver blacklisted", "High risk COLLECT structure"])

    if db.q("SELECT 1 FROM users LIMIT 1"):
        return
    device.register_user("U1001", "Rahul Patil", "9876543210", "XXXX1234 (HDFC)", 18.5204, 73.8567, 1200)
    device.register_device("U1001", "DEV-RAHUL-S23", "SIM-RAHUL-8991", "Rahul's Galaxy S23")
    device.register_user("U1002", "Priya Sharma", "9123456780", "XXXX5678 (SBI)", 19.0760, 72.8777, 3000)
    device.register_device("U1002", "DEV-PRIYA-PIXEL", "SIM-PRIYA-8992", "Priya's Pixel 8")
    for vpa in ["ramesh.kirana@ybl", "chaiwala@oksbi", "mom.patil@oksbi"]:
        db.x("INSERT OR IGNORE INTO beneficiaries(user_id,vpa,first_seen,count) VALUES('U1001',?,?,5)", (vpa, db.now()))
    for vpa in ["bigbazaar.pune@icici", "electricity.mseb@sbi"]:
        db.x("INSERT OR IGNORE INTO beneficiaries(user_id,vpa,first_seen,count) VALUES('U1002',?,?,4)", (vpa, db.now()))
    # demo logins for the two demo customers (password: Demo@1234)
    for uname, mail, name, uid in [("rahul", "rahul@demo.in", "Rahul Patil", "U1001"),
                                   ("priya", "priya@demo.in", "Priya Sharma", "U1002")]:
        if not db.q("SELECT 1 FROM accounts WHERE username=?", (uname,)):
            auth.create_account(uname, mail, name, "Demo@1234", "user", uid)
