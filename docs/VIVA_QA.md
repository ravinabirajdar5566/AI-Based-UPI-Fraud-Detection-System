# Likely viva / judge questions (simple English)

**1. What problem does your project solve?**
Most fraud systems look only at the amount. Real UPI fraud mixes many tricks: stolen phone, SIM swap, fake QR, phishing link, unsafe network, scam receiver. Our system checks all of them and gives one risk score with reasons.

**2. How does the AI part work?**
A Random Forest reads 13 features (amount vs your average, hour, new receiver, new device, SIM mismatch, payments in last hour, distance from home, network risk, QR risk, link risk, reports on receiver) and outputs a fraud probability. This is combined with the layer scores and rules.

**3. Why combine ML with rules?**
ML finds patterns but can miss a clear case (blacklisted receiver). Rules give certainty and explainability. Hard rules can only raise the score, never lower it.

**4. Which dataset did you use? Is it real?**
Synthetic data made by `ml/generate_data.py`, because real UPI data is private. It has 4% fraud and noisy labels. The code accepts PaySim/Kaggle data once converted to the same columns.

**5. Why not use accuracy?**
Fraud is rare. A model that says "safe" every time gets about 96% accuracy and catches no fraud. We use precision, recall, F1 and PR-AUC. We used class weights to handle the imbalance.

**6. What are your results?**
Precision 0.95, recall 0.79, F1 0.86, ROC-AUC 0.89 on synthetic test data. The Random Forest beat the Logistic Regression baseline on precision (0.95 vs about 0.58).

**7. Why blockchain? A normal database also stores records.**
A normal database can be edited quietly by an admin. In our chain every block holds the previous block's hash, so changing an old record breaks all later blocks and `verify_chain()` shows it (try the "Simulate tampering" button). In a real deployment banks would each hold a copy, so no single party can rewrite fraud history.

**8. What do you store on the blockchain?**
Only a salted transaction hash, timestamp, risk score and status. Never account number, PIN, OTP, phone number or name.

**9. Is device/SIM binding real?**
It is simulated. Real UPI already binds the SIM through SMS verification with the bank. We store salted hashes of phone, device ID and SIM, and compare them at payment time.

**10. Can you really detect unsafe Wi-Fi?**
Not fully, no app can. We check what is observable: IP blacklists, Tor/VPN, network type (open vs secured), and whether TLS is valid.

**11. How do you detect a fake QR?**
We decode it and check UPI ID format, blacklist, scam words, whether the name matches a verified merchant, whether the amount inside the QR matches what you entered, whether the typed UPI ID matches the QR, and whether it is a "collect" request.

**12. How do you explain a decision to the user?**
The "Why?" list shows exact reasons, for example "New receiver + 8.2x your usual amount + late-night payment".

**13. What if the system blocks a genuine payment (false positive)?**
Medium risk goes to OTP, not a block. Only high risk blocks. Thresholds (35 / 70) are in `config.py` and can be tuned using the precision/recall trade-off.

**14. How does it improve over time?**
Users report fraud → the receiver gets a risk bump (3 reports auto-blacklist the UPI ID) and the transaction becomes a label-1 training row. `python ml/train.py --with-feedback` retrains.

**15. What are the limitations?**
Synthetic data, simulated SIM binding, heuristic link scanning, demo blacklists, SQLite, OTP shown on screen in demo mode. (Listed in README.)

**16. Future work?**
Real data and a bank API, SHAP explanations, live Safe Browsing lookups, WebAuthn biometric, graph analysis of mule accounts, anchoring the ledger on a public Ethereum testnet.

## New in v2

**How does the live part work?**
The server keeps a small event bus. When a payment is checked, the result is published to it, and every open browser holds a Server-Sent Events connection (`/api/live/stream`) that receives it instantly. Admins receive all events; a customer only receives their own.

**How do you explain an AI decision to the user?**
We use a what-if method. For each signal (new device, unusual amount, risky network...) we reset just that signal to "normal", re-run the entire decision (model, layers, rules, overrides) and measure how far the score drops. A 30-point drop means that signal added 30 points. It works for any model, and it explains the final score, not only the ML part.

**How is the admin's work used by the AI?**
In the review queue the admin marks a held payment as fraud or genuine. That sets the training label and flags the receiver. "Retrain with feedback" runs `ml/train.py --with-feedback` and hot-loads the new model without restarting.

**How are passwords and sessions protected?**
Passwords are hashed with PBKDF2-SHA256 (200,000 rounds, random salt). Sessions are HMAC-signed tokens with an expiry. Five wrong passwords lock the account for five minutes. The role is read from the database on every request, so disabling an account works immediately. The payment API ignores any user ID sent by the browser and uses the one from the session.

**What if the phone is stolen?**
The thief's device is unknown, so payments need verification, high amounts are blocked, and the owner can press Panic freeze from another device. Daily limits cap the loss.

**What is not real?**
Device and SIM IDs come from the browser (real UPI binds the SIM through the bank), OTP is shown on screen in demo mode, and the model is trained on synthetic data.
