# Sundos Fitness Platform v3

Ready-to-run fitness platform with premium mobile UI, PromptPay QR payments, PWA install support, QR member check-in, admin/staff roles, manual payment approval, and Option B auto-verification hooks.

## Login
- Admin: `admin@gym.com` / `admin123`
- Staff: `staff@gym.com` / `staff123`

## Run locally
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

## Environment variables
Create `.env` or set these in Render:

```bash
SECRET_KEY=change-this
PROMPTPAY_ID=0812345678
PAYMENT_MODE=manual
WEBHOOK_SECRET=change-this-too
GYM_NAME="Sundos Fitness"
```

`PAYMENT_MODE` options:
- `manual`: customer pays by PromptPay QR, staff approves after checking slip/bank app.
- `auto_mock`: demo auto-verification checkbox appears on payment page.
- `webhook`: connect a Slip API / bank provider to `/api/payment/webhook`.

## Option B auto verification
The app includes a secure webhook endpoint:

`POST /api/payment/webhook`

JSON body example:
```json
{"ref":"PAY123ABC","amount":1200,"status":"paid","provider":"your-slip-api"}
```

The request must include header:

`X-Signature: HMAC_SHA256(raw_json_body, WEBHOOK_SECRET)`

When verified, the payment status changes to `auto_verified` and membership is activated automatically.

## PWA mobile install
The app includes:
- `manifest.json`
- service worker cache
- app icon
- standalone mobile display

On iPhone: open in Safari → Share → Add to Home Screen.
On Android: Chrome usually shows Install App.

## Deploy to Render
1. Push this folder to GitHub.
2. Create a new Render Web Service.
3. Use build command: `pip install -r requirements.txt`
4. Use start command: `gunicorn app:app`
5. Add environment variables, especially `SECRET_KEY`, `PROMPTPAY_ID`, and `WEBHOOK_SECRET`.

## Notes before real launch
- Change default admin/staff passwords immediately.
- Use PostgreSQL on Render for production instead of SQLite.
- Connect a real Slip API/bank webhook for true automatic payment verification.

## Version 4 updates

- Member phone number is now collected on public registration and front-desk member creation.
- Admin has a Transactions page at `/admin/transactions`.
- Transactions dashboard shows total approved revenue, today's revenue, current-month revenue, pending value, and all transaction records.
- Main CSV export `/admin/export.csv` now exports transaction data and includes member phone number and price.
- Member CSV export is available at `/admin/members.csv`.

If you already used v3 with an existing SQLite database, v4 includes a lightweight migration that adds the `phone` column automatically.

## Password Reset / Email Setup

Change Password works immediately for logged-in users.

Forgot Password creates a secure reset link that expires in 1 hour. For local testing, the reset link is printed in the terminal. For real email sending, add these to `.env`:

```
BASE_URL=https://your-app-url.onrender.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com
```

If SMTP is not configured, customers should ask staff/admin to help reset while you run from the terminal.

## v4.2 front-desk password recovery update
- Change Password remains available for logged-in users.
- Forgot Password now tells customers to visit the front desk.
- Admin can reset a member password from Members or Member Detail.
- Email reset links are disabled by default for operational security.
