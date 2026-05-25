import os
import csv
import uuid
import hmac
import hashlib
import smtplib
from email.message import EmailMessage
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from functools import wraps

import qrcode
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

PROMPTPAY_ID = os.getenv('PROMPTPAY_ID', '0917853662')
PAYMENT_MODE = os.getenv('PAYMENT_MODE', 'manual')  # manual, auto_mock, webhook
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', 'change-webhook-secret')
GYM_NAME = os.getenv('GYM_NAME', 'OFFWHITE')
BASE_URL = os.getenv('BASE_URL')
SMTP_HOST = os.getenv('SMTP_HOST')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USER or 'no-reply@fitness.local')

db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

PLANS = {
    'day': {'name': 'Day Pass', 'price': 50, 'days': 1},
    'monthly': {'name': 'Monthly Membership', 'price': 700, 'days': 30},
    'quarterly': {'name': 'Quarterly Membership', 'price': 2000, 'days': 90},
}



class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    phone = db.Column(db.String(30))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='member') # member, staff, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    membership_type = db.Column(db.String(30))
    membership_expiry = db.Column(db.DateTime)
    member_qr_token = db.Column(db.String(80), unique=True, default=lambda: uuid.uuid4().hex)
    payments = db.relationship('Payment', backref='user', lazy=True)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ref = db.Column(db.String(30), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    plan = db.Column(db.String(30), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending, approved, rejected, auto_verified
    method = db.Column(db.String(30), default='promptpay')
    slip_note = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    verified_payload = db.Column(db.Text)

class CheckIn(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    method = db.Column(db.String(30), default='qr')
    result = db.Column(db.String(30), default='valid')
    muscle_group = db.Column(db.String(50))
    note = db.Column(db.String(255))

# ---------- PromptPay EMV QR ----------
def _tlv(tag, value):
    return f"{tag}{len(value):02d}{value}"

def _crc16_ccitt(data: str) -> str:
    crc = 0xFFFF
    for ch in data.encode('ascii'):
        crc ^= ch << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return f"{crc:04X}"

def _format_promptpay_id(pp_id: str):
    raw = ''.join(c for c in pp_id if c.isdigit())
    if len(raw) == 10:  # mobile phone
        return '0066' + raw[1:]
    return raw

def promptpay_payload(promptpay_id: str, amount: float):
    aid = _tlv('00', 'A000000677010111')
    target = _tlv('01', _format_promptpay_id(promptpay_id))
    merchant = _tlv('29', aid + target)
    payload = (
        _tlv('00', '01') +
        _tlv('01', '12') +
        merchant +
        _tlv('53', '764') +
        _tlv('54', f"{amount:.2f}") +
        _tlv('58', 'TH') +
        _tlv('59', 'FITNESS') +
        _tlv('60', 'BANGKOK')
    )
    to_crc = payload + '6304'
    return to_crc + _crc16_ccitt(to_crc)

def qr_data_uri(text):
    img = qrcode.make(text)
    buf = BytesIO()
    img.save(buf, format='PNG')
    import base64
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()

def activate_membership(user, plan_key):
    plan = PLANS[plan_key]
    start = datetime.utcnow()
    if user.membership_expiry and user.membership_expiry > start:
        start = user.membership_expiry
    user.membership_type = plan['name']
    user.membership_expiry = start + timedelta(days=plan['days'])
    user.member_qr_token = uuid.uuid4().hex


def create_approved_payment(user, plan_key, method='frontdesk', slip_note=''):
    """Record an approved transaction and return the payment."""
    plan = PLANS[plan_key]
    payment = Payment(
        ref='PAY' + uuid.uuid4().hex[:10].upper(),
        user_id=user.id,
        plan=plan_key,
        amount=plan['price'],
        status='approved',
        method=method,
        slip_note=slip_note,
        approved_at=datetime.utcnow()
    )
    db.session.add(payment)
    return payment

# ---------- Auth helpers ----------
def current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None

@app.context_processor
def inject_globals():
    return dict(current_user=current_user(), gym_name=GYM_NAME, payment_mode=PAYMENT_MODE, plans=PLANS)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

def staff_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or u.role not in ['staff', 'admin']:
            flash('Staff access required.', 'danger')
            return redirect(url_for('home'))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or u.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
        return fn(*args, **kwargs)
    return wrapper


def build_external_url(endpoint, **values):
    """Build a public reset URL for localhost or deployed hosting."""
    if BASE_URL:
        return BASE_URL.rstrip('/') + url_for(endpoint, **values)
    return url_for(endpoint, _external=True, **values)

def send_password_reset_email(to_email, reset_link):
    """Send reset email if SMTP is configured; otherwise print link in terminal."""
    if SMTP_HOST and SMTP_USER and SMTP_PASSWORD:
        msg = EmailMessage()
        msg['Subject'] = f'{GYM_NAME} password reset'
        msg['From'] = SMTP_FROM
        msg['To'] = to_email
        msg.set_content(
            f"Reset your {GYM_NAME} password here:\n\n{reset_link}\n\n"
            "This link expires in 1 hour. If you did not request this, you can ignore this email."
        )
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
    else:
        print('\nPASSWORD RESET LINK for', to_email, ':')
        print(reset_link)
        print('Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD, SMTP_FROM to send this by email.\n')

# ---------- Routes ----------

MUSCLE_GROUPS = ["Chest", "Back", "Legs", "Shoulders", "Arms", "Core", "Cardio", "Full Body", "Mobility"]

def record_checkin(user, method="qr", result="valid", muscle_group=None, note=None):
    """Create one check-in record with optional workout details."""
    checkin = CheckIn(
        user_id=user.id,
        method=method,
        result=result,
        muscle_group=muscle_group,
        note=note
    )
    db.session.add(checkin)
    db.session.commit()
    return checkin

def get_user_by_qr_or_id(token):
    """Find user from QR token first, then numeric member id."""
    token = (token or "").strip()
    if not token:
        return None
    user = User.query.filter_by(member_qr_token=token).first()
    if user:
        return user
    if token.isdigit():
        return User.query.get(int(token))
    return None

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form.get('phone','').strip()
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))
        user = User(name=name, email=email, phone=phone, password_hash=generate_password_hash(password))
        db.session.add(user); db.session.commit()
        session['user_id'] = user.id
        flash('Account created. Choose a plan to activate membership.', 'success')
        return redirect(url_for('buy'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('admin_dashboard' if user.role in ['admin','staff'] else 'dashboard'))
        flash('Invalid login.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); flash('Logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = current_user()
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if not check_password_hash(user.password_hash, current_pw):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))
        if len(new_pw) < 8:
            flash('New password must be at least 8 characters.', 'danger')
            return redirect(url_for('change_password'))
        if new_pw != confirm_pw:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))
        user.password_hash = generate_password_hash(new_pw)
        db.session.commit()
        flash('Password updated successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # Front-desk recovery policy: customers do not reset passwords by email.
    # They should visit the front desk, where admin can verify identity and reset it.
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Email reset links are disabled for front-desk recovery mode.
    flash('Password reset by email is disabled. Please contact the front desk.', 'info')
    return redirect(url_for('forgot_password'))

@app.route('/admin/reset-password/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if len(new_pw) < 8:
            flash('New password must be at least 8 characters.', 'danger')
            return redirect(request.url)
        if new_pw != confirm_pw:
            flash('New passwords do not match.', 'danger')
            return redirect(request.url)
        user.password_hash = generate_password_hash(new_pw)
        db.session.commit()
        flash(f'Password reset successfully for {user.name}.', 'success')
        return redirect(url_for('member_detail', user_id=user.id))
    return render_template('admin_reset_password.html', user=user)

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    qr = qr_data_uri(user.member_qr_token) if user.membership_expiry else None
    pending = Payment.query.filter_by(user_id=user.id, status='pending').order_by(Payment.created_at.desc()).all()
    return render_template('dashboard.html', user=user, qr=qr, pending=pending, now=datetime.utcnow())

@app.route('/buy', methods=['GET','POST'])
@login_required
def buy():
    if request.method == 'POST':
        plan_key = request.form['plan']
        if plan_key not in PLANS:
            flash('Invalid plan.', 'danger'); return redirect(url_for('buy'))
        p = Payment(ref='PAY' + uuid.uuid4().hex[:10].upper(), user_id=current_user().id, plan=plan_key, amount=PLANS[plan_key]['price'])
        db.session.add(p); db.session.commit()
        return redirect(url_for('payment_page', ref=p.ref))
    return render_template('buy.html')

@app.route('/payment/<ref>', methods=['GET','POST'])
@login_required
def payment_page(ref):
    p = Payment.query.filter_by(ref=ref, user_id=current_user().id).first_or_404()
    if request.method == 'POST':
        p.slip_note = request.form.get('slip_note','')
        if PAYMENT_MODE == 'auto_mock' and request.form.get('mock_auto') == '1':
            p.status = 'auto_verified'; p.approved_at = datetime.utcnow(); p.verified_payload = 'Mock auto verification successful.'
            activate_membership(p.user, p.plan)
            flash('Payment auto-verified in demo mode. Membership activated.', 'success')
        else:
            flash('Payment submitted. Staff will verify and approve it.', 'success')
        db.session.commit()
        return redirect(url_for('dashboard'))
    payload = promptpay_payload(PROMPTPAY_ID, p.amount)
    qr = qr_data_uri(payload)
    return render_template('payment.html', p=p, qr=qr, pp_id=PROMPTPAY_ID)

@app.route('/admin')
@staff_required
def admin_dashboard():
    users = User.query.count()
    active = User.query.filter(User.membership_expiry > datetime.utcnow()).count()
    pending = Payment.query.filter_by(status='pending').order_by(Payment.created_at.desc()).all()
    recent_checkins = CheckIn.query.order_by(CheckIn.created_at.desc()).limit(10).all()
    return render_template('admin.html', users=users, active=active, pending=pending, recent_checkins=recent_checkins)

@app.route('/admin/members')
@staff_required
def members():
    q = request.args.get('q','').strip()
    query = User.query
    if q:
        query = query.filter((User.name.ilike(f'%{q}%')) | (User.email.ilike(f'%{q}%')) | (User.phone.ilike(f'%{q}%')))
    return render_template('members.html', members=query.order_by(User.created_at.desc()).all(), q=q, now=datetime.utcnow())

@app.route('/member/<int:user_id>')
@staff_required
def member_detail(user_id):

    user = User.query.get_or_404(user_id)

    payments = Payment.query.filter_by(user_id=user.id)\
        .order_by(Payment.created_at.desc())\
        .all()

    checkins = CheckIn.query.filter_by(user_id=user.id)\
        .order_by(CheckIn.created_at.desc())\
        .all()

    print("CHECKINS FOUND:", checkins)

    last_checkin = checkins[0] if checkins else None

    return render_template(
        'member_detail.html',
        user=user,
        payments=payments,
        plans=PLANS,
        checkins=checkins,
        last_checkin=last_checkin,
        now=datetime.utcnow()
    )
@app.route('/admin/add-member', methods=['GET','POST'])
@staff_required
def add_member():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('add_member'))

        user = User(
            name=request.form['name'].strip(),
            email=email,
            phone=request.form.get('phone','').strip(),
            password_hash=generate_password_hash(request.form.get('password') or '123456')
        )

        plan = request.form.get('plan')
        db.session.add(user)
        db.session.flush()  # gives user.id before creating payment

        if plan in PLANS:
            activate_membership(user, plan)
            create_approved_payment(
                user=user,
                plan_key=plan,
                method='frontdesk',
                slip_note='Created automatically when member was added at front desk.'
            )
            flash(f'Member added. {PLANS[plan]["name"]} activated and ฿{PLANS[plan]["price"]} recorded in transactions.', 'success')
        else:
            flash('Member added without active plan.', 'success')

        db.session.commit()
        return redirect(url_for('member_detail', user_id=user.id))

    return render_template('add_member.html')


@app.route('/admin/renew-member/<int:user_id>', methods=['POST'])
@staff_required
def renew_member(user_id):
    user = User.query.get_or_404(user_id)
    plan = request.form.get('plan')
    if plan not in PLANS:
        flash('Invalid renewal plan.', 'danger')
        return redirect(url_for('member_detail', user_id=user.id))

    activate_membership(user, plan)
    create_approved_payment(
        user=user,
        plan_key=plan,
        method='frontdesk_renewal',
        slip_note='Created automatically from member renewal.'
    )
    db.session.commit()

    flash(f'{user.name} renewed with {PLANS[plan]["name"]}. ฿{PLANS[plan]["price"]} recorded in transactions.', 'success')
    return redirect(url_for('member_detail', user_id=user.id))


@app.route('/admin/delete-member/<int:user_id>', methods=['POST'])
@admin_required
def delete_member(user_id):
    user = User.query.get_or_404(user_id)
    CheckIn.query.filter_by(user_id=user.id).delete()
    Payment.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('Member deleted permanently.', 'success')
    return redirect(url_for('members'))

@app.route('/admin/payment/<ref>/<action>', methods=['POST'])
@staff_required
def update_payment(ref, action):
    p = Payment.query.filter_by(ref=ref).first_or_404()
    if action == 'approve':
        p.status = 'approved'; p.approved_at = datetime.utcnow(); activate_membership(p.user, p.plan)
        flash('Payment approved and membership activated.', 'success')
    elif action == 'reject':
        p.status = 'rejected'; flash('Payment rejected.', 'info')
    db.session.commit()
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/regenerate/<int:user_id>', methods=['POST'])
@staff_required
def regenerate_qr(user_id):
    user = User.query.get_or_404(user_id)
    user.member_qr_token = uuid.uuid4().hex
    db.session.commit(); flash('Member QR regenerated.', 'success')
    return redirect(url_for('member_detail', user_id=user.id))

@app.route('/checkin', methods=['GET','POST'])
@staff_required
def checkin():
    result = None
    user = None
    latest_checkin = None

    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        muscle_group = request.form.get('muscle_group')
        note = request.form.get('note')

        user = get_user_by_qr_or_id(token)

        if user and user.membership_expiry and user.membership_expiry > datetime.utcnow():
            latest_checkin = record_checkin(
                user=user,
                method='qr',
                result='valid',
                muscle_group=muscle_group,
                note=note
            )
            result = 'valid'
            flash(f'Valid member: {user.name}. Entry allowed.', 'success')
        elif user:
            result = 'expired'
            flash(f'{user.name} is found but membership is expired.', 'danger')
        else:
            result = 'invalid'
            flash('Invalid member QR token or member number.', 'danger')

    return render_template(
        'checkin.html',
        result=result,
        user=user,
        latest_checkin=latest_checkin,
        muscle_groups=MUSCLE_GROUPS,
        now=datetime.utcnow()
    )

@app.route('/manual-checkin/<int:user_id>', methods=['GET', 'POST'])
@staff_required
def manual_checkin(user_id):

    user = User.query.get_or_404(user_id)

    print("MANUAL CHECKIN HIT")

    if request.method == 'POST':

        print("POST RECEIVED")

        muscle_group = request.form.get('muscle_group')
        note = request.form.get('note')

        print("DATA:", muscle_group, note)

        checkin = CheckIn(
            user_id=user.id,
            method='manual',
            result='valid',
            muscle_group=muscle_group,
            note=note
        )

        db.session.add(checkin)
        db.session.commit()

        print("CHECKIN SAVED")

        flash(f'Manual check-in recorded for {user.name}.', 'success')

        return redirect(url_for('member_detail', user_id=user.id))

    return render_template(
        'manual_checkin.html',
        user=user,
        muscle_groups=MUSCLE_GROUPS,
        now=datetime.utcnow()
    )


@app.route('/admin/delete-checkin/<int:checkin_id>', methods=['POST'])
@admin_required
def delete_checkin(checkin_id):
    checkin = CheckIn.query.get_or_404(checkin_id)
    user_id = checkin.user_id
    db.session.delete(checkin)
    db.session.commit()
    flash('Workout history deleted.', 'success')
    return redirect(url_for('member_detail', user_id=user_id))

@app.route('/admin/transactions')
@staff_required
def transactions():
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    approved_statuses = ['approved', 'auto_verified']
    total_revenue = db.session.query(db.func.coalesce(db.func.sum(Payment.amount), 0)).filter(Payment.status.in_(approved_statuses)).scalar() or 0
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    revenue_today = db.session.query(db.func.coalesce(db.func.sum(Payment.amount), 0)).filter(Payment.status.in_(approved_statuses), Payment.approved_at >= today_start).scalar() or 0
    revenue_month = db.session.query(db.func.coalesce(db.func.sum(Payment.amount), 0)).filter(Payment.status.in_(approved_statuses), Payment.approved_at >= month_start).scalar() or 0
    pending_total = db.session.query(db.func.coalesce(db.func.sum(Payment.amount), 0)).filter_by(status='pending').scalar() or 0
    approved_count = Payment.query.filter(Payment.status.in_(approved_statuses)).count()
    return render_template('transactions.html', payments=payments, total_revenue=total_revenue, revenue_today=revenue_today, revenue_month=revenue_month, pending_total=pending_total, approved_count=approved_count)

@app.route('/admin/export.csv')
@staff_required
def export_csv():
    out = StringIO(); w = csv.writer(out)
    w.writerow(['transaction_id','payment_ref','member_id','name','email','phone','plan','plan_name','price','payment_status','payment_method','slip_note','created_at','approved_at','membership_type','membership_expiry'])
    for p in Payment.query.order_by(Payment.created_at.desc()).all():
        plan_name = PLANS.get(p.plan, {}).get('name', p.plan)
        w.writerow([p.id, p.ref, p.user.id, p.user.name, p.user.email, p.user.phone or '', p.plan, plan_name, p.amount, p.status, p.method, p.slip_note or '', p.created_at, p.approved_at or '', p.user.membership_type or '', p.user.membership_expiry or ''])
    return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=transactions_with_prices.csv'})

@app.route('/admin/members.csv')
@staff_required
def export_members_csv():
    out = StringIO(); w = csv.writer(out)
    w.writerow(['id','name','email','phone','role','membership_type','membership_expiry','created_at'])
    for u in User.query.order_by(User.id).all():
        w.writerow([u.id,u.name,u.email,u.phone or '',u.role,u.membership_type,u.membership_expiry,u.created_at])
    return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=members.csv'})

# Option B webhook: connect this to your Slip API / bank provider.
@app.route('/api/payment/webhook', methods=['POST'])
def payment_webhook():
    sig = request.headers.get('X-Signature','')
    raw = request.get_data()
    expected = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return jsonify({'ok': False, 'error': 'bad signature'}), 401
    data = request.get_json(force=True)
    p = Payment.query.filter_by(ref=data.get('ref')).first()
    if not p:
        return jsonify({'ok': False, 'error': 'payment not found'}), 404
    if float(data.get('amount', 0)) != float(p.amount):
        p.status = 'rejected'; p.verified_payload = str(data); db.session.commit()
        return jsonify({'ok': False, 'error': 'amount mismatch'}), 400
    if data.get('status') in ['paid', 'verified', 'success']:
        p.status = 'auto_verified'; p.approved_at = datetime.utcnow(); p.verified_payload = str(data)
        activate_membership(p.user, p.plan); db.session.commit()
        return jsonify({'ok': True, 'message': 'membership activated'})
    return jsonify({'ok': False, 'message': 'ignored'})

@app.route('/static/<path:path>')
def static_proxy(path):
    return app.send_static_file(path)

@app.cli.command('init-db')
def init_db_cmd():
    init_db(); print('Database initialized')

def ensure_schema():
    # Lightweight SQLite migration for users upgrading from v3.
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        with db.engine.connect() as conn:
            cols = [row[1] for row in conn.exec_driver_sql('PRAGMA table_info(user)').fetchall()]
            if cols and 'phone' not in cols:
                conn.exec_driver_sql('ALTER TABLE user ADD COLUMN phone VARCHAR(30)')
                conn.commit()
def ensure_checkin_workout_columns():
    """Add workout columns to existing CheckIn table when upgrading old databases."""
    try:
        inspector = db.inspect(db.engine)
        columns = [c["name"] for c in inspector.get_columns("check_in")]

        with db.engine.begin() as conn:
            if "muscle_group" not in columns:
                conn.execute(db.text(
                    "ALTER TABLE check_in ADD COLUMN muscle_group VARCHAR(50)"
                ))

            if "note" not in columns:
                conn.execute(db.text(
                    "ALTER TABLE check_in ADD COLUMN note VARCHAR(255)"
                ))

    except Exception as exc:
        print("Workout column check skipped:", exc)
def init_db():
    db.create_all()
    ensure_checkin_workout_columns()
    ensure_schema()
    if not User.query.filter_by(email='admin@gym.com').first():
        admin = User(name='Admin', email='admin@gym.com', password_hash=generate_password_hash('admin123'), role='admin')
        db.session.add(admin)
    if not User.query.filter_by(email='staff@gym.com').first():
        staff = User(name='Front Desk', email='staff@gym.com', password_hash=generate_password_hash('staff123'), role='staff')
        db.session.add(staff)
    db.session.commit()

with app.app_context():
    init_db()
    #db.create_all()

if __name__ == '__main__':
    import os

    port = int(os.environ.get("PORT", 10000))

    app.run(
        host='0.0.0.0',
        port=port
    )
