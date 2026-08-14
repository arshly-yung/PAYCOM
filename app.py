import os
import io
import ssl
import uuid
import smtplib
import secrets
import hashlib
import base64
import requests
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from functools import wraps

from cryptography.fernet import Fernet
from flask import (
    Flask, render_template, request, redirect, url_for, flash, abort,
    jsonify, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

db_url = os.getenv("DATABASE_URL", "sqlite:///paycom.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-me"),
    SQLALCHEMY_DATABASE_URI=db_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "150 per hour"]
)

COUNTRIES = {
    "Japan": {"code": "JP", "currency": "JPY", "symbol": "¥"},
    "United States": {"code": "US", "currency": "USD", "symbol": "$"},
    "Taiwan": {"code": "TW", "currency": "TWD", "symbol": "NT$"},
}

STATUSES = [
    "WAITING_FOR_RECEIVING_DETAILS",
    "RECEIVING_DETAILS_SENT",
    "WAITING_FOR_PAYMENT",
    "RECEIPT_UPLOADED",
    "PAYMENT_VERIFIED",
    "PAYOUT_DETAILS_SUBMITTED",
    "PAYOUT_READY",
    "PAYOUT_PROCESSING",
    "COMPLETED",
    "ON_HOLD",
    "FAILED",
    "CANCELLED",
]

AVATARS = ["avatar1", "avatar2", "avatar3", "avatar4", "avatar5", "avatar6"]

JPY_EMAIL_MIN = Decimal("10000")
JPY_EMAIL_MAX = Decimal("500000")
JPY_ID_MIN = Decimal("510000")
JPY_ID_MAX = Decimal("1000000")
DEFAULT_FEE_PERCENT = Decimal(os.getenv("PAYCOM_FEE_PERCENT", "10"))

def utcnow():
    return datetime.now(timezone.utc)

def money(value):
    if value is None:
        return Decimal("0.00")
    return Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

def make_cipher():
    configured = os.getenv("DOCUMENT_ENCRYPTION_KEY", "").strip()
    if configured:
        try:
            return Fernet(configured.encode())
        except Exception:
            pass
    digest = hashlib.sha256(app.config["SECRET_KEY"].encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))

cipher = make_cipher()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(120), unique=True, nullable=False, index=True)
    email = db.Column(db.String(180), unique=True, nullable=True)
    pin_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    role = db.Column(db.String(20), default="customer", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_code_hash = db.Column(db.String(255), nullable=True)
    email_code_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    avatar_key = db.Column(db.String(30), default="avatar1", nullable=False)
    identity_status = db.Column(db.String(30), default="NOT_SUBMITTED", nullable=False)
    identity_decline_reason = db.Column(db.String(500), nullable=True)
    identity_submitted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    identity_reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    user = db.relationship("User", backref=db.backref("security_profile", uselist=False))

class IdentityDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    document_type = db.Column(db.String(40), nullable=False)
    encrypted_id_number = db.Column(db.LargeBinary, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(120), nullable=False)
    encrypted_file = db.Column(db.LargeBinary, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user = db.relationship("User")

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(40), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    country = db.Column(db.String(50), nullable=False)
    currency = db.Column(db.String(10), nullable=False)
    expected_amount = db.Column(db.Numeric(18, 2), nullable=False)
    receiving_reference = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(50), default="WAITING_FOR_RECEIVING_DETAILS", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    user = db.relationship("User", backref="transactions")

class ReceivingInstruction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transaction.id"), nullable=False, index=True)
    bank_name = db.Column(db.String(180), nullable=False)
    account_name = db.Column(db.String(180), nullable=False)
    account_number = db.Column(db.String(180), nullable=False)
    branch_or_code = db.Column(db.String(180), nullable=True)
    payment_reference = db.Column(db.String(180), nullable=True)
    instructions = db.Column(db.Text, nullable=True)
    sent_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class Receipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transaction.id"), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(30), default="UPLOADED", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class ReceiptFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey("receipt.id"), unique=True, nullable=False, index=True)
    mime_type = db.Column(db.String(120), nullable=False)
    encrypted_file = db.Column(db.LargeBinary, nullable=False)

class PayoutRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transaction.id"), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    bank_name = db.Column(db.String(120), nullable=False)
    account_number = db.Column(db.String(30), nullable=False)
    account_name = db.Column(db.String(150), nullable=False)
    gross_ngn_amount = db.Column(db.Numeric(18, 2), nullable=True)
    fee_percent = db.Column(db.Numeric(7, 3), nullable=True)
    fee_ngn_amount = db.Column(db.Numeric(18, 2), nullable=True)
    net_ngn_amount = db.Column(db.Numeric(18, 2), nullable=True)
    actual_sent_ngn = db.Column(db.Numeric(18, 2), nullable=True)
    transfer_reference = db.Column(db.String(180), nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default="AWAITING_ADMIN", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transaction.id"), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def get_profile(user, create=True):
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    if not profile and create:
        profile = UserProfile(
            user_id=user.id,
            avatar_key=AVATARS[(user.id - 1) % len(AVATARS)],
            email_verified=True if user.role == "admin" else False,
            identity_status="APPROVED" if user.role == "admin" else "NOT_SUBMITTED",
        )
        db.session.add(profile)
        db.session.commit()
    return profile

def ensure_profiles():
    for user in User.query.all():
        get_profile(user)

def audit(action, transaction_id=None, details=None):
    db.session.add(AuditLog(
        actor_user_id=current_user.id if current_user.is_authenticated else None,
        transaction_id=transaction_id,
        action=action,
        details=details,
    ))
    db.session.commit()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def make_reference(country):
    return f"PAY-{COUNTRIES[country]['code']}-{uuid.uuid4().hex[:8].upper()}"

def latest_receiving_instruction(tx_id):
    return ReceivingInstruction.query.filter_by(
        transaction_id=tx_id, is_active=True
    ).order_by(ReceivingInstruction.id.desc()).first()

def active_identity_document(user_id):
    return IdentityDocument.query.filter_by(
        user_id=user_id, is_active=True
    ).order_by(IdentityDocument.id.desc()).first()

def ensure_admin():
    phone = os.getenv("ADMIN_PHONE")
    pin = os.getenv("ADMIN_PIN")
    if not phone or not pin:
        return
    user = User.query.filter_by(phone=phone).first()
    if user:
        user.role = "admin"
        user.is_verified = True
        user.pin_hash = generate_password_hash(pin)
    else:
        user = User(
            full_name="Pay.com Administrator",
            phone=phone,
            email=None,
            pin_hash=generate_password_hash(pin),
            is_verified=True,
            role="admin",
        )
        db.session.add(user)
    db.session.commit()
    profile = get_profile(user)
    profile.email_verified = True
    profile.identity_status = "APPROVED"
    db.session.commit()

def send_verification_email(user, code):
    if not user.email:
        raise RuntimeError("No email address is set on the account.")

    if os.getenv("EMAIL_TEST_MODE", "0") == "1":
        app.logger.warning("EMAIL_TEST_MODE code for %s: %s", user.email, code)
        return

    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("RESEND_API_KEY is not configured.")

    sender = os.getenv("RESEND_FROM", "Pay.com <onboarding@resend.dev>").strip()

    payload = {
        "from": sender,
        "to": [user.email],
        "subject": "Your Pay.com verification code",
        "html": f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;">
            <div style="font-size:28px;font-weight:800;margin-bottom:16px;">
                Pay<span style="color:#2563eb;">.com</span>
            </div>
            <p style="font-size:16px;color:#344054;">Your verification code is:</p>
            <div style="font-size:34px;font-weight:800;letter-spacing:7px;color:#101828;margin:22px 0;">
                {code}
            </div>
            <p style="color:#667085;">This code expires in 10 minutes.</p>
            <p style="color:#667085;">If you did not request this code, you can ignore this email.</p>
        </div>
        """,
    }

    response = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )

    if not response.ok:
        raise RuntimeError(f"Resend email failed: {response.status_code} {response.text}")

    return

def create_and_send_email_code(user):
    profile = get_profile(user)
    code = str(secrets.randbelow(900000) + 100000)
    profile.email_code_hash = generate_password_hash(code)
    profile.email_code_expires_at = utcnow() + timedelta(minutes=10)
    db.session.commit()
    send_verification_email(user, code)

def masked_account(number):
    if not number:
        return ""
    if len(number) <= 4:
        return number
    return "•" * (len(number) - 4) + number[-4:]

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if os.getenv("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.context_processor
def template_helpers():
    return {
        "get_profile": get_profile,
        "masked_account": masked_account,
        "avatars": AVATARS,
    }

@app.get("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip().lower()
        pin = request.form.get("pin", "").strip()

        if not name or not phone or not email or len(pin) < 4 or not pin.isdigit():
            flash("Enter your name, phone, email and a numeric PIN of at least 4 digits.", "error")
            return redirect(url_for("register"))
        if User.query.filter_by(phone=phone).first():
            flash("That phone number is already registered.", "error")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("That email address is already registered.", "error")
            return redirect(url_for("register"))

        user = User(
            full_name=name,
            phone=phone,
            email=email,
            pin_hash=generate_password_hash(pin),
            is_verified=False,
            role="customer",
        )
        db.session.add(user)
        db.session.commit()
        get_profile(user)
        login_user(user)
        audit("USER_REGISTERED", details=f"user_id={user.id}")

        try:
            create_and_send_email_code(user)
            flash("Account created. We sent a 6-digit code to your email.", "success")
            return redirect(url_for("verify_email"))
        except Exception as exc:
            app.logger.warning("Email send failed: %s", exc)
            flash("Account created. Email verification is waiting for email delivery setup.", "error")
            return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("8 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.role == "admin" else "dashboard"))
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        pin = request.form.get("pin", "").strip()
        user = User.query.filter_by(phone=phone).first()
        if user and check_password_hash(user.pin_hash, pin):
            login_user(user)
            get_profile(user)
            audit("LOGIN_SUCCESS")
            return redirect(url_for("admin_dashboard" if user.role == "admin" else "dashboard"))
        flash("Invalid phone/login ID or PIN.", "error")
    return render_template("login.html")

@app.get("/logout")
@login_required
def logout():
    audit("LOGOUT")
    logout_user()
    return redirect(url_for("index"))

@app.get("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    profile = get_profile(current_user)
    txns = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.id.desc()).all()
    return render_template("dashboard.html", txns=txns, profile=profile)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    profile = get_profile(current_user)
    if request.method == "POST":
        avatar = request.form.get("avatar", "")
        if avatar in AVATARS:
            profile.avatar_key = avatar
            db.session.commit()
            flash("Profile picture updated.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", profile=profile)

@app.route("/verify-email", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def verify_email():
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    profile = get_profile(current_user)
    if profile.email_verified:
        flash("Your email is already verified.", "success")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        expires = profile.email_code_expires_at
        if (
            not code or
            not profile.email_code_hash or
            not expires or
            utcnow() > expires or
            not check_password_hash(profile.email_code_hash, code)
        ):
            flash("That code is invalid or expired.", "error")
            return redirect(url_for("verify_email"))

        profile.email_verified = True
        profile.email_code_hash = None
        profile.email_code_expires_at = None
        db.session.commit()
        audit("EMAIL_VERIFIED", details=f"user_id={current_user.id}")
        flash("Email verified. Your green verification badge is active.", "success")
        return redirect(url_for("dashboard"))

    return render_template("verify_email.html", profile=profile)

@app.post("/verify-email/resend")
@login_required
@limiter.limit("3 per 10 minutes")
def resend_email_code():
    profile = get_profile(current_user)
    if profile.email_verified:
        return redirect(url_for("dashboard"))
    try:
        create_and_send_email_code(current_user)
        flash("A new verification code was sent.", "success")
    except Exception as exc:
        app.logger.warning("Email resend failed: %s", exc)
        flash("Email delivery is not configured yet.", "error")
    return redirect(url_for("verify_email"))

@app.route("/identity", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per hour")
def identity():
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    profile = get_profile(current_user)
    if not profile.email_verified:
        flash("Verify your email before submitting identity documents.", "error")
        return redirect(url_for("verify_email"))

    if request.method == "POST":
        doc_type = request.form.get("document_type", "").strip()
        id_number = request.form.get("id_number", "").strip()
        upload = request.files.get("document")

        if doc_type not in {"NIN", "DRIVERS_LICENSE"}:
            flash("Choose NIN or Driver's License.", "error")
            return redirect(url_for("identity"))
        if len(id_number) < 5:
            flash("Enter a valid identity number.", "error")
            return redirect(url_for("identity"))
        if not upload or not upload.filename:
            flash("Upload the ID document.", "error")
            return redirect(url_for("identity"))

        ext = os.path.splitext(upload.filename.lower())[1]
        allowed = {".jpg", ".jpeg", ".png", ".pdf"}
        if ext not in allowed:
            flash("Only JPG, PNG and PDF files are accepted.", "error")
            return redirect(url_for("identity"))

        raw = upload.read()
        if not raw or len(raw) > 5 * 1024 * 1024:
            flash("The document must be smaller than 5 MB.", "error")
            return redirect(url_for("identity"))

        IdentityDocument.query.filter_by(
            user_id=current_user.id, is_active=True
        ).update({"is_active": False})

        doc = IdentityDocument(
            user_id=current_user.id,
            document_type=doc_type,
            encrypted_id_number=cipher.encrypt(id_number.encode("utf-8")),
            filename=upload.filename[:255],
            mime_type=upload.mimetype or "application/octet-stream",
            encrypted_file=cipher.encrypt(raw),
            is_active=True,
        )
        db.session.add(doc)
        profile.identity_status = "PENDING"
        profile.identity_decline_reason = None
        profile.identity_submitted_at = utcnow()
        profile.identity_reviewed_at = None
        db.session.commit()
        audit("IDENTITY_SUBMITTED", details=f"user_id={current_user.id}; type={doc_type}")
        flash("Identity submitted. An administrator will review it.", "success")
        return redirect(url_for("profile"))

    return render_template("identity.html", profile=profile)

@app.route("/receive", methods=["GET", "POST"])
@login_required
def receive():
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    profile = get_profile(current_user)

    if not current_user.is_verified:
        flash("Your account must be approved by Pay.com first.", "error")
        return redirect(url_for("dashboard"))
    if not profile.email_verified:
        flash("Verify your email before creating a transaction.", "error")
        return redirect(url_for("verify_email"))

    if request.method == "POST":
        country = request.form.get("country")
        try:
            amount = money(request.form.get("amount", "0"))
        except (InvalidOperation, ValueError):
            amount = Decimal("0")

        if country not in COUNTRIES or amount <= 0:
            flash("Enter a valid transaction.", "error")
            return redirect(url_for("receive"))

        if country == "Japan":
            if JPY_EMAIL_MIN <= amount <= JPY_EMAIL_MAX:
                pass
            elif JPY_ID_MIN <= amount <= JPY_ID_MAX:
                if profile.identity_status != "APPROVED":
                    flash("Transactions from ¥510,000 to ¥1,000,000 require approved ID verification.", "error")
                    return redirect(url_for("identity"))
            elif Decimal("500000") < amount < Decimal("510000"):
                flash("Choose up to ¥500,000, or at least ¥510,000 with approved ID verification.", "error")
                return redirect(url_for("receive"))
            else:
                flash("Japan transactions are currently limited to ¥10,000–¥1,000,000.", "error")
                return redirect(url_for("receive"))

        ref = make_reference(country)
        tx = Transaction(
            reference=ref,
            user_id=current_user.id,
            country=country,
            currency=COUNTRIES[country]["currency"],
            expected_amount=amount,
            receiving_reference=ref.replace("-", ""),
            status="WAITING_FOR_RECEIVING_DETAILS",
        )
        db.session.add(tx)
        db.session.commit()
        audit("TRANSACTION_CREATED", tx.id, details=f"amount={amount}; currency={tx.currency}")
        return redirect(url_for("transaction_detail", tx_id=tx.id))

    return render_template(
        "receive.html",
        countries=COUNTRIES,
        profile=profile,
        jpy_email_min=JPY_EMAIL_MIN,
        jpy_email_max=JPY_EMAIL_MAX,
        jpy_id_min=JPY_ID_MIN,
        jpy_id_max=JPY_ID_MAX,
    )

@app.get("/transaction/<int:tx_id>")
@login_required
def transaction_detail(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx or (tx.user_id != current_user.id and current_user.role != "admin"):
        abort(404)

    instruction = latest_receiving_instruction(tx.id)
    receipt = Receipt.query.filter_by(transaction_id=tx.id).order_by(Receipt.id.desc()).first()
    payout = PayoutRequest.query.filter_by(transaction_id=tx.id).first()
    return render_template(
        "transaction.html",
        tx=tx,
        instruction=instruction,
        receipt=receipt,
        payout=payout,
    )

@app.post("/transaction/<int:tx_id>/receipt")
@login_required
def receipt_upload(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx or tx.user_id != current_user.id:
        abort(404)
    if not latest_receiving_instruction(tx.id):
        flash("Wait for receiving details first.", "error")
        return redirect(url_for("transaction_detail", tx_id=tx.id))

    upload = request.files.get("receipt")
    if not upload or not upload.filename:
        flash("Choose a receipt.", "error")
        return redirect(url_for("transaction_detail", tx_id=tx.id))

    ext = os.path.splitext(upload.filename.lower())[1]
    if ext not in {".jpg", ".jpeg", ".png", ".pdf"}:
        flash("Only JPG, PNG and PDF receipts are accepted.", "error")
        return redirect(url_for("transaction_detail", tx_id=tx.id))

    raw = upload.read()
    if not raw or len(raw) > 5 * 1024 * 1024:
        flash("Receipt must be smaller than 5 MB.", "error")
        return redirect(url_for("transaction_detail", tx_id=tx.id))

    receipt = Receipt(
        transaction_id=tx.id,
        original_filename=upload.filename[:255],
        status="UPLOADED",
    )
    db.session.add(receipt)
    db.session.flush()
    db.session.add(ReceiptFile(
        receipt_id=receipt.id,
        mime_type=upload.mimetype or "application/octet-stream",
        encrypted_file=cipher.encrypt(raw),
    ))
    tx.status = "RECEIPT_UPLOADED"
    db.session.commit()
    audit("RECEIPT_RECORDED", tx.id, details=upload.filename[:255])
    flash("Receipt uploaded. Pay.com will verify the incoming payment.", "success")
    return redirect(url_for("transaction_detail", tx_id=tx.id))

@app.route("/transaction/<int:tx_id>/payout-details", methods=["GET", "POST"])
@login_required
def payout_details(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx or tx.user_id != current_user.id:
        abort(404)
    if tx.status not in {
        "PAYMENT_VERIFIED",
        "PAYOUT_DETAILS_SUBMITTED",
        "PAYOUT_READY",
        "PAYOUT_PROCESSING",
    }:
        flash("Payout details become available after payment verification.", "error")
        return redirect(url_for("transaction_detail", tx_id=tx.id))

    payout = PayoutRequest.query.filter_by(transaction_id=tx.id).first()

    if request.method == "POST":
        bank = request.form.get("bank_name", "").strip()
        number = request.form.get("account_number", "").strip()
        name = request.form.get("account_name", "").strip()

        if not bank or not name or not number.isdigit() or len(number) != 10:
            flash("Enter a valid Nigerian bank name, 10-digit account number and account name.", "error")
            return redirect(url_for("payout_details", tx_id=tx.id))

        if not payout:
            payout = PayoutRequest(
                transaction_id=tx.id,
                user_id=current_user.id,
                bank_name=bank,
                account_number=number,
                account_name=name,
                status="AWAITING_ADMIN",
            )
            db.session.add(payout)
        else:
            payout.bank_name = bank
            payout.account_number = number
            payout.account_name = name
            if payout.status == "AWAITING_ADMIN":
                pass

        tx.status = "PAYOUT_DETAILS_SUBMITTED"
        db.session.commit()
        audit("PAYOUT_DETAILS_SUBMITTED", tx.id, details=f"bank={bank}; acct_last4={number[-4:]}")
        flash("Your Nigerian payout account has been submitted.", "success")
        return redirect(url_for("transaction_detail", tx_id=tx.id))

    return render_template("payout_details.html", tx=tx, payout=payout)

@app.get("/admin")
@login_required
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.id.desc()).all()
    txns = Transaction.query.order_by(Transaction.id.desc()).all()
    pending_ids = UserProfile.query.filter_by(identity_status="PENDING").all()
    profiles = {p.user_id: p for p in UserProfile.query.all()}
    return render_template(
        "admin.html",
        users=users,
        txns=txns,
        pending_ids=pending_ids,
        profiles=profiles,
    )

@app.get("/admin/transaction/<int:tx_id>")
@login_required
@admin_required
def admin_transaction(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx:
        abort(404)

    history = ReceivingInstruction.query.filter_by(
        transaction_id=tx.id
    ).order_by(ReceivingInstruction.id.desc()).all()
    logs = AuditLog.query.filter_by(
        transaction_id=tx.id
    ).order_by(AuditLog.id.desc()).all()
    receipt = Receipt.query.filter_by(transaction_id=tx.id).order_by(Receipt.id.desc()).first()
    payout = PayoutRequest.query.filter_by(transaction_id=tx.id).first()

    return render_template(
        "admin_transaction.html",
        tx=tx,
        instruction=latest_receiving_instruction(tx.id),
        receiving_history=history,
        logs=logs,
        statuses=STATUSES,
        receipt=receipt,
        payout=payout,
        default_fee_percent=DEFAULT_FEE_PERCENT,
    )

@app.post("/admin/user/<int:user_id>/verify")
@login_required
@admin_required
def admin_verify_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    user.is_verified = True
    db.session.commit()
    audit("ADMIN_VERIFIED_USER", details=f"user_id={user.id}")
    return redirect(url_for("admin_dashboard"))

@app.post("/admin/user/<int:user_id>/unverify")
@login_required
@admin_required
def admin_unverify_user(user_id):
    user = db.session.get(User, user_id)
    if not user or user.role == "admin":
        abort(404)
    user.is_verified = False
    db.session.commit()
    audit("ADMIN_UNVERIFIED_USER", details=f"user_id={user.id}")
    return redirect(url_for("admin_dashboard"))

@app.get("/admin/identity/<int:user_id>")
@login_required
@admin_required
def admin_identity(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    profile = get_profile(user)
    doc = active_identity_document(user_id)
    id_number = None
    if doc:
        try:
            id_number = cipher.decrypt(doc.encrypted_id_number).decode("utf-8")
        except Exception:
            id_number = "Unable to decrypt"
    return render_template(
        "admin_identity.html",
        customer=user,
        profile=profile,
        document=doc,
        id_number=id_number,
    )

@app.get("/admin/identity-document/<int:doc_id>")
@login_required
@admin_required
def admin_identity_document(doc_id):
    doc = db.session.get(IdentityDocument, doc_id)
    if not doc:
        abort(404)
    raw = cipher.decrypt(doc.encrypted_file)
    return send_file(
        io.BytesIO(raw),
        mimetype=doc.mime_type,
        download_name=doc.filename,
        as_attachment=False,
    )

@app.post("/admin/identity/<int:user_id>/decision")
@login_required
@admin_required
def admin_identity_decision(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    profile = get_profile(user)
    decision = request.form.get("decision", "").strip()
    reason = request.form.get("reason", "").strip()

    if decision == "APPROVE":
        profile.identity_status = "APPROVED"
        profile.identity_decline_reason = None
        action = "IDENTITY_APPROVED"
    elif decision == "DECLINE":
        profile.identity_status = "DECLINED"
        profile.identity_decline_reason = reason or "Document could not be approved."
        action = "IDENTITY_DECLINED"
    else:
        abort(400)

    profile.identity_reviewed_at = utcnow()
    db.session.commit()
    audit(action, details=f"user_id={user.id}")
    flash("Identity review saved.", "success")
    return redirect(url_for("admin_identity", user_id=user.id))

@app.get("/admin/receipt/<int:receipt_id>")
@login_required
@admin_required
def admin_receipt(receipt_id):
    receipt = db.session.get(Receipt, receipt_id)
    if not receipt:
        abort(404)
    stored = ReceiptFile.query.filter_by(receipt_id=receipt.id).first()
    if not stored:
        abort(404)
    raw = cipher.decrypt(stored.encrypted_file)
    return send_file(
        io.BytesIO(raw),
        mimetype=stored.mime_type,
        download_name=receipt.original_filename,
        as_attachment=False,
    )

@app.post("/admin/transaction/<int:tx_id>/receiving-details")
@login_required
@admin_required
def admin_send_receiving_details(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx:
        abort(404)

    bank = request.form.get("bank_name", "").strip()
    name = request.form.get("account_name", "").strip()
    number = request.form.get("account_number", "").strip()
    branch = request.form.get("branch_or_code", "").strip() or None
    pref = request.form.get("payment_reference", "").strip() or tx.receiving_reference
    instructions = request.form.get("instructions", "").strip() or None

    if not bank or not name or not number:
        flash("Bank name, account name and account number are required.", "error")
        return redirect(url_for("admin_transaction", tx_id=tx.id))

    ReceivingInstruction.query.filter_by(
        transaction_id=tx.id, is_active=True
    ).update({"is_active": False})

    db.session.add(ReceivingInstruction(
        transaction_id=tx.id,
        bank_name=bank,
        account_name=name,
        account_number=number,
        branch_or_code=branch,
        payment_reference=pref,
        instructions=instructions,
        sent_by_user_id=current_user.id,
        is_active=True,
    ))
    tx.status = "RECEIVING_DETAILS_SENT"
    db.session.commit()
    audit("ADMIN_SENT_RECEIVING_DETAILS", tx.id, details=f"bank={bank}; acct_last4={number[-4:]}")
    flash("Receiving details sent to this transaction.", "success")
    return redirect(url_for("admin_transaction", tx_id=tx.id))

@app.post("/admin/transaction/<int:tx_id>/status")
@login_required
@admin_required
def admin_update_status(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx:
        abort(404)

    status = request.form.get("status")
    if status not in STATUSES:
        abort(400)

    if status in {"PAYOUT_READY", "PAYOUT_PROCESSING", "COMPLETED"}:
        flash("Use the payout controls to move into payout or completed status.", "error")
        return redirect(url_for("admin_transaction", tx_id=tx.id))

    tx.status = status
    db.session.commit()
    audit("ADMIN_UPDATED_STATUS", tx.id, details=status)
    return redirect(url_for("admin_transaction", tx_id=tx.id))

@app.post("/admin/transaction/<int:tx_id>/prepare-payout")
@login_required
@admin_required
def admin_prepare_payout(tx_id):
    tx = db.session.get(Transaction, tx_id)
    if not tx:
        abort(404)
    payout = PayoutRequest.query.filter_by(transaction_id=tx.id).first()
    if not payout:
        flash("The customer must submit Nigerian payout account details first.", "error")
        return redirect(url_for("admin_transaction", tx_id=tx.id))

    try:
        gross = money(request.form.get("gross_ngn_amount", "0"))
        fee_percent = Decimal(request.form.get("fee_percent", str(DEFAULT_FEE_PERCENT)))
    except Exception:
        gross = Decimal("0")
        fee_percent = DEFAULT_FEE_PERCENT

    if gross <= 0 or fee_percent < 0 or fee_percent >= 100:
        flash("Enter a valid gross NGN amount and fee percentage.", "error")
        return redirect(url_for("admin_transaction", tx_id=tx.id))

    fee = (gross * fee_percent / Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    net = (gross - fee).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    payout.gross_ngn_amount = gross
    payout.fee_percent = fee_percent
    payout.fee_ngn_amount = fee
    payout.net_ngn_amount = net
    payout.admin_notes = request.form.get("admin_notes", "").strip() or None
    payout.status = "READY"
    tx.status = "PAYOUT_READY"
    db.session.commit()
    audit("PAYOUT_PREPARED", tx.id, details=f"gross={gross}; fee={fee}; net={net}")
    flash("Payout breakdown prepared. The customer can now see the fee and net amount.", "success")
    return redirect(url_for("admin_transaction", tx_id=tx.id))

@app.post("/admin/transaction/<int:tx_id>/start-payout")
@login_required
@admin_required
def admin_start_payout(tx_id):
    tx = db.session.get(Transaction, tx_id)
    payout = PayoutRequest.query.filter_by(transaction_id=tx_id).first()
    if not tx or not payout or payout.status != "READY":
        flash("Prepare the payout first.", "error")
        return redirect(url_for("admin_transaction", tx_id=tx_id))
    payout.status = "PROCESSING"
    tx.status = "PAYOUT_PROCESSING"
    db.session.commit()
    audit("PAYOUT_PROCESSING", tx.id, details=f"net={payout.net_ngn_amount}")
    flash("Payout marked as processing. Make the bank transfer, then record the transfer reference.", "success")
    return redirect(url_for("admin_transaction", tx_id=tx.id))

@app.post("/admin/transaction/<int:tx_id>/complete-payout")
@login_required
@admin_required
def admin_complete_payout(tx_id):
    tx = db.session.get(Transaction, tx_id)
    payout = PayoutRequest.query.filter_by(transaction_id=tx_id).first()
    if not tx or not payout or payout.status != "PROCESSING":
        flash("The payout must be processing before it can be completed.", "error")
        return redirect(url_for("admin_transaction", tx_id=tx_id))

    transfer_ref = request.form.get("transfer_reference", "").strip()
    try:
        actual_sent = money(request.form.get("actual_sent_ngn", "0"))
    except Exception:
        actual_sent = Decimal("0")

    expected = money(payout.net_ngn_amount)
    if not transfer_ref:
        flash("Enter the actual bank transfer reference.", "error")
        return redirect(url_for("admin_transaction", tx_id=tx.id))
    if abs(actual_sent - expected) > Decimal("1.00"):
        flash(f"Amount sent must match the customer net payout of ₦{expected:,.2f}.", "error")
        return redirect(url_for("admin_transaction", tx_id=tx.id))

    payout.actual_sent_ngn = actual_sent
    payout.transfer_reference = transfer_ref
    payout.status = "COMPLETED"
    payout.completed_at = utcnow()
    tx.status = "COMPLETED"
    db.session.commit()
    audit("PAYOUT_COMPLETED", tx.id, details=f"amount={actual_sent}; ref={transfer_ref}")
    flash("Payout recorded as completed.", "success")
    return redirect(url_for("admin_transaction", tx_id=tx.id))

@app.get("/health")
def health():
    return jsonify(status="ok", service="paycom-v3")

with app.app_context():
    db.create_all()
    ensure_admin()
    ensure_profiles()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_ENV") != "production")
