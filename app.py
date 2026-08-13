import os, uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
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
)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
limiter = Limiter(get_remote_address, app=app, default_limits=["300 per day", "100 per hour"])

COUNTRIES = {
    "Japan": {"code": "JP", "currency": "JPY"},
    "United States": {"code": "US", "currency": "USD"},
    "Taiwan": {"code": "TW", "currency": "TWD"},
}
STATUSES = [
    "WAITING_FOR_RECEIVING_DETAILS","RECEIVING_DETAILS_SENT","WAITING_FOR_PAYMENT",
    "RECEIPT_UPLOADED","PAYMENT_VERIFIED","PAYOUT_PROCESSING","COMPLETED",
    "ON_HOLD","FAILED","CANCELLED"
]
def utcnow(): return datetime.now(timezone.utc)

class User(UserMixin, db.Model):
    id=db.Column(db.Integer,primary_key=True)
    full_name=db.Column(db.String(120),nullable=False)
    phone=db.Column(db.String(120),unique=True,nullable=False,index=True)
    email=db.Column(db.String(180),unique=True,nullable=True)
    pin_hash=db.Column(db.String(255),nullable=False)
    is_verified=db.Column(db.Boolean,default=False,nullable=False)
    role=db.Column(db.String(20),default="customer",nullable=False)
    created_at=db.Column(db.DateTime(timezone=True),default=utcnow,nullable=False)

class Transaction(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    reference=db.Column(db.String(40),unique=True,nullable=False,index=True)
    user_id=db.Column(db.Integer,db.ForeignKey("user.id"),nullable=False,index=True)
    country=db.Column(db.String(50),nullable=False)
    currency=db.Column(db.String(10),nullable=False)
    expected_amount=db.Column(db.Numeric(18,2),nullable=False)
    receiving_reference=db.Column(db.String(80),nullable=False)
    status=db.Column(db.String(50),default="WAITING_FOR_RECEIVING_DETAILS",nullable=False)
    created_at=db.Column(db.DateTime(timezone=True),default=utcnow,nullable=False)
    updated_at=db.Column(db.DateTime(timezone=True),default=utcnow,onupdate=utcnow,nullable=False)
    user=db.relationship("User",backref="transactions")

class ReceivingInstruction(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    transaction_id=db.Column(db.Integer,db.ForeignKey("transaction.id"),nullable=False,index=True)
    bank_name=db.Column(db.String(180),nullable=False)
    account_name=db.Column(db.String(180),nullable=False)
    account_number=db.Column(db.String(180),nullable=False)
    branch_or_code=db.Column(db.String(180),nullable=True)
    payment_reference=db.Column(db.String(180),nullable=True)
    instructions=db.Column(db.Text,nullable=True)
    sent_by_user_id=db.Column(db.Integer,db.ForeignKey("user.id"),nullable=False)
    is_active=db.Column(db.Boolean,default=True,nullable=False)
    created_at=db.Column(db.DateTime(timezone=True),default=utcnow,nullable=False)

class Receipt(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    transaction_id=db.Column(db.Integer,db.ForeignKey("transaction.id"),nullable=False,index=True)
    original_filename=db.Column(db.String(255),nullable=False)
    status=db.Column(db.String(30),default="UPLOADED",nullable=False)
    created_at=db.Column(db.DateTime(timezone=True),default=utcnow,nullable=False)

class AuditLog(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    actor_user_id=db.Column(db.Integer,db.ForeignKey("user.id"),nullable=True)
    transaction_id=db.Column(db.Integer,db.ForeignKey("transaction.id"),nullable=True)
    action=db.Column(db.String(120),nullable=False)
    details=db.Column(db.Text,nullable=True)
    created_at=db.Column(db.DateTime(timezone=True),default=utcnow,nullable=False)

@login_manager.user_loader
def load_user(user_id): return db.session.get(User,int(user_id))

def audit(action,transaction_id=None,details=None):
    db.session.add(AuditLog(actor_user_id=current_user.id if current_user.is_authenticated else None,
        transaction_id=transaction_id,action=action,details=details))
    db.session.commit()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if not current_user.is_authenticated or current_user.role!="admin": abort(403)
        return fn(*args,**kwargs)
    return wrapper

def make_reference(country):
    return f"PAY-{COUNTRIES[country]['code']}-{uuid.uuid4().hex[:8].upper()}"

def latest_receiving_instruction(tx_id):
    return ReceivingInstruction.query.filter_by(transaction_id=tx_id,is_active=True).order_by(ReceivingInstruction.id.desc()).first()

def ensure_admin():
    phone=os.getenv("ADMIN_PHONE"); pin=os.getenv("ADMIN_PIN")
    if not phone or not pin: return
    u=User.query.filter_by(phone=phone).first()
    if u:
        u.role="admin"; u.is_verified=True; u.pin_hash=generate_password_hash(pin)
    else:
        db.session.add(User(full_name="Pay.com Administrator",phone=phone,pin_hash=generate_password_hash(pin),is_verified=True,role="admin"))
    db.session.commit()

@app.get("/")
def index(): return render_template("index.html")

@app.route("/register",methods=["GET","POST"])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated: return redirect(url_for("dashboard"))
    if request.method=="POST":
        name=request.form.get("full_name","").strip()
        phone=request.form.get("phone","").strip()
        email=request.form.get("email","").strip().lower() or None
        pin=request.form.get("pin","").strip()
        if not name or not phone or len(pin)<4 or not pin.isdigit():
            flash("Enter valid account details.","error"); return redirect(url_for("register"))
        if User.query.filter_by(phone=phone).first():
            flash("That phone number is already registered.","error"); return redirect(url_for("register"))
        u=User(full_name=name,phone=phone,email=email,pin_hash=generate_password_hash(pin))
        db.session.add(u); db.session.commit(); login_user(u); audit("USER_REGISTERED")
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login",methods=["GET","POST"])
@limiter.limit("8 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.role=="admin" else "dashboard"))
    if request.method=="POST":
        phone=request.form.get("phone","").strip(); pin=request.form.get("pin","").strip()
        u=User.query.filter_by(phone=phone).first()
        if u and check_password_hash(u.pin_hash,pin):
            login_user(u); audit("LOGIN_SUCCESS")
            return redirect(url_for("admin_dashboard" if u.role=="admin" else "dashboard"))
        flash("Invalid phone number or PIN.","error")
    return render_template("login.html")

@app.get("/logout")
@login_required
def logout():
    logout_user(); return redirect(url_for("index"))

@app.get("/dashboard")
@login_required
def dashboard():
    if current_user.role=="admin": return redirect(url_for("admin_dashboard"))
    txns=Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.id.desc()).all()
    return render_template("dashboard.html",txns=txns)

@app.route("/receive",methods=["GET","POST"])
@login_required
def receive():
    if current_user.role=="admin": return redirect(url_for("admin_dashboard"))
    if not current_user.is_verified:
        flash("Your account must be verified first.","error"); return redirect(url_for("dashboard"))
    if request.method=="POST":
        country=request.form.get("country")
        try: amount=float(request.form.get("amount","0"))
        except: amount=0
        if country not in COUNTRIES or amount<=0:
            flash("Enter a valid transaction.","error"); return redirect(url_for("receive"))
        ref=make_reference(country)
        tx=Transaction(reference=ref,user_id=current_user.id,country=country,currency=COUNTRIES[country]["currency"],
            expected_amount=amount,receiving_reference=ref.replace("-",""),status="WAITING_FOR_RECEIVING_DETAILS")
        db.session.add(tx); db.session.commit(); audit("TRANSACTION_CREATED",tx.id)
        return redirect(url_for("transaction_detail",tx_id=tx.id))
    return render_template("receive.html",countries=COUNTRIES)

@app.get("/transaction/<int:tx_id>")
@login_required
def transaction_detail(tx_id):
    tx=db.session.get(Transaction,tx_id)
    if not tx or (tx.user_id!=current_user.id and current_user.role!="admin"): abort(404)
    instruction=latest_receiving_instruction(tx.id)
    receipt=Receipt.query.filter_by(transaction_id=tx.id).order_by(Receipt.id.desc()).first()
    return render_template("transaction.html",tx=tx,instruction=instruction,receipt=receipt)

@app.post("/transaction/<int:tx_id>/receipt")
@login_required
def receipt_upload(tx_id):
    tx=db.session.get(Transaction,tx_id)
    if not tx or tx.user_id!=current_user.id: abort(404)
    if not latest_receiving_instruction(tx.id):
        flash("Wait for receiving details first.","error"); return redirect(url_for("transaction_detail",tx_id=tx.id))
    file=request.files.get("receipt")
    if not file or not file.filename:
        flash("Choose a receipt.","error"); return redirect(url_for("transaction_detail",tx_id=tx.id))
    db.session.add(Receipt(transaction_id=tx.id,original_filename=file.filename[:255]))
    tx.status="RECEIPT_UPLOADED"; db.session.commit(); audit("RECEIPT_RECORDED",tx.id)
    return redirect(url_for("transaction_detail",tx_id=tx.id))

@app.get("/admin")
@login_required
@admin_required
def admin_dashboard():
    return render_template("admin.html",users=User.query.order_by(User.id.desc()).all(),
        txns=Transaction.query.order_by(Transaction.id.desc()).all())

@app.get("/admin/transaction/<int:tx_id>")
@login_required
@admin_required
def admin_transaction(tx_id):
    tx=db.session.get(Transaction,tx_id)
    if not tx: abort(404)
    history=ReceivingInstruction.query.filter_by(transaction_id=tx.id).order_by(ReceivingInstruction.id.desc()).all()
    logs=AuditLog.query.filter_by(transaction_id=tx.id).order_by(AuditLog.id.desc()).all()
    return render_template("admin_transaction.html",tx=tx,instruction=latest_receiving_instruction(tx.id),
        receiving_history=history,logs=logs,statuses=STATUSES)

@app.post("/admin/user/<int:user_id>/verify")
@login_required
@admin_required
def admin_verify_user(user_id):
    u=db.session.get(User,user_id)
    if not u: abort(404)
    u.is_verified=True; db.session.commit(); audit("ADMIN_VERIFIED_USER",details=f"user_id={u.id}")
    return redirect(url_for("admin_dashboard"))

@app.post("/admin/transaction/<int:tx_id>/receiving-details")
@login_required
@admin_required
def admin_send_receiving_details(tx_id):
    tx=db.session.get(Transaction,tx_id)
    if not tx: abort(404)
    bank=request.form.get("bank_name","").strip()
    name=request.form.get("account_name","").strip()
    number=request.form.get("account_number","").strip()
    branch=request.form.get("branch_or_code","").strip() or None
    pref=request.form.get("payment_reference","").strip() or tx.receiving_reference
    instructions=request.form.get("instructions","").strip() or None
    if not bank or not name or not number:
        flash("Bank name, account name and account number are required.","error")
        return redirect(url_for("admin_transaction",tx_id=tx.id))
    ReceivingInstruction.query.filter_by(transaction_id=tx.id,is_active=True).update({"is_active":False})
    db.session.add(ReceivingInstruction(transaction_id=tx.id,bank_name=bank,account_name=name,
        account_number=number,branch_or_code=branch,payment_reference=pref,instructions=instructions,
        sent_by_user_id=current_user.id,is_active=True))
    tx.status="RECEIVING_DETAILS_SENT"; db.session.commit()
    audit("ADMIN_SENT_RECEIVING_DETAILS",tx.id,details=f"bank={bank}")
    flash("Receiving details sent to this transaction.","success")
    return redirect(url_for("admin_transaction",tx_id=tx.id))

@app.post("/admin/transaction/<int:tx_id>/status")
@login_required
@admin_required
def admin_update_status(tx_id):
    tx=db.session.get(Transaction,tx_id)
    if not tx: abort(404)
    status=request.form.get("status")
    if status not in STATUSES: abort(400)
    tx.status=status; db.session.commit(); audit("ADMIN_UPDATED_STATUS",tx.id,details=status)
    return redirect(url_for("admin_transaction",tx_id=tx.id))

@app.get("/health")
def health(): return jsonify(status="ok",service="paycom")

with app.app_context():
    db.create_all()
    ensure_admin()

if __name__=="__main__":
    app.run(debug=os.getenv("FLASK_ENV")!="production")
