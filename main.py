from datetime import datetime, date
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
import calendar as calmod
import os

# --- SMS (Twilio) ---
try:
    from twilio.rest import Client
except Exception:  # twilio not installed is OK — we’ll no-op send_sms
    Client = None

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# ---- Twilio config ----
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER")


def send_sms(to_number: str, body: str) -> bool:
    """
    Send an SMS via Twilio. Returns True on success, False otherwise.
    Gracefully no-ops if Twilio isn't configured or number is empty.
    """
    if not to_number or not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER):
        return False
    if Client is None:
        return False
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(to=to_number, from_=TWILIO_FROM_NUMBER, body=body)
        return True
    except Exception:
        return False


# ---- Database config (SQLite) ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ABS_DB_PATH = os.path.join(BASE_DIR, "site.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{ABS_DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
print("Using DB at:", ABS_DB_PATH)

db = SQLAlchemy(app)

# ===========================
#           MODELS
# ===========================

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(120), nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Access role: "user" (default) or "boss" (calendar-only view + cancel)
    role = db.Column(db.String(20), default="user")
    # phone for SMS (E.164 preferred, e.g. +15551234567)
    phone = db.Column(db.String(32))

    def set_password(self, raw_password: str):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)


class Appointment(db.Model):
    __tablename__ = "appointment"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False, default="Appointment")
    start_at = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.Text)
    services = db.Column(db.Text)            # comma-separated list of selected services
    canceled = db.Column(db.Boolean, default=False)  # soft cancel flag

    user = db.relationship("User", backref=db.backref("appointments", lazy=True))


# ---- Ensure tables exist + safe migrations for new columns ----
with app.app_context():
    db.create_all()
    # add role if missing
    try:
        db.session.execute(text('ALTER TABLE "user" ADD COLUMN role VARCHAR(20) DEFAULT "user";'))
        db.session.execute(text('UPDATE "user" SET role="user" WHERE role IS NULL;'))
        db.session.commit()
        print("Migration: added 'role' column to user.")
    except Exception:
        db.session.rollback()
    # add canceled if missing
    try:
        db.session.execute(text('ALTER TABLE "appointment" ADD COLUMN canceled BOOLEAN DEFAULT 0;'))
        db.session.commit()
        print("Migration: added 'canceled' column to appointment.")
    except Exception:
        db.session.rollback()
    # add phone to user if missing
    try:
        db.session.execute(text('ALTER TABLE "user" ADD COLUMN phone VARCHAR(32);'))
        db.session.commit()
        print("Migration: added 'phone' column to user.")
    except Exception:
        db.session.rollback()

# ===========================
#        ACCESS HELPERS
# ===========================

def is_logged_in():
    return "user_id" in session

def is_boss():
    return session.get("role") == "boss"

def block_boss_only(fn):
    """
    If a user is 'boss' (calendar-only), redirect them to the calendar.
    Use this on routes bosses should NOT access.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if is_logged_in() and is_boss():
            today = date.today()
            return redirect(url_for("calendar_view", year=today.year, month=today.month))
        return fn(*args, **kwargs)
    return wrapper

# ===========================
#           ROUTES
# ===========================

# ---- Sign in (Home) ----
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        password = request.form.get("password", "")

        if not fullname or not password:
            flash("Please enter both your full name and password.")
            return render_template("home.html")

        user = User.query.filter_by(fullname=fullname).first()
        if not user or not user.check_password(password):
            flash("Invalid credentials.")
            return render_template("home.html")

        # Save user info in session
        session["user_id"] = user.id
        session["user_name"] = user.fullname
        session["role"] = (user.role or "user")

        # Boss lands on calendar directly
        if is_boss():
            today = date.today()
            return redirect(url_for("calendar_view", year=today.year, month=today.month))

        return redirect(url_for("main"))

    return render_template("home.html")


# ---- Main page ----
@app.route("/main")
@block_boss_only
def main():
    if not is_logged_in():
        flash("Please log in first.")
        return redirect(url_for("home"))
    return render_template("main.html", name=session.get("user_name"), is_boss=is_boss())


# ---- Logout ----
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


# ---- Create Account ----
@app.route("/create-account", methods=["GET", "POST"])
@block_boss_only
def create_account():
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not fullname or not email or not password:
            flash("All fields are required.")
            return render_template("create_account.html")
        if password != confirm:
            flash("Passwords do not match.")
            return render_template("create_account.html")
        if User.query.filter_by(email=email).first():
            flash("That email is already registered.")
            return render_template("create_account.html")

        user = User(fullname=fullname, email=email, phone=phone or None)  # role defaults to "user"
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created! You can log in now.")
        return redirect(url_for("home"))

    return render_template("create_account.html")


# ---- Forgot Password (stub) ----
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Please enter your email.")
            return render_template("forgot_password.html")
        flash("If that email is registered, a reset link has been sent.")
        return redirect(url_for("home"))
    return render_template("forgot_password.html")


# ---- Create Appointment (customer) ----
@app.route("/appointments/new", methods=["GET", "POST"], endpoint="create_appointment")
@block_boss_only
def create_appointment():
    if not is_logged_in():
        flash("Please log in first.")
        return redirect(url_for("home"))

    if request.method == "POST":
        # Expecting checkboxes named "services" (accordion groups) and an optional 'special_request'
        services_list = request.form.getlist("services")
        special_request = (request.form.get("special_request", "") or "").strip()
        if special_request:
            services_list.append(f"Special Request: {special_request}")

        if not services_list:
            flash("Please select at least one service.")
            return render_template("create_appointment.html")

        date_str = request.form.get("date", "").strip()
        time_str = request.form.get("time", "").strip()

        try:
            start_at = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
        except ValueError:
            flash("Invalid date or time format.")
            return render_template("create_appointment.html")

        services_str = ", ".join(services_list)
        # a simple title: use first service if present
        title = services_list[0] if services_list else "Appointment"

        appt = Appointment(
            user_id=session["user_id"],
            title=title,
            start_at=start_at,
            notes=None,
            services=services_str,
        )
        db.session.add(appt)
        db.session.commit()

        flash("Appointment created!")
        return redirect(url_for("main"))

    # GET
    return render_template("create_appointment.html")


# ---- List Appointments (customer) ----
@app.route("/appointments")
@block_boss_only
def list_appointments():
    if not is_logged_in():
        flash("Please log in first.")
        return redirect(url_for("home"))
    appts = (
        Appointment.query
        .filter_by(user_id=session["user_id"])
        .order_by(Appointment.start_at.asc())
        .all()
    )
    return render_template("appointments.html", appts=appts)


# ---- Customer: cancel Appointment (soft cancel) ----
@app.route("/appointments/<int:appt_id>/cancel", methods=["POST"])
@block_boss_only
def customer_cancel_appointment(appt_id):
    if not is_logged_in():
        flash("Please log in first.")
        return redirect(url_for("home"))

    appt = Appointment.query.filter_by(id=appt_id, user_id=session["user_id"]).first()
    if not appt:
        flash("Appointment not found.")
        return redirect(url_for("list_appointments"))

    if appt.canceled:
        flash("This appointment is already canceled.")
        return redirect(url_for("list_appointments"))

    appt.canceled = True
    db.session.commit()
    flash("Appointment canceled.")
    return redirect(url_for("list_appointments"))


# ---- Hard delete (boss/admin only) ----
@app.route("/appointments/<int:appt_id>/delete", methods=["POST"], endpoint="delete_appointment")
def delete_appointment(appt_id):
    if not is_logged_in():
        flash("Please log in first.")
        return redirect(url_for("home"))
    if not is_boss():
        flash("Unauthorized.")
        return redirect(url_for("home"))

    appt = Appointment.query.get(appt_id)
    if not appt:
        flash("Appointment not found.")
        return redirect(url_for("calendar_view"))
    db.session.delete(appt)
    db.session.commit()
    flash("Appointment permanently deleted.")
    return redirect(url_for("calendar_view"))


# ---- Boss: mark appointment canceled (soft) + SMS notify user ----
@app.route("/boss/appointments/<int:appt_id>/cancel", methods=["POST"])
def boss_cancel(appt_id):
    if not is_logged_in() or not is_boss():
        flash("Unauthorized.")
        return redirect(url_for("home"))

    appt = Appointment.query.get(appt_id)
    if not appt:
        flash("Appointment not found.")
        return redirect(url_for("calendar_view"))

    if not appt.canceled:
        appt.canceled = True
        db.session.commit()

        # Build a friendly message
        dt_str = appt.start_at.strftime("%b %d, %Y at %I:%M %p")
        name = appt.user.fullname
        body = (
            f"Hi {name}, your appointment on {dt_str} has been canceled. "
            f"If you'd like to reschedule, please reply or book again."
        )
        # Try sending SMS (non-blocking failure)
        sent = send_sms(appt.user.phone, body)
        if not sent:
            flash("Appointment canceled, but SMS notification could not be sent (check Twilio config or phone).")
    else:
        flash("This appointment was already canceled.")

    # return to same month if provided
    y = request.args.get("year")
    m = request.args.get("month")
    if y and m:
        try:
            y, m = int(y), int(m)
            return redirect(url_for("calendar_view", year=y, month=m))
        except ValueError:
            pass
    return redirect(url_for("calendar_view"))


# ---- Calendar View (all logged-in users) ----
@app.route("/calendar")
def calendar_view():
    if not is_logged_in():
        flash("Please log in first.")
        return redirect(url_for("home"))

    try:
        year = int(request.args.get("year", date.today().year))
        month = int(request.args.get("month", date.today().month))
    except ValueError:
        year, month = date.today().year, date.today().month

    if month < 1 or month > 12:
        month = date.today().month

    month_name = calmod.month_name[month]
    weeks = calmod.monthcalendar(year, month)

    month_start = datetime(year, month, 1)
    month_end = datetime(year + (month // 12), (month % 12) + 1, 1)

    # Boss sees ALL appointments; users see only their own
    base_q = Appointment.query.filter(
        Appointment.start_at >= month_start,
        Appointment.start_at < month_end
    )
    if not is_boss():
        base_q = base_q.filter(Appointment.user_id == session["user_id"])

    appts = base_q.order_by(Appointment.start_at.asc()).all()

    appts_by_day = {}
    for a in appts:
        appts_by_day.setdefault(a.start_at.day, []).append(a)

    prev_year, prev_month = (year, month - 1) if month > 1 else (year - 1, 12)
    next_year, next_month = (year, month + 1) if month < 12 else (year + 1, 1)

    return render_template(
        "calendar.html",
        year=year,
        month=month,
        month_name=month_name,
        weeks=weeks,
        appts_by_day=appts_by_day,
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
        is_boss=is_boss(),
    )


if __name__ == "__main__":
    app.run(debug=True)
