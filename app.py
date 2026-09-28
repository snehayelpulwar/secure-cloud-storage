import os
import re
import sqlite3
from functools import wraps

import bcrypt
from dotenv import load_dotenv
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

load_dotenv()  # reads the .env file

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing in .env")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = "users.db"
serializer = URLSafeTimedSerializer(app.secret_key)


# ---------- Token helpers ----------
def make_token(email, purpose):
    # purpose = "verify" or "reset", so one token type can't be used for the other
    return serializer.dumps(email, salt=purpose)


def read_token(token, purpose, max_age):
    try:
        return serializer.loads(token, salt=purpose, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None


def send_email(to, subject, body):
    # TEMPORARY: prints in the terminal. We replace this with real email later.
    print("\n----- EMAIL (test mode) -----")
    print("To:", to)
    print("Subject:", subject)
    print(body)
    print("-----------------------------\n")


def strong_password(password):
    return (len(password) >= 8
            and len(password.encode("utf-8")) <= 72  # bcrypt limit
            and re.search(r"[A-Za-z]", password)
            and re.search(r"\d", password))


# ---------- Database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_verified INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()
    db.close()


# ---------- Login protection ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------- Routes ----------
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Enter a valid email address.", "error")
        elif not strong_password(password):
            flash("Password must be 8+ characters with letters and numbers.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, hashed.decode("utf-8")),
                )
                db.commit()

                token = make_token(email, "verify")
                link = url_for("verify_email", token=token, _external=True)
                send_email(email, "Verify your account",
                           f"Click to verify (valid 24 hours): {link}")

                flash("Account created. Check your email to verify.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "error")

    return render_template("register.html")


@app.route("/verify/<token>")
def verify_email(token):
    email = read_token(token, "verify", max_age=86400)  # 24 hours
    if not email:
        flash("Verification link is invalid or expired.", "error")
        return redirect(url_for("login"))
    db = get_db()
    db.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
    db.commit()
    flash("Email verified. You can log in now.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        password_bytes = password.encode("utf-8")
        if user and len(password_bytes) <= 72 and bcrypt.checkpw(
                password_bytes, user["password_hash"].encode("utf-8")):
            if not user["is_verified"]:
                flash("Please verify your email first.", "error")
                return render_template("login.html")
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = get_db().execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user:
            token = make_token(email, "reset")
            link = url_for("reset_password", token=token, _external=True)
            send_email(email, "Reset your password",
                       f"Click to reset (valid 30 minutes): {link}")
        # Same message whether or not the email exists (prevents user enumeration)
        flash("If that email exists, a reset link has been sent.", "success")
        return redirect(url_for("login"))
    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = read_token(token, "reset", max_age=1800)  # 30 minutes
    if not email:
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("forgot"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not strong_password(password):
            flash("Password must be 8+ characters with letters and numbers.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            db = get_db()
            db.execute("UPDATE users SET password_hash = ? WHERE email = ?",
                       (hashed.decode("utf-8"), email))
            db.commit()
            flash("Password changed. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("reset.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)  # debug=True only for development