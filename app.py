import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import time
import uuid
from functools import wraps

import bcrypt
import pyotp
import qrcode
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g, send_file, abort)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing in .env")

_file_key = os.getenv("FILE_KEY")
if not _file_key:
    raise RuntimeError("FILE_KEY is missing in .env")
FILE_KEY = base64.urlsafe_b64decode(_file_key)
if len(FILE_KEY) != 32:
    raise RuntimeError("FILE_KEY must be 32 bytes (AES-256)")
aesgcm = AESGCM(FILE_KEY)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

MAX_FILE_MB = 10
app.config["MAX_CONTENT_LENGTH"] = (MAX_FILE_MB + 1) * 1024 * 1024
ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "docx", "xlsx", "pptx", "zip", "csv"}
STORAGE_DIR = "storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

DATABASE = "users.db"
OTP_VALID_SECONDS = 300
OTP_MAX_TRIES = 5
serializer = URLSafeTimedSerializer(app.secret_key)


# ---------- Token helpers ----------
def make_token(email, purpose):
    return serializer.dumps(email, salt=purpose)


def read_token(token, purpose, max_age):
    try:
        return serializer.loads(token, salt=purpose, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None


def send_email(to, subject, body):
    print("\n----- EMAIL (test mode) -----")
    print("To:", to)
    print("Subject:", subject)
    print(body)
    print("-----------------------------\n")


def strong_password(password):
    return (len(password) >= 8
            and len(password.encode("utf-8")) <= 72
            and re.search(r"[A-Za-z]", password)
            and re.search(r"\d", password))


# ---------- Email OTP helpers ----------
def hash_otp(code):
    return hmac.new(app.secret_key.encode(), code.encode(), hashlib.sha256).hexdigest()


def create_otp(user_id, email):
    code = f"{secrets.randbelow(1000000):06d}"
    db = get_db()
    db.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
    db.execute(
        "INSERT INTO otp_codes (user_id, code_hash, expires_at, attempts) "
        "VALUES (?, ?, ?, 0)",
        (user_id, hash_otp(code), time.time() + OTP_VALID_SECONDS),
    )
    db.commit()
    send_email(email, "Your login code",
               f"Your code is: {code}  (valid 5 minutes)")


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
    db.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            user_id INTEGER PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cols = [row[1] for row in db.execute("PRAGMA table_info(users)")]
    if "totp_secret" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    if "totp_enabled" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
    if "totp_attempts" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_attempts INTEGER NOT NULL DEFAULT 0")
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


def finish_login(user):
    session.clear()
    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session["role"] = user["role"]


@app.errorhandler(413)
def too_large(error):
    flash(f"File too large. Maximum is {MAX_FILE_MB} MB.", "error")
    return redirect(url_for("dashboard"))


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
            flash("Password must be 8-72 characters with letters and numbers.", "error")
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
    email = read_token(token, "verify", max_age=86400)
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

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        password_bytes = password.encode("utf-8")
        if user and len(password_bytes) <= 72 and bcrypt.checkpw(
                password_bytes, user["password_hash"].encode("utf-8")):
            if not user["is_verified"]:
                flash("Please verify your email first.", "error")
                return render_template("login.html")

            session.clear()
            session["pending_user_id"] = user["id"]

            if user["totp_enabled"]:
                db.execute("UPDATE users SET totp_attempts = 0 WHERE id = ?",
                           (user["id"],))
                db.commit()
                return redirect(url_for("totp"))

            create_otp(user["id"], user["email"])
            flash("A 6-digit code was sent to your email.", "success")
            return redirect(url_for("otp"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        db = get_db()
        row = db.execute(
            "SELECT * FROM otp_codes WHERE user_id = ?", (user_id,)
        ).fetchone()

        if not row or time.time() > row["expires_at"]:
            db.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
            db.commit()
            session.clear()
            flash("Code expired. Please log in again.", "error")
            return redirect(url_for("login"))

        if row["attempts"] >= OTP_MAX_TRIES:
            db.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
            db.commit()
            session.clear()
            flash("Too many wrong codes. Please log in again.", "error")
            return redirect(url_for("login"))

        if hmac.compare_digest(hash_otp(code), row["code_hash"]):
            user = db.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            db.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
            db.commit()
            finish_login(user)
            return redirect(url_for("dashboard"))

        db.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE user_id = ?",
                   (user_id,))
        db.commit()
        flash("Wrong code. Try again.", "error")

    return render_template("otp.html")


@app.route("/totp", methods=["GET", "POST"])
def totp():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not user["totp_enabled"]:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        if user["totp_attempts"] >= OTP_MAX_TRIES:
            session.clear()
            flash("Too many wrong codes. Please log in again.", "error")
            return redirect(url_for("login"))

        code = request.form.get("code", "").strip()
        if pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            db.execute("UPDATE users SET totp_attempts = 0 WHERE id = ?", (user_id,))
            db.commit()
            finish_login(user)
            return redirect(url_for("dashboard"))

        db.execute("UPDATE users SET totp_attempts = totp_attempts + 1 WHERE id = ?",
                   (user_id,))
        db.commit()
        flash("Wrong code. Try again.", "error")

    return render_template("totp.html")


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?",
                      (session["user_id"],)).fetchone()

    if user["totp_enabled"]:
        flash("Authenticator app is already enabled.", "success")
        return redirect(url_for("dashboard"))

    secret = user["totp_secret"]
    if not secret:
        secret = pyotp.random_base32()
        db.execute("UPDATE users SET totp_secret = ? WHERE id = ?",
                   (secret, user["id"]))
        db.commit()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            db.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?",
                       (user["id"],))
            db.commit()
            flash("Authenticator app enabled.", "success")
            return redirect(url_for("dashboard"))
        flash("Wrong code. Scan the QR again and retry.", "error")

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["email"], issuer_name="Secure Cloud Storage")
    buffer = io.BytesIO()
    qrcode.make(uri).save(buffer, format="PNG")
    qr = base64.b64encode(buffer.getvalue()).decode("ascii")

    return render_template("setup_2fa.html", qr=qr, secret=secret)


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
        flash("If that email exists, a reset link has been sent.", "success")
        return redirect(url_for("login"))
    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = read_token(token, "reset", max_age=1800)
    if not email:
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("forgot"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not strong_password(password):
            flash("Password must be 8-72 characters with letters and numbers.", "error")
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


# ---------- Files ----------
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT totp_enabled FROM users WHERE id = ?",
                      (session["user_id"],)).fetchone()
    files = db.execute(
        "SELECT * FROM files WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],)).fetchall()
    return render_template("dashboard.html",
                           totp_enabled=user["totp_enabled"],
                           files=files, max_mb=MAX_FILE_MB)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("Choose a file first.", "error")
        return redirect(url_for("dashboard"))

    name = secure_filename(file.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT:
        flash("File type not allowed.", "error")
        return redirect(url_for("dashboard"))

    data = file.read()
    if len(data) == 0:
        flash("The file is empty.", "error")
        return redirect(url_for("dashboard"))
    if len(data) > MAX_FILE_MB * 1024 * 1024:
        flash(f"File too large. Maximum is {MAX_FILE_MB} MB.", "error")
        return redirect(url_for("dashboard"))

    # Encrypt: a fresh random nonce for every file, stored before the ciphertext
    nonce = os.urandom(12)
    encrypted = nonce + aesgcm.encrypt(nonce, data, None)

    stored_name = uuid.uuid4().hex   # random name, the user's filename never touches the disk
    with open(os.path.join(STORAGE_DIR, stored_name), "wb") as f:
        f.write(encrypted)

    db = get_db()
    db.execute(
        "INSERT INTO files (user_id, original_name, stored_name, size) "
        "VALUES (?, ?, ?, ?)",
        (session["user_id"], name, stored_name, len(data)))
    db.commit()
    flash("File encrypted and uploaded.", "success")
    return redirect(url_for("dashboard"))


def get_own_file(file_id):
    # user_id check: users can only reach their own files
    row = get_db().execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, session["user_id"])).fetchone()
    if not row:
        abort(404)
    return row


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    row = get_own_file(file_id)
    path = os.path.join(STORAGE_DIR, row["stored_name"])
    if not os.path.exists(path):
        abort(404)
    with open(path, "rb") as f:
        blob = f.read()
    try:
        data = aesgcm.decrypt(blob[:12], blob[12:], None)
    except InvalidTag:
        flash("File is damaged or was changed.", "error")
        return redirect(url_for("dashboard"))
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=row["original_name"])


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    row = get_own_file(file_id)
    path = os.path.join(STORAGE_DIR, row["stored_name"])
    if os.path.exists(path):
        os.remove(path)
    db = get_db()
    db.execute("DELETE FROM files WHERE id = ?", (row["id"],))
    db.commit()
    flash("File deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)  # debug=True only for development