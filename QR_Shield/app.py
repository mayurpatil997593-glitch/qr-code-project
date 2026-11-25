import os
import re
import io
import secrets
from contextlib import contextmanager
from urllib.parse import urlparse

import cv2
import numpy as np
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-this-secret-before-deploy")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "/tmp/qr_shield_uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "webp"}

@contextmanager
def get_db():
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL is missing. Set it in your .env file or Render Environment.")
    # Render may provide postgres://; psycopg2 accepts postgresql://.
    database_url = database_url.replace("postgres://", "postgresql://", 1)
    conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor, connect_timeout=10)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    statements = [
        """CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(180) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'user',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            original_filename TEXT,
            decoded_content TEXT NOT NULL,
            content_type VARCHAR(20) NOT NULL,
            risk_score INTEGER NOT NULL,
            verdict VARCHAR(30) NOT NULL,
            findings JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )"""
    ]
    with get_db() as conn:
        with conn.cursor() as cur:
            for sql in statements:
                cur.execute(sql)
            admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
            admin_password = os.getenv("ADMIN_PASSWORD", "")
            if admin_email and admin_password:
                cur.execute("SELECT id FROM users WHERE email=%s", (admin_email,))
                if not cur.fetchone():
                    cur.execute(
                        "INSERT INTO users (username,email,password_hash,role) VALUES (%s,%s,%s,'admin')",
                        ("admin", admin_email, generate_password_hash(admin_password))
                    )

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def decode_qr(image_path):
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError("The uploaded file could not be read as an image.")
    detector = cv2.QRCodeDetector()
    decoded, points, _ = detector.detectAndDecode(image)
    if not decoded:
        raise ValueError("No readable QR code was found. Try a clearer PNG or JPG image.")
    return decoded.strip()

def analyze_content(content):
    """Static, offline checks only. The URL is never opened or fetched."""
    findings = []
    score = 0
    parsed = urlparse(content.strip())
    is_url = parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)

    if not is_url:
        findings.append("QR content is not an HTTP/HTTPS URL. Treat unknown text or contact details carefully.")
        return {"score": 10, "verdict": "Review", "content_type": "Text", "findings": findings}

    host = (parsed.hostname or "").lower()
    if parsed.scheme.lower() == "http":
        score += 20
        findings.append("The link uses HTTP, not HTTPS. The connection may not be encrypted.")
    else:
        findings.append("The link uses HTTPS. This does not by itself prove that the site is trustworthy.")

    if "@" in parsed.netloc:
        score += 25
        findings.append("The URL contains an @ symbol in its authority section, which can be used to disguise the destination.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 20
        findings.append("The hostname contains internationalized/punycode text. Check for look-alike characters.")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 20
        findings.append("The destination uses an IP address instead of a recognizable domain name.")

    suspicious_terms = ("login", "verify", "account", "password", "secure", "wallet", "bank", "update")
    matched = [term for term in suspicious_terms if term in (host + parsed.path + parsed.query).lower()]
    if matched:
        score += min(20, 5 * len(matched))
        findings.append("The URL contains sensitive-action words: " + ", ".join(matched) + ".")

    if len(content) > 180:
        score += 10
        findings.append("The URL is unusually long.")

    if host.count("-") >= 3:
        score += 10
        findings.append("The hostname contains several hyphens, which can sometimes appear in deceptive domains.")

    score = min(score, 100)
    verdict = "Safe-looking" if score < 25 else ("Suspicious" if score < 60 else "High Risk")
    if score == 0:
        findings.append("No obvious warning signs were found by the basic checks.")
    findings.append("This is a heuristic result, not a guarantee. Use a trusted reputation service for deeper checks.")
    return {"score": score, "verdict": verdict, "content_type": "URL", "findings": findings}

@app.context_processor
def inject_user():
    return {"current_user": session.get("username"), "current_role": session.get("role")}

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 8 or "@" not in email:
            flash("Enter a username (at least 3 characters), valid email, and password (at least 8 characters).", "danger")
            return render_template("register.html")
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO users (username,email,password_hash) VALUES (%s,%s,%s) RETURNING id",
                        (username, email, generate_password_hash(password))
                    )
                    user_id = cur.fetchone()["id"]
            session.update(user_id=user_id, username=username, role="user")
            flash("Account created successfully.", "success")
            return redirect(url_for("dashboard"))
        except psycopg2.errors.UniqueViolation:
            flash("That username or email is already registered.", "danger")
        except Exception as exc:
            app.logger.exception("Registration failed: %s", exc)
            flash("Registration failed. Check the database connection and try again.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
                    user = cur.fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session.update(user_id=user["id"], username=user["username"], role=user["role"])
                return redirect(url_for("dashboard"))
            flash("Invalid email or password.", "danger")
        except Exception as exc:
            app.logger.exception("Login failed: %s", exc)
            flash("Could not connect to the database. Check DATABASE_URL.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS total FROM scans WHERE user_id=%s", (session["user_id"],))
            total = cur.fetchone()["total"]
            cur.execute("SELECT COUNT(*) AS risky FROM scans WHERE user_id=%s AND risk_score >= 60", (session["user_id"],))
            risky = cur.fetchone()["risky"]
            cur.execute("SELECT * FROM scans WHERE user_id=%s ORDER BY created_at DESC LIMIT 5", (session["user_id"],))
            recent = cur.fetchall()
    return render_template("dashboard.html", total=total, risky=risky, recent=recent)

@app.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():
    result = None
    if request.method == "POST":
        upload = request.files.get("qr_image")
        if not upload or not upload.filename:
            flash("Choose a QR image first.", "warning")
            return render_template("scanner.html", result=None)
        if not allowed_file(upload.filename):
            flash("Allowed formats: PNG, JPG, JPEG, BMP, WEBP.", "danger")
            return render_template("scanner.html", result=None)
        filename = secure_filename(upload.filename)
        unique_name = secrets.token_hex(8) + "_" + filename
        path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        upload.save(path)
        try:
            decoded = decode_qr(path)
            analysis = analyze_content(decoded)
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """INSERT INTO scans
                        (user_id, original_filename, decoded_content, content_type, risk_score, verdict, findings)
                        VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                        (session["user_id"], filename, decoded, analysis["content_type"],
                         analysis["score"], analysis["verdict"], Json(analysis["findings"]))
                    )
                    scan_id = cur.fetchone()["id"]
            result = {**analysis, "decoded": decoded, "scan_id": scan_id}
        except ValueError as exc:
            flash(str(exc), "danger")
        except Exception as exc:
            app.logger.exception("Scan failed: %s", exc)
            flash("Scan could not be saved. Check database connection.", "danger")
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    return render_template("scanner.html", result=result)

@app.route("/history")
@login_required
def history():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE user_id=%s ORDER BY created_at DESC LIMIT 100", (session["user_id"],))
            scans = cur.fetchall()
    return render_template("history.html", scans=scans)

@app.route("/report/<int:scan_id>")
@login_required
def report(scan_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id=%s AND user_id=%s", (scan_id, session["user_id"]))
            scan = cur.fetchone()
    if not scan:
        flash("Report not found.", "danger")
        return redirect(url_for("history"))
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 55
    pdf.setTitle(f"QR Shield Scan Report {scan_id}")
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(50, y, "QR SHIELD - SECURITY SCAN REPORT")
    y -= 35
    pdf.setFont("Helvetica", 10)
    lines = [
        f"Scan ID: {scan['id']}",
        f"Date: {scan['created_at']}",
        f"Type: {scan['content_type']}",
        f"Verdict: {scan['verdict']}",
        f"Risk score: {scan['risk_score']}/100",
        "Decoded content: " + scan["decoded_content"][:250],
        "",
        "Findings:"
    ]
    for line in lines:
        pdf.drawString(50, y, line[:110])
        y -= 18
    for item in scan["findings"]:
        wrapped = str(item)
        pdf.drawString(60, y, "- " + wrapped[:105])
        y -= 17
        if y < 65:
            pdf.showPage()
            y = height - 55
            pdf.setFont("Helvetica", 10)
    y -= 15
    pdf.drawString(50, y, "Disclaimer: Automated heuristic checks are not a guarantee of safety.")
    pdf.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"qr-shield-report-{scan_id}.pdf", mimetype="application/pdf")

@app.route("/admin")
@login_required
def admin():
    if session.get("role") != "admin":
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard"))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,username,email,role,created_at FROM users ORDER BY created_at DESC")
            users = cur.fetchall()
            cur.execute("SELECT s.*,u.username FROM scans s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC LIMIT 100")
            scans = cur.fetchall()
    return render_template("admin.html", users=users, scans=scans)

@app.errorhandler(413)
def too_large(_error):
    flash("Image is too large. Maximum upload size is 5 MB.", "danger")
    return redirect(url_for("scanner"))

@app.route("/health")
def health():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return {"status": "ok", "database": "connected"}, 200
    except Exception as exc:
        app.logger.exception("Health check failed: %s", exc)
        return {"status": "error", "database": "unavailable"}, 503

# Initialize tables when the module is imported by Gunicorn on Render.
try:
    init_db()
    app.logger.info("Database tables are ready.")
except Exception as exc:
    app.logger.exception("Database initialization failed: %s", exc)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG") == "1")
