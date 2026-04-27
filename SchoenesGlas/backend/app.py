"""
SchönesGlas – Mitarbeiterportal Backend
Flask + SQLite, password hashing via Werkzeug (PBKDF2-SHA256)
"""
import os
import sqlite3
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash

# ── Secret key (generated once, persisted so sessions survive restarts) ──────
_KEY_FILE = os.path.join(os.path.dirname(__file__), ".secret_key")
if os.path.exists(_KEY_FILE):
    with open(_KEY_FILE, "rb") as _f:
        _SECRET = _f.read()
else:
    _SECRET = os.urandom(32)
    with open(_KEY_FILE, "wb") as _f:
        _f.write(_SECRET)

app = Flask(__name__)
app.secret_key = _SECRET
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DB_PATH = os.path.join(os.path.dirname(__file__), "workers.db")

# Parent directory that contains all the static website files (index.html etc.)
SITE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ── DB helper ─────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Auth decorator ────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "worker_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))


# ── Serve the static website ──────────────────────────────────────────────────
@app.route("/site/")
def site_index():
    return send_from_directory(SITE_ROOT, "index.html")


@app.route("/site/<path:filename>")
def site_file(filename):
    """Serve any static file from the SchoenesGlas/ root (HTML, CSS, images)."""
    return send_from_directory(SITE_ROOT, filename)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "worker_id" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        login_id = request.form.get("login", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        worker = db.execute(
            "SELECT * FROM workers WHERE login = ?", (login_id,)
        ).fetchone()
        db.close()

        if worker and check_password_hash(worker["password"], password):
            session["worker_id"] = worker["id"]
            session["worker_login"] = worker["login"]
            session["worker_email"] = worker["email"]
            return redirect(url_for("dashboard"))
        else:
            # Same message for wrong login OR wrong password (no user enumeration)
            error = "Ungültige Anmeldedaten. Bitte erneut versuchen."

    return render_template("login.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    worker = db.execute(
        "SELECT id, login, email FROM workers WHERE id = ?",
        (session["worker_id"],),
    ).fetchone()
    db.close()
    return render_template("dashboard.html", worker=worker)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    error = None
    success = None

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        db = get_db()
        worker = db.execute(
            "SELECT * FROM workers WHERE id = ?", (session["worker_id"],)
        ).fetchone()

        if not check_password_hash(worker["password"], current_pw):
            error = "Das aktuelle Passwort ist falsch."
        elif len(new_pw) < 8:
            error = "Das neue Passwort muss mindestens 8 Zeichen lang sein."
        elif new_pw == current_pw:
            error = "Das neue Passwort muss sich vom alten unterscheiden."
        elif new_pw != confirm_pw:
            error = "Die neuen Passwörter stimmen nicht überein."
        else:
            db.execute(
                "UPDATE workers SET password = ? WHERE id = ?",
                (generate_password_hash(new_pw), session["worker_id"]),
            )
            db.commit()
            success = "Passwort wurde erfolgreich geändert."

        db.close()

    return render_template("change_password.html", error=error, success=success)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
