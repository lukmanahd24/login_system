import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "csv", "docx"}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit


# ---------- Database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


# ---------- Helpers ----------
def current_user():
    if "user" not in g:
        uid = session.get("user_id")
        g.user = None
        if uid is not None:
            g.user = get_db().execute(
                "SELECT * FROM users WHERE id = ?", (uid,)
            ).fetchone()
    return g.user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def user_upload_dir(user_id):
    path = os.path.join(UPLOAD_ROOT, str(user_id))
    os.makedirs(path, exist_ok=True)
    return path


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("_csrf")
        if not token or token != request.form.get("_csrf"):
            abort(400, "Invalid or missing CSRF token")


@app.context_processor
def inject_globals():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return {"csrf_token": session["_csrf"], "current_user": current_user()}


# ---------- Auth ----------
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("profile"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            error = "Username must be 3-30 characters: letters, numbers, underscore."
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."

        if error is None:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password),
                     datetime.utcnow().strftime("%Y-%m-%d %H:%M")),
                )
                db.commit()
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Username or email is already registered."
        flash(error, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower()),
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["_csrf"] = secrets.token_hex(16)
            return redirect(url_for("profile"))
        flash("Invalid username/email or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


# ---------- User details ----------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()[:100]
        phone = request.form.get("phone", "").strip()[:20]
        email = request.form.get("email", "").strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
        else:
            try:
                db = get_db()
                db.execute(
                    "UPDATE users SET full_name = ?, phone = ?, email = ? WHERE id = ?",
                    (full_name, phone, email, user["id"]),
                )
                db.commit()
                flash("Details updated.", "success")
                return redirect(url_for("profile"))
            except sqlite3.IntegrityError:
                flash("That email is already in use.", "error")
    return render_template("profile.html", user=user)


# ---------- File access ----------
@app.route("/files")
@login_required
def files():
    rows = get_db().execute(
        "SELECT * FROM files WHERE user_id = ? ORDER BY id DESC",
        (current_user()["id"],),
    ).fetchall()
    return render_template("files.html", files=rows,
                           allowed=", ".join(sorted(ALLOWED_EXTENSIONS)))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if file is None or file.filename == "":
        flash("Choose a file to upload.", "error")
        return redirect(url_for("files"))
    original = secure_filename(file.filename)
    if not original or not allowed_file(original):
        flash("File type not allowed.", "error")
        return redirect(url_for("files"))

    user = current_user()
    ext = original.rsplit(".", 1)[1].lower()
    stored = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(user_upload_dir(user["id"]), stored)
    file.save(path)

    db = get_db()
    db.execute(
        "INSERT INTO files (user_id, original_name, stored_name, size, uploaded_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (user["id"], original, stored, os.path.getsize(path),
         datetime.utcnow().strftime("%Y-%m-%d %H:%M")),
    )
    db.commit()
    flash("File uploaded.", "success")
    return redirect(url_for("files"))


def get_own_file(file_id):
    row = get_db().execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, current_user()["id"]),
    ).fetchone()
    if row is None:
        abort(404)  # also hides other users' files
    return row


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    row = get_own_file(file_id)
    return send_from_directory(
        user_upload_dir(current_user()["id"]), row["stored_name"],
        as_attachment=True, download_name=row["original_name"],
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    row = get_own_file(file_id)
    path = os.path.join(user_upload_dir(current_user()["id"]), row["stored_name"])
    if os.path.exists(path):
        os.remove(path)
    db = get_db()
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    flash("File deleted.", "success")
    return redirect(url_for("files"))


@app.errorhandler(413)
def too_large(_e):
    flash("File is too large (max 5 MB).", "error")
    return redirect(url_for("files"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
