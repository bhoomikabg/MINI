# app.py
import os
import json
import time
import uuid
import re
import sqlite3
from functools import wraps
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

# ---------- Configuration ----------
APP_LOG = os.environ.get("HONEYPOT_LOG", "/var/log/honeypot_login/honeypot_login.log")
DB_PATH = os.environ.get("HONEYPOT_DB", "./honeypot.db")  # default in project dir
SECRET_KEY = os.environ.get("SECRET_KEY", "change_this_secret_for_prod")

# Ensure log directory exists (safe)
log_dir = os.path.dirname(APP_LOG) or "."
try:
    os.makedirs(log_dir, exist_ok=True)
except Exception as e:
    # Don't crash the app if we can't create the log directory (e.g., permission issues on Windows)
    print(f"Warning: cannot create log dir {log_dir}: {e}")

# Ensure DB directory exists if DB_PATH uses a directory
db_dir = os.path.dirname(os.path.abspath(DB_PATH))
if db_dir and not os.path.exists(db_dir):
    try:
        os.makedirs(db_dir, exist_ok=True)
    except Exception as e:
        print("Warning: failed to create DB directory:", e)

# Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------- Rate-limiting & basic heuristics ----------
RATE_LIMIT_WINDOW = 60      # seconds
RATE_LIMIT_MAX = 10         # max attempts per window before temporary block
TEMP_BLOCK_SECONDS = 300    # block length if quota exceeded

attempts = {}       # ip -> [timestamps]
temp_blocks = {}    # ip -> unblock_ts
allowlist = {}      # ip -> expiry_ts

SUSPICIOUS_KEYWORDS = [
    r"ignore previous instructions",
    r"exfiltrat", r"open the file", r"password", r"token",
    r"exec\(", r"system prompt", r"drop database", r"base64"
]
COMMON_ADMIN_USERNAMES = {"admin", "root", "administrator", "test", "guest", "operator"}

# ---------- Logging helpers ----------
def now_ts():
    return datetime.utcnow().isoformat() + "Z"

def append_log(event: dict):
    try:
        with open(APP_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        print("Failed to write log:", e)

# ---------- SQLite helpers ----------
def get_db_conn():
    """Return a sqlite3 connection. Caller should close it."""
    conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create users table if not exists."""
    conn = get_db_conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

def get_user_by_username(username: str):
    conn = get_db_conn()
    try:
        cur = conn.execute("SELECT id, username, password_hash, created_at FROM users WHERE username = ? LIMIT 1", (username,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

# Initialize DB at startup
init_db()

# ---------- IP + scoring helpers ----------
def ip_from_request():
    xf = request.headers.get("X-Forwarded-For", "")
    if xf:
        return xf.split(",")[0].strip()
    return request.remote_addr or "unknown"

def score_attempt(username: str, password: str, ua: str, ip: str):
    score = 0
    reasons = []

    # network identity (simple heuristics)
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        score -= 2

    if username.lower() in COMMON_ADMIN_USERNAMES:
        score += 20
        reasons.append("common-admin-username")

    ua_l = (ua or "").lower()
    if ua_l.startswith("python-requests") or ua_l.startswith("curl/") or "bot" in ua_l:
        score += 10
        reasons.append("script-user-agent")

    if len(password) > 100 or re.search(r'^[A-Za-z0-9+/=]{200,}$', password):
        score += 20
        reasons.append("long-or-base64-password")

    for kw in SUSPICIOUS_KEYWORDS:
        if re.search(kw, (username + " " + password).lower()):
            score += 25
            reasons.append("injection-keyword")

    return score, reasons

def record_attempt(username, password):
    ip = ip_from_request()
    ua = request.headers.get("User-Agent", "")
    ts = now_ts()
    event = {
        "id": str(uuid.uuid4()),
        "ts": ts,
        "src_ip": ip,
        "user_agent": ua,
        "username": username,
        "password_snippet": (password[:200] + ("..." if len(password) > 200 else "")),
        "full_password_length": len(password),
        "path": request.path,
        "method": request.method,
        "headers": {k:v for k,v in request.headers.items()},
    }
    append_log(event)
    return event

def rate_limit_check(ip):
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    arr = attempts.get(ip, [])
    arr = [t for t in arr if t >= window_start]
    arr.append(now)
    attempts[ip] = arr
    if ip in temp_blocks and temp_blocks[ip] > now:
        return False, f"temporarily blocked until {datetime.utcfromtimestamp(temp_blocks[ip]).isoformat()}Z"
    if len(arr) > RATE_LIMIT_MAX:
        temp_blocks[ip] = now + TEMP_BLOCK_SECONDS
        return False, "rate limit exceeded - temporary block"
    return True, None

# ---------- Flask routes ----------
def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if session.get("authed"):
            return f(*args, **kwargs)
        return redirect(url_for("login", next=request.path))
    return inner

@app.route("/", methods=["GET"])
def root():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def do_login():
    ip = ip_from_request()
    ok, reason = rate_limit_check(ip)
    ua = request.headers.get("User-Agent", "")
    username = (request.form.get("username", "") or "").strip()
    password = (request.form.get("password", "") or "")

    # log attempt
    event = record_attempt(username, password)

    if not ok:
        event2 = {"event":"rate_limited", "id":event["id"], "ts": now_ts(), "src_ip": ip, "reason": reason}
        append_log(event2)
        flash("Login failed: Rate limit exceeded", "error")
        return render_template("login.html"), 429

    # score attempt
    score, reasons = score_attempt(username, password, ua, ip)
    append_log({"event":"scored", "id": event["id"], "score": score, "reasons": reasons})

    # lookup user in DB (secure paramized query)
    user = get_user_by_username(username)
    is_legit = False
    if user:
        try:
            if check_password_hash(user["password_hash"], password):
                is_legit = True
        except Exception as e:
            # any check error treat as failure but log
            append_log({"event":"pw_check_error","id":event["id"], "ts": now_ts(), "error": str(e)})

    # allowlist can modify behavior (demo policy)
    if ip in allowlist and allowlist[ip] > time.time():
        # in demo, allowlist grants trust; you may change this policy
        is_legit = is_legit or True

    if is_legit and score < 80:
        session["authed"] = True
        session["user"] = username
        append_log({"event":"login_success","id":event["id"], "ts": now_ts(), "src_ip": ip, "user": username})
        return redirect(url_for("dashboard"))

    append_log({"event":"login_failed","id":event["id"], "ts": now_ts(), "src_ip": ip, "user": username, "score": score, "reasons": reasons})
    flash("Invalid username or password", "error")
    return render_template("login.html"), 403

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session.get("user"))

@app.route("/logs_tail")
def logs_tail():
    if request.remote_addr not in ("127.0.0.1", "localhost"):
        return "Forbidden", 403
    try:
        N = int(request.args.get("n", "40"))
        with open(APP_LOG, "r", encoding="utf-8") as f:
            lines = f.read().strip().splitlines()[-N:]
        return "<pre>" + "\n".join(lines) + "</pre>"
    except Exception as e:
        return str(e), 500

# ---------- Register Route ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("Both fields are required!", "error")
            return redirect(url_for("register"))

        # check for existing user
        if get_user_by_username(username):
            flash("Username already exists. Please choose another.", "error")
            return redirect(url_for("register"))

        # store password securely using werkzeug
        pw_hash = generate_password_hash(password)
        conn = get_db_conn()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, pw_hash, now_ts())
            )
            conn.commit()
        finally:
            conn.close()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
