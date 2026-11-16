import os
import secrets
import time
from collections import deque
from datetime import datetime

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=900,
)

# ---- Synthetic demo data only. No real patient information. ----
PATIENTS = {
    1: {"name": "Asha Verma", "age": 34, "appointment": "2026-11-18 10:30", "diagnosis": "Type 2 diabetes", "medication": "Metformin 500 mg"},
    2: {"name": "Ravi Nair", "age": 58, "appointment": "2026-11-18 11:15", "diagnosis": "Hypertension", "medication": "Amlodipine 5 mg"},
    3: {"name": "Meena Iyer", "age": 41, "appointment": "2026-11-19 09:00", "diagnosis": "Asthma", "medication": "Salbutamol inhaler"},
    4: {"name": "Karan Shah", "age": 27, "appointment": "2026-11-19 14:45", "diagnosis": "Migraine", "medication": "Sumatriptan 50 mg"},
}

# Role based access: each role only sees the fields it needs (least privilege).
ROLE_FIELDS = {
    "doctor": ["name", "age", "appointment", "diagnosis", "medication"],
    "nurse": ["name", "age", "appointment", "medication"],
    "receptionist": ["name", "appointment"],
}

# Demo accounts. Passwords are hashed in memory and come from a Kubernetes Secret, never from Git.
_demo_pw = generate_password_hash(os.environ["DEMO_PASSWORD"])
USERS = {
    "dr.rao": {"role": "doctor", "hash": _demo_pw},
    "nurse.priya": {"role": "nurse", "hash": _demo_pw},
    "recep.kumar": {"role": "receptionist", "hash": _demo_pw},
}

AUDIT = deque(maxlen=200)  # who did what (patient ids only, never patient data)
FAILS = {}  # username -> (count, first_fail_time)
MAX_FAILS, LOCK_SECONDS = 5, 300

BASE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MediSecure Patient Portal</title>
<style>
 body{margin:0;font-family:system-ui,Arial,sans-serif;background:#f1f6f6;color:#10302f}
 header{background:#0f766e;color:#fff;padding:16px 24px;display:flex;justify-content:space-between;align-items:center}
 header a,header button{color:#fff;background:none;border:1px solid #ffffff80;border-radius:8px;padding:6px 12px;text-decoration:none;cursor:pointer;font-size:14px}
 main{max-width:860px;margin:28px auto;padding:0 18px}
 .card{background:#fff;border-radius:14px;padding:22px;box-shadow:0 1px 4px #0001;margin-bottom:18px}
 table{width:100%;border-collapse:collapse} th,td{text-align:left;padding:10px;border-bottom:1px solid #e3eded}
 th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#4b6f6d}
 input{padding:10px;border:1px solid #b8cfcd;border-radius:8px;width:100%;box-sizing:border-box;margin:6px 0 14px}
 .btn{background:#0f766e;color:#fff;border:0;border-radius:8px;padding:10px 18px;cursor:pointer;font-size:15px}
 .err{color:#b91c1c;font-weight:600} .tag{background:#ccfbf1;border-radius:999px;padding:3px 10px;font-size:13px}
 footer{text-align:center;color:#5b7e7c;font-size:13px;margin:30px 0}
</style></head><body>
<header><strong>MediSecure Patient Portal</strong>
{% if user %}<span><span class="tag">{{ user }} ({{ role }})</span>
<a href="{{ url_for('patients') }}">Patients</a>
{% if role == 'doctor' %}<a href="{{ url_for('audit') }}">Audit log</a>{% endif %}
<form method="post" action="{{ url_for('logout') }}" style="display:inline">
<input type="hidden" name="csrf" value="{{ csrf }}"><button>Sign out</button></form></span>{% endif %}
</header><main>{% block body %}{% endblock %}</main>
<footer>Synthetic demo data | Arjun V and Kanikshaa K | Essentials in Cloud and DevOps | SRM Institute</footer>
</body></html>"""

LOGIN = BASE.replace("{% block body %}{% endblock %}", """
<div class="card" style="max-width:380px;margin:40px auto">
<h2>Staff sign in</h2>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Username</label><input name="username" autocomplete="username" required>
<label>Password</label><input name="password" type="password" autocomplete="current-password" required>
<button class="btn">Sign in</button></form></div>""")

PATIENT_LIST = BASE.replace("{% block body %}{% endblock %}", """
<div class="card"><h2>Patients</h2>
<p>You are signed in as <b>{{ role }}</b>, so you can only see: {{ fields|join(', ') }}.</p>
<table><tr><th>ID</th>{% for f in fields %}<th>{{ f }}</th>{% endfor %}</tr>
{% for pid, p in rows %}<tr><td>{{ pid }}</td>{% for f in fields %}<td>{{ p[f] }}</td>{% endfor %}</tr>{% endfor %}
</table></div>""")

AUDIT_PAGE = BASE.replace("{% block body %}{% endblock %}", """
<div class="card"><h2>Audit log</h2><p>Every sign in and every patient list view is recorded.</p>
<table><tr><th>Time</th><th>User</th><th>Action</th></tr>
{% for t, u, a in entries %}<tr><td>{{ t }}</td><td>{{ u }}</td><td>{{ a }}</td></tr>{% endfor %}
</table></div>""")


def log(user, action):
    AUDIT.appendleft((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user, action))


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
        abort(400)


def ctx(**extra):
    user = session.get("user")
    base = {"user": user, "role": USERS[user]["role"] if user else None, "csrf": csrf_token()}
    base.update(extra)
    return base


def require_login():
    if session.get("user") not in USERS:
        return redirect(url_for("login"))
    return None


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def home():
    return redirect(url_for("patients"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "")[:50]
        password = request.form.get("password", "")
        count, first = FAILS.get(username, (0, 0))
        if count >= MAX_FAILS and time.time() - first < LOCK_SECONDS:
            error = "Account temporarily locked. Try again in a few minutes."
            log(username, "LOGIN BLOCKED (too many failures)")
        elif username in USERS and check_password_hash(USERS[username]["hash"], password):
            FAILS.pop(username, None)
            session.clear()
            session["user"] = username
            session.permanent = True
            log(username, "LOGIN OK")
            return redirect(url_for("patients"))
        else:
            if time.time() - first >= LOCK_SECONDS:
                count, first = 0, time.time()
            FAILS[username] = (count + 1, first or time.time())
            log(username or "unknown", "LOGIN FAILED")
            error = "Invalid username or password."
    return render_template_string(LOGIN, **ctx(error=error))


@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    log(session.get("user", "unknown"), "LOGOUT")
    session.clear()
    return redirect(url_for("login"))


@app.route("/patients")
def patients():
    denied = require_login()
    if denied:
        return denied
    role = USERS[session["user"]]["role"]
    fields = ROLE_FIELDS[role]
    log(session["user"], "VIEWED PATIENT LIST (%d records)" % len(PATIENTS))
    return render_template_string(PATIENT_LIST, **ctx(fields=fields, rows=sorted(PATIENTS.items())))


@app.route("/audit")
def audit():
    denied = require_login()
    if denied:
        return denied
    if USERS[session["user"]]["role"] != "doctor":
        abort(403)
    return render_template_string(AUDIT_PAGE, **ctx(entries=list(AUDIT)))


@app.route("/health")
def health():
    return "ok", 200
