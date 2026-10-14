import os
import json
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
from flask import Flask, request, redirect, url_for, session, flash, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret")

MAX_ATTEMPTS = 3     # itni galat tries ke baad block
LOCK_MINUTES = 15    # block hone ka time

DB_URL = (os.environ.get("DATABASE_URL")
          or os.environ.get("POSTGRES_URL")
          or os.environ.get("STORAGE_URL"))


# ---------- Postgres storage (Neon) ----------
def fresh():
    return {"users": {}, "items": [], "logs": [], "next_id": 1}


def get_conn():
    conn = psycopg2.connect(DB_URL)
    with conn.cursor() as c:
        c.execute("CREATE TABLE IF NOT EXISTS store (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")
    conn.commit()
    return conn


def load():
    conn = get_conn()
    try:
        with conn.cursor() as c:
            c.execute("SELECT data FROM store WHERE id = 1")
            row = c.fetchone()
        return json.loads(row[0]) if row else fresh()
    finally:
        conn.close()


def save(d):
    conn = get_conn()
    try:
        with conn.cursor() as c:
            c.execute(
                "INSERT INTO store (id, data) VALUES (1, %s) "
                "ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data",
                (json.dumps(d),),
            )
        conn.commit()
    finally:
        conn.close()


def log(d, action, username=None):
    d["logs"].append({
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        "username": username or session.get("user", "anonymous"),
        "action": action,
    })
    d["logs"] = d["logs"][-200:]


def is_locked(user):
    return bool(user and user.get("locked_until")
                and datetime.fromisoformat(user["locked_until"]) > datetime.utcnow())


def login_required(admin=False):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if "user" not in session:
                return redirect(url_for("login"))
            if admin and session.get("role") != "admin":
                flash("Sirf admin ye kar sakta hai.")
                return redirect(url_for("home"))
            return f(*a, **k)
        return wrapper
    return deco


LAYOUT = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stock Manager</title>
<style>
body{font-family:Arial,sans-serif;max-width:800px;margin:20px auto;padding:0 12px;background:#dbeafe}
nav{display:flex;gap:14px;align-items:center;margin-bottom:16px}
table{width:100%;border-collapse:collapse;background:#fff}
td,th{border:1px solid #ddd;padding:8px;text-align:left}
.low{background:#ffe0e0}.msg{background:#fff3cd;padding:8px;margin:8px 0;border-radius:4px}
input,button{padding:6px;margin:2px}form.inline{display:inline}
</style></head><body>
<nav><b>Stock Manager</b>
{% if session.user %}<a href="/">Stock</a>
{% if session.role=='admin' %}<a href="/logs">Logs</a>{% endif %}
<span style="margin-left:auto">{{session.user}} ({{session.role}}) <a href="/logout">Logout</a></span>{% endif %}</nav>
{% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}
{{ inner|safe }}</body></html>
"""


def page(body, **ctx):
    return render_template_string(LAYOUT, inner=render_template_string(body, **ctx))


# ---------- Auth ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        d = load()
        if len(u) < 3 or len(p) < 6:
            flash("Username 3+ aur password 6+ characters ka ho.")
        elif u in d["users"]:
            flash("Username pehle se maujood hai.")
        else:
            role = "admin" if not d["users"] else "staff"  # pehla user admin
            d["users"][u] = {"password_hash": generate_password_hash(p), "role": role,
                             "failed": 0, "locked_until": None}
            log(d, f"Naya user bana ({role})", u)
            save(d)
            flash("Account ban gaya, ab login karein.")
            return redirect(url_for("login"))
    return page("""<h2>Register</h2><form method="post">
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button>Register</button></form><a href="/login">Login</a>""")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        d = load()
        user = d["users"].get(u)
        if not user:
            log(d, "Login fail: unknown user", u)
            flash("Username ya password ghalat hai.")
        elif is_locked(user):
            until = datetime.fromisoformat(user["locked_until"])
            mins = int((until - datetime.utcnow()).total_seconds() // 60) + 1
            flash(f"Account block hai. {mins} minute baad try karein ya admin se unlock karwayein.")
        elif check_password_hash(user["password_hash"], p):
            user["failed"], user["locked_until"] = 0, None
            session.update(user=u, role=user["role"])
            log(d, "Login success")
            save(d)
            return redirect(url_for("home"))
        else:
            user["failed"] += 1
            left = MAX_ATTEMPTS - user["failed"]
            if left <= 0:
                user["locked_until"] = (datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)).isoformat()
                user["failed"] = 0
                flash(f"Bohat ghalat tries. Account {LOCK_MINUTES} minute ke liye block.")
                log(d, "ACCOUNT BLOCKED (ghalat password)", u)
            else:
                flash(f"Password ghalat. {left} try baqi hain.")
                log(d, "Login fail: wrong password", u)
        save(d)
    return page("""<h2>Login</h2><form method="post">
