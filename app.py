import os
import re
import json
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
from flask import Flask, request, redirect, url_for, session, flash, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret")

MAX_ATTEMPTS = 3     # staff ke liye itni galat tries ke baad block
LOCK_MINUTES = 15    # block hone ka time (admin kabhi block nahi hota)

DB_URL = (os.environ.get("DATABASE_URL")
          or os.environ.get("POSTGRES_URL")
          or os.environ.get("STORAGE_URL"))

# 50 cyber security items: (naam, qty, min level)
PRESET = [
    ("Firewall Appliance (Fortinet)", 8, 2), ("Firewall Appliance (Cisco ASA)", 5, 2),
    ("Managed Switch 24-Port", 15, 4), ("Managed Switch 48-Port", 6, 2),
    ("Enterprise Router", 12, 3), ("Wireless Access Point", 20, 5),
    ("USB Wi-Fi Adapter", 30, 8), ("Network Load Balancer", 3, 1),
    ("VPN Gateway Device", 4, 1), ("SFP Fiber Module", 25, 6),
    ("LAN Cable Cat6 (305m Box)", 15, 4), ("Patch Cable 1m", 100, 25),
    ("RJ45 Connectors (Pack of 100)", 20, 5), ("Crimping Tool Kit", 10, 3),
    ("Network Cable Tester", 8, 2), ("Network Rack 42U", 4, 1),
    ("USB Security Key (FIDO2)", 40, 10), ("Smart Card", 80, 20),
    ("Smart Card Reader", 25, 6), ("Biometric Fingerprint Machine", 10, 3),
    ("RFID Access Card", 150, 30), ("RFID Door Controller", 8, 2),
    ("Face Recognition Terminal", 5, 2), ("Hardware OTP Token", 35, 10),
    ("IP Dome Camera", 40, 10), ("IP Bullet Camera", 35, 10),
    ("NVR 16-Channel", 8, 2), ("DVR 8-Channel", 6, 2),
    ("Surveillance Hard Disk 4TB", 20, 5), ("PoE Injector", 25, 6),
    ("Antivirus License (1 Year)", 100, 25), ("Endpoint Protection License", 80, 20),
    ("VPN License (1 Year)", 50, 15), ("SIEM License", 5, 1),
    ("Email Security License", 40, 10), ("Password Manager License", 60, 15),
    ("Backup Software License", 30, 8), ("Vulnerability Scanner License", 6, 2),
    ("Windows Server License", 10, 3), ("SSL Certificate (1 Year)", 25, 5),
    ("Security Testing Laptop", 10, 3), ("Desktop PC", 15, 4),
    ("External Hard Drive 2TB", 30, 8), ("NAS Storage Device", 4, 1),
    ("UPS 1KVA", 12, 3), ("Raspberry Pi (Lab Use)", 15, 4),
    ("Encrypted USB Flash Drive 64GB", 50, 15), ("Monitor-Mode Wireless Adapter", 10, 3),
    ("Security Awareness Training Kit", 20, 5), ("Faraday Bag (Phone Shielding)", 25, 8),
]


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
    if not user or user.get("role") == "admin":   # admin kabhi block nahi
        return False
    return bool(user.get("locked_until")
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


def add_stock(d, name, qty, min_level, merge):
    """Item add karta hai. Pehle se ho to merge=True par qty jama hoti hai,
    warna chhor deta hai. Return: 'new', 'updated' ya 'skipped'."""
    name = name.strip()
    for i in d["items"]:
        if i["name"].lower() == name.lower():
            if merge:
                i["quantity"] += qty
                return "updated"
            return "skipped"
    d["items"].append({"id": d["next_id"], "name": name,
                       "quantity": max(0, qty), "min_level": max(0, min_level)})
    d["next_id"] += 1
    return "new"


LAYOUT = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stock Manager</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',Arial,sans-serif}
a{text-decoration:none}
form.inline{display:inline}
button{border:0;border-radius:10px;color:#fff;font-weight:600;font-size:14px;cursor:pointer;background:linear-gradient(135deg,#4f7cff,#6a5cff);padding:9px 14px;margin:2px}
button:hover{filter:brightness(1.1)}

/* ===== App (dashboard) theme ===== */
body.app{background:#e9eef7;color:#1e293b}
body.app a{color:#3b66f5}
.shell{display:flex;min-height:100vh}
.side{width:74px;background:#fff;display:flex;flex-direction:column;align-items:center;gap:10px;padding:16px 0;box-shadow:2px 0 16px rgba(15,23,42,.06);position:sticky;top:0;height:100vh}
.side .logo{font-size:28px;margin-bottom:14px}
.ico{width:46px;height:46px;border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:21px}
.ico:hover,.ico.on{background:#e6edff}
.main{flex:1;padding:18px 24px;min-width:0}
.top{display:flex;align-items:center;gap:14px;background:#fff;border-radius:16px;padding:10px 18px;margin-bottom:20px;box-shadow:0 4px 18px rgba(15,23,42,.06);flex-wrap:wrap}
.top .brand-name{font-weight:700;font-size:17px}
.pill{padding:7px 16px;border-radius:999px;font-size:14px;color:#475569}
.pill.on{background:#eef2ff;color:#3b66f5;font-weight:600}
.chip{margin-left:auto;display:flex;align-items:center;gap:10px;font-size:14px}
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,#4f7cff,#a855f7);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700}
.hi{font-size:26px;margin:4px 0 2px}
.muted{color:#64748b;margin:0 0 18px}
.card{background:#fff;border-radius:18px;padding:18px 20px;box-shadow:0 4px 18px rgba(15,23,42,.06)}
.card h3{margin:0 0 14px;font-size:16px}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:16px}
.stat span{color:#64748b;font-size:13px}
.stat b{display:block;font-size:30px;margin-top:6px}
.stat .warn{color:#d97706}.stat .bad{color:#dc2626}.stat .good{color:#16a34a}
.row2{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:16px}
.row3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.bars{display:flex;gap:14px;height:230px;align-items:stretch;padding-top:6px}
.col{flex:1;display:flex;flex-direction:column;align-items:center;min-width:0}
.bw{flex:1;width:100%;display:flex;align-items:flex-end;justify-content:center}
.bar{width:62%;min-height:6px;background:linear-gradient(180deg,#7aa2ff,#4f7cff);border-radius:8px 8px 0 0;position:relative}
.bar.lowbar{background:linear-gradient(180deg,#fca5a5,#ef4444)}
.bar em{position:absolute;top:-20px;left:50%;transform:translateX(-50%);font-style:normal;font-size:12px;color:#475569}
.col small{margin-top:8px;color:#64748b;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.legend{font-size:12px;color:#64748b;margin-top:10px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 4px 0 10px}
.donut-wrap{display:flex;flex-direction:column;align-items:center;gap:14px}
.donut{width:180px;height:180px;border-radius:50%;display:flex;align-items:center;justify-content:center}
.donut div{width:128px;height:128px;border-radius:50%;background:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center}
.donut b{font-size:30px}
.donut span{font-size:12px;color:#64748b}
.mini{display:flex;gap:18px;font-size:13px;color:#475569}
.list{display:flex;flex-direction:column;gap:10px}
.li{display:flex;align-items:center;gap:12px;padding:10px;border-radius:12px;background:#f6f8fc}
.li .ic{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;background:#e6edff;font-size:16px;flex-shrink:0}
.li .ic.red{background:#fee2e2}.li .ic.green{background:#dcfce7}
.li div{min-width:0;font-size:13px}
.li b{display:block;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.li small{color:#64748b}
.tbl{overflow-x:auto}
table{width:100%;border-collapse:collapse}
body.app th{text-align:left;color:#64748b;font-size:13px;padding:10px;border-bottom:2px solid #eef2f7}
body.app td{padding:10px;border-bottom:1px solid #eef2f7;font-size:14px}
body.app tr.low td{background:#fff1f2}
body.app input,body.app textarea{padding:10px 12px;border-radius:10px;border:1px solid #d5dcea;background:#fff;color:#1e293b;margin:2px;outline:none;font-size:14px;font-family:inherit}
body.app input:focus,body.app textarea:focus{border-color:#4f7cff;box-shadow:0 0 0 3px rgba(79,124,255,.18)}
textarea{width:100%;min-height:170px}
.addrow{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.msg{background:#fff7e0;border:1px solid #f5d27a;color:#8a5a00;padding:10px 14px;margin:0 0 14px;border-radius:10px}
.tag{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}
.tag.ok{background:#dcfce7;color:#15803d}.tag.low{background:#fef3c7;color:#b45309}.tag.out{background:#fee2e2;color:#b91c1c}

/* ===== Chat ===== */
.cb{height:380px;overflow-y:auto;background:#f6f8fc;border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:10px}
.m{max-width:78%;padding:10px 14px;border-radius:14px;font-size:14px;white-space:pre-line;line-height:1.5}
.m.me{align-self:flex-end;background:linear-gradient(135deg,#4f7cff,#6a5cff);color:#fff}
.m.bot{align-self:flex-start;background:#fff;border:1px solid #e2e8f0}
.cf{display:flex;gap:8px;margin-top:12px}
.cf input{flex:1}

/* ===== Guest (login/register) dark theme ===== */
body.guest{color:#e2e8f0;min-height:100vh;padding:20px 14px;
background:radial-gradient(circle at 15% 10%,#2a1a6e 0%,transparent 45%),radial-gradient(circle at 85% 90%,#0e4a6b 0%,transparent 45%),#0a0f1f;background-attachment:fixed}
body.guest a{color:#818cf8}
body.guest .msg{background:rgba(250,204,21,.15);border:1px solid rgba(250,204,21,.45);color:#fde68a;max-width:860px;margin:10px auto}
body.guest h2{color:#f1f5f9;margin-top:0}
body.guest input{padding:11px 12px;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;outline:none;font-size:15px;margin:2px}
body.guest input:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.30)}
body.guest input::placeholder{color:#64748b}
.auth{display:grid;grid-template-columns:1fr 1fr;max-width:860px;margin:40px auto;border-radius:22px;overflow:hidden;border:1px solid rgba(255,255,255,.12);box-shadow:0 20px 60px rgba(0,0,0,.6);background:rgba(255,255,255,.04)}
.brand{padding:40px 32px;background:linear-gradient(160deg,#4f46e5 0%,#7c3aed 55%,#0ea5e9 130%);color:#fff;display:flex;flex-direction:column;justify-content:center}
.brand .logo{font-size:46px;margin-bottom:8px}
.brand h1{margin:0 0 6px;font-size:28px}
.brand p{margin:0 0 18px;opacity:.9;line-height:1.5}
.brand ul{list-style:none;padding:0;margin:0}
.brand li{padding:6px 0}
.form-side{padding:40px 32px;display:flex;flex-direction:column;justify-content:center;background:rgba(10,15,31,.85)}
.form-side h2{font-size:26px;margin-bottom:4px}
.sub{color:#94a3b8;margin:0 0 20px}
.form-side form{display:flex;flex-direction:column;gap:12px}
.form-side label{font-size:13px;color:#a5b4fc;margin-bottom:-6px}
.pwrow{position:relative;display:flex}
.pwrow input{flex:1;padding-right:70px}
.eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);padding:6px 10px;font-size:12px;background:#1e293b;margin:0}
.big{margin-top:6px;padding:13px;font-size:16px}
.alt{margin-top:18px;color:#94a3b8;font-size:14px}

@media(max-width:900px){
 .grid4{grid-template-columns:1fr 1fr}.row2,.row3{grid-template-columns:1fr}
}
@media(max-width:700px){
 .shell{flex-direction:column}
 .side{width:100%;height:auto;flex-direction:row;justify-content:center;position:static;padding:8px 0}
 .side .logo{margin:0 10px 0 0}
 .main{padding:14px}
 .auth{grid-template-columns:1fr;margin:10px auto}
 .brand,.form-side{padding:26px 22px}
}
</style></head>
<body class="{{ 'app' if session.user else 'guest' }}">
{% if session.user %}
<div class="shell">
  <aside class="side">
    <div class="logo">&#128737;</div>
    <a class="ico {{ 'on' if request.path=='/' else '' }}" href="/" title="Dashboard">&#127968;</a>
    <a class="ico {{ 'on' if request.path=='/stock' else '' }}" href="/stock" title="Stock">&#128230;</a>
    <a class="ico {{ 'on' if request.path=='/chat' else '' }}" href="/chat" title="Chat">&#128172;</a>
    {% if session.role=='admin' %}<a class="ico {{ 'on' if request.path=='/import' else '' }}" href="/import" title="Bulk Import">&#128229;</a>{% endif %}
    {% if session.role=='admin' %}<a class="ico {{ 'on' if request.path=='/logs' else '' }}" href="/logs" title="Logs">&#128220;</a>{% endif %}
    <a class="ico" href="/logout" title="Logout">&#128682;</a>
  </aside>
  <div class="main">
    <div class="top">
      <span class="brand-name">Stock Manager</span>
      <a class="pill {{ 'on' if request.path=='/' else '' }}" href="/">Dashboard</a>
      <a class="pill {{ 'on' if request.path=='/stock' else '' }}" href="/stock">Stock</a>
      <a class="pill {{ 'on' if request.path=='/chat' else '' }}" href="/chat">Chat</a>
      {% if session.role=='admin' %}<a class="pill {{ 'on' if request.path=='/import' else '' }}" href="/import">Import</a>{% endif %}
      {% if session.role=='admin' %}<a class="pill {{ 'on' if request.path=='/logs' else '' }}" href="/logs">Logs</a>{% endif %}
      <div class="chip"><span>{{session.user}} ({{session.role}})</span><div class="avatar">{{ session.user[0]|upper }}</div></div>
    </div>
    {% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}
    {{ inner|safe }}
  </div>
</div>
{% else %}
{% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}
{{ inner|safe }}
{% endif %}
</body></html>
"""


def page(body, **ctx):
    return render_template_string(LAYOUT, inner=render_template_string(body, **ctx))


BRAND = """
<div class="brand">
  <div class="logo">&#128737;</div>
  <h1>Stock Manager</h1>
  <p>Secure inventory system for your organization.</p>
  <ul>
    <li>&#128274; Encrypted passwords</li>
    <li>&#128101; Admin and staff roles</li>
    <li>&#128196; Full audit log</li>
    <li>&#9889; Brute-force protection</li>
  </ul>
</div>
"""

EYE_JS = """onclick="var i=document.getElementById('pw');if(i.type==='password'){i.type='text';this.textContent='Hide'}else{i.type='password';this.textContent='Show'}" """


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
    return page('<div class="auth">' + BRAND + """
    <div class="form-side">
      <h2>Create account</h2>
      <p class="sub">Naya account banayein</p>
      <form method="post">
        <label>Username</label>
        <input name="username" placeholder="Kam az kam 3 characters" required autocomplete="username">
        <label>Password</label>
        <div class="pwrow">
          <input id="pw" name="password" type="password" placeholder="Kam az kam 6 characters" required autocomplete="new-password">
          <button type="button" class="eye" """ + EYE_JS + """>Show</button>
        </div>
        <button class="big">Register</button>
      </form>
      <div class="alt">Pehle se account hai? <a href="/login">Login karein</a></div>
    </div></div>""")


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
            if user["role"] == "admin":
                user["failed"] = 0
                flash("Password ghalat hai. Dobara koshish karein.")
                log(d, "Login fail: wrong
