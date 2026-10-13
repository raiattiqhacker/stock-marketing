import os
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, redirect, url_for, session, flash, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret")

# Vercel par sirf /tmp mein likh sakte hain
DATA_FILE = "/tmp/data.json" if os.environ.get("VERCEL") else "data.json"
MAX_ATTEMPTS = 3     # itni galat tries ke baad block
LOCK_MINUTES = 15    # block hone ka time


# ---------- JSON storage (database ki jagah) ----------
def load():
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except Exception:
        return {"users": {}, "items": [], "logs": [], "next_id": 1}


def save(d):
    with open(DATA_FILE, "w") as f:
        json.dump(d, f)


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
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button>Login</button></form><a href="/register">Register</a>""")


@app.route("/logout")
def logout():
    if "user" in session:
        d = load()
        log(d, "Logout")
        save(d)
    session.clear()
    return redirect(url_for("login"))


# ---------- Stock ----------
@app.route("/")
@login_required()
def home():
    items = sorted(load()["items"], key=lambda i: i["name"].lower())
    return page("""
    <h2>Stock</h2>
    <form method="post" action="/add">
      <input name="name" placeholder="Item name" required>
      <input name="quantity" type="number" min="0" placeholder="Qty" required>
      <input name="min_level" type="number" min="0" placeholder="Min level" value="5">
      <button>Add item</button></form><br>
    <table><tr><th>Item</th><th>Qty</th><th>Min</th><th>Action</th></tr>
    {% for i in items %}
    <tr class="{{ 'low' if i.quantity <= i.min_level else '' }}">
      <td>{{i.name}}</td><td>{{i.quantity}}</td><td>{{i.min_level}}</td>
      <td><form class="inline" method="post" action="/update/{{i.id}}">
        <input name="quantity" type="number" min="0" value="{{i.quantity}}" style="width:70px">
        <button>Update</button></form>
        {% if session.role=='admin' %}
        <form class="inline" method="post" action="/delete/{{i.id}}"
          onsubmit="return confirm('Delete karna hai?')"><button>Delete</button></form>
        {% endif %}</td></tr>
    {% else %}<tr><td colspan="4">Abhi koi item nahi.</td></tr>{% endfor %}
    </table><p>Laal rows = stock kam hai.</p>""", items=items)


@app.route("/add", methods=["POST"])
@login_required()
def add():
    d = load()
    item = {"id": d["next_id"], "name": request.form["name"].strip(),
            "quantity": max(0, int(request.form["quantity"])),
            "min_level": max(0, int(request.form.get("min_level") or 5))}
    d["next_id"] += 1
    d["items"].append(item)
    log(d, f"Item add: {item['name']} ({item['quantity']})")
    save(d)
    return redirect(url_for("home"))


@app.route("/update/<int:item_id>", methods=["POST"])
@login_required()
def update(item_id):
    d = load()
    for i in d["items"]:
        if i["id"] == item_id:
            old, i["quantity"] = i["quantity"], max(0, int(request.form["quantity"]))
            log(d, f"Qty change: {i['name']} {old} -> {i['quantity']}")
    save(d)
    return redirect(url_for("home"))


@app.route("/delete/<int:item_id>", methods=["POST"])
@login_required(admin=True)
def delete(item_id):
    d = load()
    for i in d["items"]:
        if i["id"] == item_id:
            log(d, f"Item delete: {i['name']}")
    d["items"] = [i for i in d["items"] if i["id"] != item_id]
    save(d)
    return redirect(url_for("home"))


# ---------- Admin ----------
@app.route("/logs")
@login_required(admin=True)
def logs():
    d = load()
    locked = [u for u, v in d["users"].items() if is_locked(v)]
    return page("""
    <h2>Blocked users</h2>
    {% for u in locked %}<form class="inline" method="post" action="/unlock/{{u}}">
      {{u}} <button>Unlock</button></form><br>
    {% else %}Koi blocked user nahi.{% endfor %}
    <h2>Audit log (last 100)</h2>
    <table><tr><th>Time (UTC)</th><th>User</th><th>Action</th></tr>
    {% for l in entries %}<tr><td>{{l.time}}</td><td>{{l.username}}</td>
      <td>{{l.action}}</td></tr>{% endfor %}</table>""",
                locked=locked, entries=d["logs"][::-1][:100])


@app.route("/unlock/<username>", methods=["POST"])
@login_required(admin=True)
def unlock(username):
    d = load()
    if username in d["users"]:
        d["users"][username].update(locked_until=None, failed=0)
        log(d, f"Admin ne unlock kiya: {username}")
        save(d)
    return redirect(url_for("logs"))


if __name__ == "__main__":
    app.run(debug=True)
