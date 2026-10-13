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
