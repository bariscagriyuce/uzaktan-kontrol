import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("DB_PATH", "/data/accounts.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    totp_secret TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- Bearer tokens handed to clients and the web panel; only the sha256 is kept.
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    device_uuid TEXT,
    created_at INTEGER NOT NULL,
    last_used INTEGER NOT NULL
);

-- Computers linked to an account. pw_hash is the device's permanent password
-- h1, which lets the owner's clients log in without a connection code.
CREATE TABLE IF NOT EXISTS devices (
    uuid TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rd_id TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    pk TEXT,
    pw_hash TEXT,
    enrolled_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS address_books (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data TEXT NOT NULL
);

-- Pending second factor after a correct password.
CREATE TABLE IF NOT EXISTS login_challenges (
    secret TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""

_local = threading.local()


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        c = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        c.execute("PRAGMA journal_mode = WAL")
        _local.conn = c
    return c


def init() -> None:
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    conn().executescript(SCHEMA)


def now() -> int:
    return int(time.time())
