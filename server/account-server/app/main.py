"""Account server for the remote desktop client.

Speaks the subset of the RustDesk API server protocol the client uses
(login, current user, legacy address book, heartbeat, sysinfo) and adds
account-linked devices: a computer that has been logged into with an account
reports a signed hash of its permanent password, and that hash is served in
the account's address book so the owner's clients connect without a code.
"""

import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import pyotp
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from . import db
from .security import (
    DUMMY_HASH,
    RateLimiter,
    account_auth_msg,
    hash_password,
    new_token,
    token_hash,
    verify_device_signature,
    verify_password,
)

log = logging.getLogger("account-server")

TOKEN_TTL = int(os.environ.get("TOKEN_TTL_DAYS", "180")) * 86400
CHALLENGE_TTL = 300
SIGNATURE_WINDOW = 600
ONLINE_SECS = 60
TRUST_PROXY = os.environ.get("TRUST_PROXY", "") == "1"
DESKTOP_OS = {"windows", "linux", "macos"}

# Peer platform names the client's address book understands.
PLATFORM_NAMES = {"windows": "Windows", "linux": "Linux", "macos": "Mac OS"}

login_limiter = RateLimiter(max_failures=10, window_secs=900)
user_limiter = RateLimiter(max_failures=20, window_secs=900)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init()
    bootstrap_admin()
    yield


app = FastAPI(title="Account server", docs_url=None, redoc_url=None, lifespan=lifespan)


def bootstrap_admin() -> None:
    """Creates the first account from ADMIN_USERNAME/ADMIN_PASSWORD."""
    username = os.environ.get("ADMIN_USERNAME", "").strip()
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not username or not password:
        return
    if db.conn().execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return
    create_user(username, password, is_admin=True)
    log.warning("Created admin account %r", username)


def create_user(username: str, password: str, is_admin: bool = False) -> None:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    db.conn().execute(
        "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
        (username, hash_password(password), int(is_admin), db.now()),
    )


def error(msg: str, status: int = 200) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=status)


def client_ip(request: Request) -> str:
    if TRUST_PROXY:
        # Set by Cloudflare (Tunnel); the proxies in between only see cloudflared.
        cf = request.headers.get("cf-connecting-ip")
        if cf:
            return cf.strip()
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


async def json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


def user_payload(user) -> dict:
    return {
        "name": user["username"],
        "display_name": user["username"],
        "email": user["email"],
        "note": "",
        "status": 1,
        "is_admin": bool(user["is_admin"]),
    }


# ---------------------------------------------------------------- auth


def current_user(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Not logged in")
    th = token_hash(auth[7:].strip())
    c = db.conn()
    row = c.execute(
        "SELECT u.*, t.last_used, t.token_hash FROM tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = ?",
        (th,),
    ).fetchone()
    if row is None or db.now() - row["last_used"] > TOKEN_TTL:
        raise HTTPException(401, "Invalid token")
    if db.now() - row["last_used"] > 60:
        c.execute("UPDATE tokens SET last_used = ? WHERE token_hash = ?", (db.now(), th))
    return row


@app.exception_handler(HTTPException)
async def http_error(_request: Request, exc: HTTPException):
    return error(str(exc.detail), exc.status_code)


def issue_token(user, body: dict) -> dict:
    """Creates a session and links the calling computer to the account."""
    info = body.get("deviceInfo") or {}
    device_os = str(info.get("os", "")).lower()
    uuid = str(body.get("uuid") or "")
    rd_id = str(body.get("id") or "")
    is_client = info.get("type") == "client"
    token = new_token()
    c = db.conn()
    c.execute(
        "INSERT INTO tokens (token_hash, user_id, kind, device_uuid, created_at, last_used) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (token_hash(token), user["id"], "client" if is_client else "web", uuid or None, db.now(), db.now()),
    )
    if is_client and uuid and rd_id and device_os in DESKTOP_OS:
        enroll_device(user["id"], uuid, rd_id, str(info.get("name", "")), device_os)
    return {"access_token": token, "type": "access_token", "user": user_payload(user)}


def enroll_device(user_id: int, uuid: str, rd_id: str, hostname: str, device_os: str) -> None:
    c = db.conn()
    row = c.execute("SELECT user_id FROM devices WHERE uuid = ?", (uuid,)).fetchone()
    if row is None:
        c.execute(
            "INSERT INTO devices (uuid, user_id, rd_id, hostname, os, enrolled_at) VALUES (?, ?, ?, ?, ?, ?)",
            (uuid, user_id, rd_id, hostname, device_os, db.now()),
        )
    elif row["user_id"] != user_id:
        # Someone at the keyboard moved the computer to another account: drop the
        # old account's key material so it has to be proven again.
        c.execute(
            "UPDATE devices SET user_id = ?, rd_id = ?, hostname = ?, os = ?, pk = NULL, "
            "pw_hash = NULL, enrolled_at = ? WHERE uuid = ?",
            (user_id, rd_id, hostname, device_os, db.now(), uuid),
        )
    else:
        c.execute(
            "UPDATE devices SET rd_id = ?, hostname = ?, os = ? WHERE uuid = ?",
            (rd_id, hostname, device_os, uuid),
        )
    log.info("device %s (%s) linked to user %s", rd_id, hostname, user_id)


@app.post("/api/login")
async def login(request: Request):
    body = await json_body(request)
    ip = client_ip(request)
    if login_limiter.blocked(ip):
        return error("Too many attempts, try again later", 429)
    c = db.conn()

    # Second step: TOTP code for a challenge issued after the password.
    secret = body.get("secret")
    if secret:
        c.execute("DELETE FROM login_challenges WHERE created_at < ?", (db.now() - CHALLENGE_TTL,))
        ch = c.execute("SELECT * FROM login_challenges WHERE secret = ?", (secret,)).fetchone()
        if ch is None:
            return error("Login expired, please sign in again")
        user = c.execute("SELECT * FROM users WHERE id = ?", (ch["user_id"],)).fetchone()
        code = str(body.get("tfaCode") or body.get("verificationCode") or "").strip()
        if not user or not user["totp_secret"] or not pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            login_limiter.fail(ip)
            return error("Wrong verification code")
        c.execute("DELETE FROM login_challenges WHERE secret = ?", (secret,))
        login_limiter.reset(ip)
        # Device fields come from the first request, which the password protected.
        return issue_token(user, {**json.loads(ch["body"]), "deviceInfo": body.get("deviceInfo") or {}})

    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    if user_limiter.blocked(username.lower()):
        return error("Too many attempts, try again later", 429)
    user = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not verify_password(password, user["password_hash"] if user else DUMMY_HASH) or user is None:
        login_limiter.fail(ip)
        user_limiter.fail(username.lower())
        return error("Wrong username or password")
    login_limiter.reset(ip)
    user_limiter.reset(username.lower())

    if user["totp_secret"]:
        challenge = secrets.token_urlsafe(24)
        c.execute(
            "INSERT INTO login_challenges (secret, user_id, body, created_at) VALUES (?, ?, ?, ?)",
            (challenge, user["id"], json.dumps({"id": body.get("id"), "uuid": body.get("uuid")}), db.now()),
        )
        return {"type": "email_check", "tfa_type": "tfa_check", "secret": challenge, "user": {"name": user["username"]}}
    return issue_token(user, body)


@app.get("/api/login-options")
def login_options():
    return []


@app.post("/api/logout")
def logout(user=Depends(current_user)):
    db.conn().execute("DELETE FROM tokens WHERE token_hash = ?", (user["token_hash"],))
    return {}


@app.post("/api/currentUser")
def current_user_info(user=Depends(current_user)):
    return user_payload(user)


# ---------------------------------------------------------------- address book


def account_devices(user_id: int):
    return db.conn().execute(
        "SELECT * FROM devices WHERE user_id = ? ORDER BY hostname", (user_id,)
    ).fetchall()


def merged_address_book(user_id: int) -> dict:
    """The user's own entries, with every linked computer added and given the
    password hash its heartbeat proved."""
    row = db.conn().execute("SELECT data FROM address_books WHERE user_id = ?", (user_id,)).fetchone()
    try:
        ab = json.loads(row["data"]) if row else {}
    except ValueError:
        ab = {}
    if not isinstance(ab, dict):
        ab = {}
    peers = ab.get("peers") if isinstance(ab.get("peers"), list) else []
    ab.setdefault("tags", [])
    by_id = {p.get("id"): p for p in peers if isinstance(p, dict)}
    for d in account_devices(user_id):
        p = by_id.get(d["rd_id"])
        if p is None:
            p = {"id": d["rd_id"], "alias": "", "tags": []}
            peers.append(p)
            by_id[d["rd_id"]] = p
        p["hash"] = d["pw_hash"] or p.get("hash", "")
        p["hostname"] = p.get("hostname") or d["hostname"]
        p["username"] = p.get("username") or d["username"]
        p["platform"] = p.get("platform") or PLATFORM_NAMES.get(d["os"], "")
    ab["peers"] = peers
    return ab


@app.get("/api/ab")
def get_ab(user=Depends(current_user)):
    return {"data": json.dumps(merged_address_book(user["id"])), "licensed_devices": 0}


@app.post("/api/ab")
async def set_ab(request: Request, user=Depends(current_user)):
    body = await json_body(request)
    data = body.get("data")
    try:
        parsed = json.loads(data) if isinstance(data, str) else None
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        return error("Invalid address book")
    if len(data) > 2_000_000:
        return error("Address book too large")
    db.conn().execute(
        "INSERT INTO address_books (user_id, data) VALUES (?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET data = excluded.data",
        (user["id"], data),
    )
    return {}


@app.post("/api/ab/get")
def get_ab_legacy_post(user=Depends(current_user)):
    return get_ab(user)


# ---------------------------------------------------------------- device side


@app.post("/api/heartbeat")
async def heartbeat(request: Request):
    body = await json_body(request)
    uuid = str(body.get("uuid") or "")
    rd_id = str(body.get("id") or "")
    resp = {"modified_at": body.get("modified_at", 0)}
    if not uuid:
        return resp
    c = db.conn()
    device = c.execute("SELECT * FROM devices WHERE uuid = ?", (uuid,)).fetchone()
    resp["account_enrolled"] = device is not None
    if device is None:
        return resp
    c.execute("UPDATE devices SET last_seen = ?, rd_id = ? WHERE uuid = ?", (db.now(), rd_id or device["rd_id"], uuid))
    auth = body.get("account_auth")
    if isinstance(auth, dict):
        apply_account_auth(device, rd_id, uuid, auth)
    return resp


def apply_account_auth(device, rd_id: str, uuid: str, auth: dict) -> None:
    pw_hash = str(auth.get("hash") or "")
    pk = str(auth.get("pk") or "")
    ts = str(auth.get("timestamp") or "")
    sig = str(auth.get("signature") or "")
    try:
        skew = abs(db.now() - int(ts))
    except ValueError:
        return
    if not pw_hash or not pk or skew > SIGNATURE_WINDOW:
        return
    # The first key seen after the account login is pinned; later reports must
    # come from the same device key.
    if device["pk"] and device["pk"] != pk:
        log.warning("device %s: signature key changed, ignoring", device["rd_id"])
        return
    if not verify_device_signature(pk, account_auth_msg(rd_id, uuid, pw_hash, ts), sig):
        log.warning("device %s: bad signature", device["rd_id"])
        return
    if device["pk"] != pk or device["pw_hash"] != pw_hash:
        db.conn().execute("UPDATE devices SET pk = ?, pw_hash = ? WHERE uuid = ?", (pk, pw_hash, uuid))


@app.post("/api/sysinfo")
async def sysinfo(request: Request):
    body = await json_body(request)
    uuid = str(body.get("uuid") or "")
    c = db.conn()
    if uuid and c.execute("SELECT 1 FROM devices WHERE uuid = ?", (uuid,)).fetchone():
        c.execute(
            "UPDATE devices SET hostname = COALESCE(NULLIF(?, ''), hostname), "
            "username = COALESCE(NULLIF(?, ''), username) WHERE uuid = ?",
            (str(body.get("hostname") or ""), str(body.get("username") or ""), uuid),
        )
    return PlainTextResponse("SYSINFO_UPDATED")


@app.post("/api/sysinfo_ver")
def sysinfo_ver():
    return PlainTextResponse("")


# ---------------------------------------------------------------- web panel


@app.get("/", response_class=HTMLResponse)
def panel():
    return (Path(__file__).parent / "panel.html").read_text(encoding="utf-8")


@app.get("/api/panel/devices")
def panel_devices(user=Depends(current_user)):
    t = db.now()
    return [
        {
            "uuid": d["uuid"],
            "id": d["rd_id"],
            "hostname": d["hostname"],
            "os": PLATFORM_NAMES.get(d["os"], d["os"]),
            "username": d["username"],
            "online": t - d["last_seen"] < ONLINE_SECS,
            "last_seen": d["last_seen"],
            "ready": bool(d["pw_hash"]),
        }
        for d in account_devices(user["id"])
    ]


@app.post("/api/panel/devices/remove")
async def panel_remove_device(request: Request, user=Depends(current_user)):
    body = await json_body(request)
    db.conn().execute(
        "DELETE FROM devices WHERE uuid = ? AND user_id = ?", (str(body.get("uuid") or ""), user["id"])
    )
    return {}


@app.get("/api/panel/me")
def panel_me(user=Depends(current_user)):
    return {**user_payload(user), "totp": bool(user["totp_secret"])}


@app.post("/api/panel/password")
async def panel_password(request: Request, user=Depends(current_user)):
    body = await json_body(request)
    if not verify_password(str(body.get("old") or ""), user["password_hash"]):
        return error("Current password is wrong")
    new = str(body.get("new") or "")
    if len(new) < 8:
        return error("Password must be at least 8 characters")
    c = db.conn()
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user["id"]))
    # Sign out everywhere else.
    c.execute("DELETE FROM tokens WHERE user_id = ? AND token_hash != ?", (user["id"], user["token_hash"]))
    return {}


@app.post("/api/panel/totp/setup")
def panel_totp_setup(user=Depends(current_user)):
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="Uzaktan Kontrol")
    return {"secret": secret, "uri": uri, "qr": qr_svg(uri)}


@app.post("/api/panel/totp/enable")
async def panel_totp_enable(request: Request, user=Depends(current_user)):
    body = await json_body(request)
    secret = str(body.get("secret") or "")
    if not secret or not pyotp.TOTP(secret).verify(str(body.get("code") or ""), valid_window=1):
        return error("Wrong verification code")
    db.conn().execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
    return {}


@app.post("/api/panel/totp/disable")
async def panel_totp_disable(request: Request, user=Depends(current_user)):
    body = await json_body(request)
    if not user["totp_secret"] or not pyotp.TOTP(user["totp_secret"]).verify(str(body.get("code") or ""), valid_window=1):
        return error("Wrong verification code")
    db.conn().execute("UPDATE users SET totp_secret = NULL WHERE id = ?", (user["id"],))
    return {}


@app.get("/api/panel/server-info")
def panel_server_info(_user=Depends(current_user)):
    key_file = os.environ.get("RELAY_KEY_FILE", "/relay-data/id_ed25519.pub")
    try:
        key = Path(key_file).read_text().strip()
    except OSError:
        key = ""
    return {"host": os.environ.get("PUBLIC_HOST", ""), "key": key}


def qr_svg(text: str) -> str:
    import io

    import qrcode
    import qrcode.image.svg

    buf = io.BytesIO()
    qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8).save(buf)
    return buf.getvalue().decode()
