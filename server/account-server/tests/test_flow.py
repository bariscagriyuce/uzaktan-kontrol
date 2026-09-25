import base64
import json
import time

import pyotp
import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("ADMIN_USERNAME", "baris")
    monkeypatch.setenv("ADMIN_PASSWORD", "cok-gizli-sifre")
    import importlib

    from app import db, main

    importlib.reload(db)
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Device:
    """Mimics what the client's service sends in its heartbeat."""

    def __init__(self, rd_id="123456789", uuid="dXVpZC0x", os="linux"):
        self.rd_id, self.uuid, self.os = rd_id, uuid, os
        self.key = SigningKey.generate()
        self.pw_hash = b64(b"h1-of-permanent-password-000000!")

    def login(self, c, password="cok-gizli-sifre", **extra):
        return c.post("/api/login", json={
            "username": "baris", "password": password, "id": self.rd_id, "uuid": self.uuid,
            "deviceInfo": {"os": self.os, "type": "client", "name": "masaustu"}, **extra,
        }).json()

    def heartbeat(self, c, key=None, pw_hash=None):
        key = key or self.key
        pw_hash = pw_hash or self.pw_hash
        ts = str(int(time.time()))
        msg = f"account-auth\0{self.rd_id}\0{self.uuid}\0{pw_hash}\0{ts}".encode()
        return c.post("/api/heartbeat", json={
            "id": self.rd_id, "uuid": self.uuid, "ver": 1, "modified_at": 0,
            "account_auth": {
                "hash": pw_hash, "pk": b64(bytes(key.verify_key)), "timestamp": ts,
                "signature": b64(key.sign(msg).signature),
            },
        }).json()


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def ab_peers(c, token):
    return json.loads(c.get("/api/ab", headers=auth(token)).json()["data"])["peers"]


def test_linked_device_appears_with_hash(client):
    dev = Device()
    res = dev.login(client)
    assert res["type"] == "access_token"
    token = res["access_token"]

    # Linked, but no password hash proven yet.
    assert dev.heartbeat(client)["account_enrolled"] is True
    peers = ab_peers(client, token)
    assert peers == [{"id": dev.rd_id, "alias": "", "tags": [], "hash": dev.pw_hash,
                      "hostname": "masaustu", "username": "", "platform": "Linux"}]


def test_forged_signature_and_key_swap_are_ignored(client):
    dev = Device()
    token = dev.login(client)["access_token"]
    dev.heartbeat(client)

    attacker = SigningKey.generate()
    dev.heartbeat(client, key=attacker, pw_hash=b64(b"attacker-hash"))
    assert ab_peers(client, token)[0]["hash"] == dev.pw_hash

    # Password change on the real device is picked up.
    dev.heartbeat(client, pw_hash=b64(b"new-h1"))
    assert ab_peers(client, token)[0]["hash"] == b64(b"new-h1")


def test_unknown_device_and_mobile_are_not_enrolled(client):
    assert Device(uuid="other").heartbeat(client)["account_enrolled"] is False
    phone = Device(uuid="phone", os="android")
    token = phone.login(client)["access_token"]
    assert phone.heartbeat(client)["account_enrolled"] is False
    assert ab_peers(client, token) == []


def test_user_address_book_is_kept_and_merged(client):
    dev = Device()
    token = dev.login(client)["access_token"]
    dev.heartbeat(client)
    data = {"tags": ["ev"], "peers": [
        {"id": dev.rd_id, "alias": "Salon PC", "tags": ["ev"], "hash": "stale"},
        {"id": "555", "alias": "Arkadaş", "tags": []},
    ]}
    assert client.post("/api/ab", json={"data": json.dumps(data)}, headers=auth(token)).status_code == 200
    peers = {p["id"]: p for p in ab_peers(client, token)}
    assert peers[dev.rd_id]["alias"] == "Salon PC"
    assert peers[dev.rd_id]["hash"] == dev.pw_hash
    assert "hash" not in peers["555"]


def test_remove_device_unenrolls(client):
    dev = Device()
    token = dev.login(client)["access_token"]
    dev.heartbeat(client)
    uuid = client.get("/api/panel/devices", headers=auth(token)).json()[0]["uuid"]
    client.post("/api/panel/devices/remove", json={"uuid": uuid}, headers=auth(token))
    assert dev.heartbeat(client)["account_enrolled"] is False
    assert ab_peers(client, token) == []


def test_other_account_cannot_see_devices(client):
    from app.main import create_user

    create_user("baska", "baska-sifre-123")
    dev = Device()
    dev.login(client)
    dev.heartbeat(client)
    other = client.post("/api/login", json={"username": "baska", "password": "baska-sifre-123",
                                            "deviceInfo": {"type": "browser"}}).json()["access_token"]
    assert ab_peers(client, other) == []
    assert client.get("/api/panel/devices", headers=auth(other)).json() == []


def test_wrong_password_and_rate_limit(client):
    dev = Device()
    assert dev.login(client, password="yanlis")["error"] == "Wrong username or password"
    for _ in range(12):
        r = client.post("/api/login", json={"username": "baris", "password": "yanlis"})
    assert r.status_code == 429
    assert client.get("/api/ab", headers=auth("sahte")).status_code == 401


def test_totp_login(client):
    token = Device().login(client)["access_token"]
    setup = client.post("/api/panel/totp/setup", headers=auth(token)).json()
    code = pyotp.TOTP(setup["secret"]).now()
    assert client.post("/api/panel/totp/enable", json={"secret": setup["secret"], "code": code},
                       headers=auth(token)).json() == {}

    dev = Device(uuid="yeni-pc", rd_id="999")
    step1 = dev.login(client)
    assert step1["type"] == "email_check" and step1["tfa_type"] == "tfa_check"
    bad = client.post("/api/login", json={"secret": step1["secret"], "tfaCode": "000000"}).json()
    assert bad["error"] == "Wrong verification code"
    ok = client.post("/api/login", json={
        "secret": step1["secret"], "tfaCode": pyotp.TOTP(setup["secret"]).now(), "username": "baris",
        "deviceInfo": {"os": "windows", "type": "client", "name": "is-pc"}}).json()
    assert ok["type"] == "access_token"
    # The device from the password step got linked.
    assert dev.heartbeat(client)["account_enrolled"] is True


def test_logout_revokes_token(client):
    token = Device().login(client)["access_token"]
    client.post("/api/logout", headers=auth(token))
    assert client.post("/api/currentUser", headers=auth(token)).status_code == 401
