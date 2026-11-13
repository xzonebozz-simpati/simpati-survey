"""Tes login admin (Superadmin SIMPATI 555) & Informasi Lisensi.
Jalankan: python -m pytest test_admin_login.py -v   (tidak memerlukan database)"""
import hashlib
import hmac
import json
import urllib.parse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from simpati_admin import (
    IntegrationMisconfigured, InvalidCredentials, LockedOut, LoginThrottle,
    SimpatiAdminClient, Unavailable,
)
from simpati_admin_pages import render_license_info_html, render_login_html
from simpati_admin_routes import build_router, safe_next
from simpati_license_gate import is_mutation_allowed_when_restricted

TOKEN = "integration-token-123"

INFO = {
    "product_name": "SIMPATI 555", "package_name": "Paket Lengkap", "customer_name": "Ikatan 555",
    "territory_scope": "Nasional", "license_key": "SMP-LIC-2026-AAAA-BBBB",
    "installation_code": "INST-1", "client_id": "cid-1", "allowed_levels": ["DPD", "DPC"],
    "valid_from": "01 Januari 2026 00:00 WIB", "valid_until": "31 Desember 2027 00:00 WIB",
    "remaining_license_time": "400 hari 2 jam", "validation_status": "ACTIVE",
    "is_restricted_mode": False, "is_offline": False, "connection_status": "ONLINE (Terhubung ke License Manager)",
    "last_validated_at": "-", "next_validation_due": "-", "grace_type": "NONE",
    "offline_grace_remaining": "-",
    "modules": [
        {"code": "SURVEI_GPS", "name": "Pelacakan GPS", "desc": "Survei lapangan", "is_active": True, "status_label": "AKTIF"},
        {"code": "AI_ANALYTICS", "name": "Analitik AI", "desc": "x", "is_active": False, "status_label": "TIDAK DILISENSIKAN"},
        {"code": "UMKM", "name": "UMKM", "desc": "y", "is_active": False, "status_label": "DITANGGUHKAN"},
    ],
    "capacity": {"max_members": "50.000", "max_accounts": "200", "max_concurrent_users": "25", "max_storage_mb": "20 GB"},
}


def sign(body, token=TOKEN):
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    out = dict(body)
    out["signature"] = hmac.new(token.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return out


def nonce_from(url_or_payload):
    if isinstance(url_or_payload, dict):
        return url_or_payload["nonce"]
    return urllib.parse.parse_qs(urllib.parse.urlparse(url_or_payload).query)["nonce"][0]


class FakeSimpati:
    """Meniru SIMPATI 555 sisi M2M."""
    def __init__(self):
        self.calls = []
        self.verify_status = 200
        self.verify_user = "superadmin"
        self.info_status = 200
        self.tamper = False
        self.raise_exc = None
        self.unsigned_403 = False

    def __call__(self, method, url, token, payload, timeout):
        self.calls.append((method, url, payload))
        if self.raise_exc:
            raise self.raise_exc
        if "/superadmin/verify" in url:
            if self.verify_status == 403 and not self.unsigned_403:
                return 403, sign({"ok": False, "reason": "invalid_credentials", "nonce": payload["nonce"]})
            if self.verify_status != 200:
                return self.verify_status, {"detail": "x"}
            body = {"ok": True, "username": self.verify_user, "role": "SUPERADMIN", "nonce": payload["nonce"]}
            if self.tamper:
                body["nonce"] = "bukan-nonce-kita"
            return 200, sign(body)
        if "/lisensi/info" in url:
            if self.info_status != 200:
                return self.info_status, {"detail": "x"}
            return 200, sign({"info": INFO, "nonce": nonce_from(url)})
        raise AssertionError(url)


# ------------------------------------------------------------------ klien
def make_client(fake):
    return SimpatiAdminClient("http://555", TOKEN, fetcher=fake)


def test_verify_ok():
    assert make_client(FakeSimpati()).verify_superadmin("superadmin", "pw") == "superadmin"


@pytest.mark.parametrize("status,exc", [(403, InvalidCredentials), (429, LockedOut),
                                        (401, IntegrationMisconfigured), (503, Unavailable), (500, Unavailable)])
def test_verify_error_mapping(status, exc):
    f = FakeSimpati(); f.verify_status = status
    with pytest.raises(exc):
        make_client(f).verify_superadmin("superadmin", "pw")


def test_unsigned_403_from_proxy_is_not_wrong_password():
    f = FakeSimpati(); f.verify_status = 403; f.unsigned_403 = True
    with pytest.raises(Unavailable):
        make_client(f).verify_superadmin("superadmin", "pw")


def test_verify_rejects_replayed_nonce():
    f = FakeSimpati(); f.tamper = True
    with pytest.raises(Unavailable):
        make_client(f).verify_superadmin("superadmin", "pw")


def test_verify_rejects_forged_signature():
    def forged(method, url, token, payload, timeout):
        body = sign({"ok": True, "username": "superadmin", "role": "SUPERADMIN", "nonce": payload["nonce"]}, "token-lain")
        return 200, body
    with pytest.raises(Unavailable):
        SimpatiAdminClient("http://555", TOKEN, fetcher=forged).verify_superadmin("superadmin", "pw")


def test_verify_network_failure_is_unavailable():
    f = FakeSimpati(); f.raise_exc = OSError("down")
    with pytest.raises(Unavailable):
        make_client(f).verify_superadmin("superadmin", "pw")


def test_unconfigured_fails_closed():
    with pytest.raises(IntegrationMisconfigured):
        SimpatiAdminClient("", "", fetcher=FakeSimpati()).verify_superadmin("a", "b")


def test_non_superadmin_role_rejected():
    def f(method, url, token, payload, timeout):
        return 200, sign({"ok": True, "username": "x", "role": "ADMIN", "nonce": payload["nonce"]})
    with pytest.raises(InvalidCredentials):
        SimpatiAdminClient("http://555", TOKEN, fetcher=f).verify_superadmin("x", "pw")


def test_info_cached_then_refreshed():
    t = [100.0]
    f = FakeSimpati()
    c = SimpatiAdminClient("http://555", TOKEN, fetcher=f, info_ttl_seconds=30, clock=lambda: t[0])
    c.fetch_license_info(); c.fetch_license_info()
    assert len(f.calls) == 1
    t[0] += 31
    c.fetch_license_info()
    assert len(f.calls) == 2


def test_info_bad_signature_rejected():
    def bad(method, url, token, payload, timeout):
        return 200, sign({"info": INFO, "nonce": nonce_from(url)}, "token-lain")
    with pytest.raises(Unavailable):
        SimpatiAdminClient("http://555", TOKEN, fetcher=bad).fetch_license_info()


# ------------------------------------------------------------------ throttle
def test_throttle_locks_and_expires():
    t = [0.0]
    th = LoginThrottle(3, 100, clock=lambda: t[0])
    for _ in range(3):
        assert th.retry_after("ip") == 0
        th.fail("ip")
    assert th.retry_after("ip") > 0
    assert th.retry_after("ip-lain") == 0
    t[0] += 101
    assert th.retry_after("ip") == 0


# ------------------------------------------------------------------ halaman
def test_safe_next():
    assert safe_next("/admin/lisensi") == "/admin/lisensi"
    for bad in ("", "https://evil.com", "//evil.com", "/\\evil", "javascript:alert(1)", "/admin/login", "/x\r\nSet-Cookie: a=b"):
        assert safe_next(bad) == "/superuser/dashboard"


def test_login_page_is_maroon_gold_and_escapes():
    html = render_login_html(error='<script>alert(1)</script>', next_url='/a"><b>', username='"><img src=x>')
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert '"><img' not in html
    assert "#d4af37" in html and "#20080d" in html          # gold + maroon
    assert 'name="username"' in html and 'name="password"' in html


def test_license_page_content_and_escaping():
    evil = dict(INFO, customer_name="<img src=x onerror=alert(1)>")
    html = render_license_info_html(evil, username="superadmin", simpati_url="https://555.example")
    assert "<img src=x onerror" not in html and "&lt;img src=x" in html
    for needle in ("LENGKAP &amp; AKTIF", "SURVEI_GPS", "AKTIF", "TIDAK BERLISENSI", "DITANGGUHKAN",
                   "SMP-LIC-2026-AAAA-BBBB", "400 hari 2 jam", "50.000", "DPD", "https://555.example/superadmin/lisensi"):
        assert needle in html, needle
    assert 'name="license_key"' not in html                  # tidak ada form aktivasi di Survei


def test_license_page_when_555_unreachable():
    html = render_license_info_html(None, username="su", fetch_error="SIMPATI 555 tidak dapat dihubungi.",
                                    survey_restricted=True, survey_reason="alasan x")
    assert "tidak dapat dimuat" in html and "Mode Terbatas" in html and "alasan x" in html


# ------------------------------------------------------------------ rute
class Store:
    def __init__(self):
        self.sessions = {}
        self.activity = []
        self.n = 0

    def issue(self, user):
        self.n += 1
        tok = f"tok-{self.n}"
        self.sessions[tok] = user
        return tok

    def lookup(self, tok):
        return self.sessions.get(tok)

    def revoke(self, tok):
        self.sessions.pop(tok, None)

    def record(self, user, request, action):
        self.activity.append((user, action))


@pytest.fixture()
def env():
    store, fake = Store(), FakeSimpati()
    app = FastAPI()
    app.include_router(build_router(
        client=SimpatiAdminClient("http://555", TOKEN, fetcher=fake),
        issue_session=store.issue, session_username=store.lookup, revoke_session=store.revoke,
        record_activity=store.record, gate_evaluate=lambda: (False, ""), simpati_url="http://555",
        throttle=LoginThrottle(3, 300), cookie_secure=False))
    return TestClient(app, follow_redirects=False), store, fake


def login(c, user="superadmin", pw="pw", **extra):
    return c.post("/admin/login", data={"username": user, "password": pw, **extra})


def test_login_page_renders(env):
    c, _, _ = env
    r = c.get("/admin/login")
    assert r.status_code == 200 and "Login Admin Survei GPS" in r.text
    assert r.headers["cache-control"] == "no-store"


def test_login_success_sets_session_cookie_and_redirects(env):
    c, store, _ = env
    r = login(c)
    assert r.status_code == 303 and r.headers["location"] == "/superuser/dashboard"
    set_cookie = r.headers["set-cookie"].lower()
    assert "sidps_session=tok-1" in set_cookie and "httponly" in set_cookie and "samesite=lax" in set_cookie
    assert store.sessions == {"tok-1": "superadmin"}
    assert ("superadmin", "LOGIN_VIA_SIMPATI_SUPERADMIN") in store.activity


def test_login_respects_safe_next_only(env):
    c, _, _ = env
    assert login(c, next="/admin/lisensi").headers["location"] == "/admin/lisensi"
    assert login(c, next="https://evil.com").headers["location"] == "/superuser/dashboard"


def test_login_wrong_password(env):
    c, store, fake = env
    fake.verify_status = 403
    r = login(c, pw="salah")
    assert r.status_code == 401 and "salah" in r.text and "set-cookie" not in r.headers
    assert not store.sessions


def test_login_lockout_after_failures(env):
    c, _, fake = env
    fake.verify_status = 403
    for _ in range(3):
        assert login(c, pw="x").status_code == 401
    fake.verify_status = 200
    r = login(c)
    assert r.status_code == 429 and "Retry-After" in r.headers          # benar pun ditolak saat terkunci
    assert len([x for x in fake.calls if "/verify" in x[1]]) == 3        # tidak lagi menghubungi 555


def test_login_555_down_gives_503_not_session(env):
    c, store, fake = env
    fake.raise_exc = OSError("down")
    r = login(c)
    assert r.status_code == 503 and "tidak dapat dihubungi" in r.text and not store.sessions


def test_login_bad_integration_token_message(env):
    c, _, fake = env
    fake.verify_status = 401
    r = login(c)
    assert r.status_code == 503 and "SIMPATI_INTEGRATION_TOKEN" in r.text


def test_login_requires_fields(env):
    c, _, fake = env
    assert login(c, user="", pw="").status_code == 400 and not fake.calls


def test_login_page_redirects_when_already_logged_in(env):
    c, _, _ = env
    login(c)
    c.cookies.set("sidps_session", "tok-1")
    assert c.get("/admin/login?next=/admin/lisensi").headers["location"] == "/admin/lisensi"


def test_license_requires_login(env):
    c, _, _ = env
    for path in ("/admin/lisensi", "/superuser/lisensi"):
        r = c.get(path)
        assert r.status_code == 303 and r.headers["location"].startswith("/admin/login?next=" + path)


def test_license_page_after_login(env):
    c, store, _ = env
    login(c)
    c.cookies.set("sidps_session", "tok-1")
    for path in ("/admin/lisensi", "/superuser/lisensi"):
        r = c.get(path)
        assert r.status_code == 200 and "Informasi Lisensi" in r.text and "SURVEI_GPS" in r.text
    assert ("superadmin", "OPEN_LICENSE_INFO") in store.activity


def test_license_page_degrades_when_555_down(env):
    c, _, fake = env
    login(c); c.cookies.set("sidps_session", "tok-1")
    fake.info_status = 503
    r = c.get("/admin/lisensi")
    assert r.status_code == 200 and "tidak dapat dimuat" in r.text


def test_logout_revokes_session(env):
    c, store, _ = env
    login(c); c.cookies.set("sidps_session", "tok-1")
    r = c.post("/admin/logout")
    assert r.status_code == 303 and r.headers["location"] == "/admin/login" and not store.sessions
    c.cookies.set("sidps_session", "tok-1")
    assert c.get("/admin/lisensi").status_code == 303


# ------------------------------------------------------------------ gerbang lisensi
def test_login_logout_allowed_in_restricted_mode():
    assert is_mutation_allowed_when_restricted("POST", "/admin/login")
    assert is_mutation_allowed_when_restricted("POST", "/admin/logout")
    assert not is_mutation_allowed_when_restricted("POST", "/admin/master-data-wilayah")
