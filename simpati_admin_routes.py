"""simpati_admin_routes.py - rute login admin (akun Superadmin SIMPATI 555) & Informasi Lisensi.

Rute:
  GET  /admin/login                   halaman login (tema dark maroon-gold)
  POST /admin/login                   verifikasi ke SIMPATI 555 -> terbitkan sesi SUPERUSER global
  POST /admin/logout                  cabut sesi + hapus cookie
  GET  /admin/lisensi                 menu Informasi Lisensi (sama dengan /admin/lisensi di SIMPATI 555)
  GET  /superuser/lisensi             alias dari /admin/lisensi

Sesi yang diterbitkan adalah sesi SUPERUSER yang sudah ada (cookie `sidps_session`, tabel
superuser_sessions), sehingga seluruh dashboard yang memeriksa sesi tersebut langsung dikenali.
Dependensi server.py diinjeksi lewat build_router() agar modul ini dapat diuji tanpa database.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional
from urllib.parse import quote

from fastapi import APIRouter, Cookie, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from simpati_admin import (
    IntegrationMisconfigured, InvalidCredentials, LockedOut, LoginThrottle,
    SimpatiAdminClient, SimpatiAdminError, Unavailable,
)
from simpati_admin_pages import render_license_info_html, render_login_html

logger = logging.getLogger("simpati_admin_routes")

DEFAULT_AFTER_LOGIN = "/superuser/dashboard"
COOKIE_NAME = "sidps_session"
SESSION_MAX_AGE = 43200  # 12 jam, sama dengan sesi SUPERUSER yang ada
_NO_STORE = {"Cache-Control": "no-store"}


def safe_next(value: Optional[str]) -> str:
    """Hanya path lokal; tolak URL absolut, //host, backslash, dan loop ke halaman login."""
    v = (value or "").strip()
    if (not v.startswith("/") or v.startswith("//") or "\\" in v or "\n" in v or "\r" in v
            or v.startswith("/admin/login") or v.startswith("/admin/logout")):
        return DEFAULT_AFTER_LOGIN
    return v


def build_router(
    *,
    client: SimpatiAdminClient,
    issue_session: Callable[[str], str],
    session_username: Callable[[Optional[str]], Optional[str]],
    revoke_session: Callable[[str], None],
    record_activity: Callable[[str, Request, str], None],
    gate_evaluate: Callable[[], "tuple[bool, str]"],
    simpati_url: str = "",
    throttle: Optional[LoginThrottle] = None,
    cookie_secure: bool = True,
) -> APIRouter:
    router = APIRouter(tags=["Admin Survei"])
    throttle = throttle or LoginThrottle()

    def _ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _login_page(request: Request, error: str = "", next_url: str = "", username: str = "",
                    status_code: int = 200, headers: Optional[dict] = None) -> HTMLResponse:
        h = dict(_NO_STORE)
        h.update(headers or {})
        return HTMLResponse(render_login_html(error, next_url, username), status_code=status_code, headers=h)

    @router.get("/admin/login", response_class=HTMLResponse, include_in_schema=False)
    def login_page(request: Request, next: str = "", sidps_session: Optional[str] = Cookie(default=None)):
        target = safe_next(next)
        if session_username(sidps_session):
            return RedirectResponse(target, status_code=303)
        return _login_page(request, next_url=target if next else "")

    @router.post("/admin/login", response_class=HTMLResponse, include_in_schema=False)
    def login_submit(request: Request, username: str = Form(""), password: str = Form(""),
                     next: str = Form("")):
        username = username.strip()
        target = safe_next(next)
        keep_next = target if next else ""
        ip = _ip(request)

        wait = throttle.retry_after(ip)
        if wait:
            return _login_page(request, f"Terlalu banyak percobaan gagal. Coba lagi dalam {wait // 60 + 1} menit.",
                               keep_next, username, 429, {"Retry-After": str(wait)})
        if not username or not password:
            return _login_page(request, "Username dan password wajib diisi.", keep_next, username, 400)

        try:
            verified_user = client.verify_superadmin(username, password)
        except InvalidCredentials as e:
            throttle.fail(ip)
            logger.warning("Login admin gagal dari %s.", ip)
            return _login_page(request, str(e), keep_next, username, 401)
        except LockedOut as e:
            return _login_page(request, str(e), keep_next, username, 429)
        except (IntegrationMisconfigured, Unavailable) as e:
            return _login_page(request, str(e), keep_next, username, 503)
        except SimpatiAdminError as e:  # pragma: no cover - cadangan
            return _login_page(request, str(e), keep_next, username, 503)

        throttle.reset(ip)
        token = issue_session(verified_user)
        record_activity(verified_user, request, "LOGIN_VIA_SIMPATI_SUPERADMIN")
        response = RedirectResponse(target, status_code=303)
        response.set_cookie(COOKIE_NAME, token, max_age=SESSION_MAX_AGE, httponly=True,
                            secure=cookie_secure, samesite="lax", path="/")
        response.headers["Cache-Control"] = "no-store"
        return response

    @router.post("/admin/logout", include_in_schema=False)
    def logout(request: Request, sidps_session: Optional[str] = Cookie(default=None)):
        if sidps_session:
            try:
                revoke_session(sidps_session)
            except Exception:
                logger.exception("Gagal mencabut sesi saat logout.")
        response = RedirectResponse("/admin/login", status_code=303)
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    def _license_page(request: Request, sidps_session: Optional[str]):
        user = session_username(sidps_session)
        if not user:
            return RedirectResponse("/admin/login?next=" + quote(request.url.path, safe="/"), status_code=303)
        record_activity(user, request, "OPEN_LICENSE_INFO")
        info, error = None, ""
        try:
            info = client.fetch_license_info()
        except SimpatiAdminError as e:
            error = str(e)
        try:
            restricted, reason = gate_evaluate()
        except Exception:
            restricted, reason = None, ""
        html = render_license_info_html(info, username=user, fetch_error=error,
                                        survey_restricted=restricted, survey_reason=reason,
                                        simpati_url=simpati_url)
        return HTMLResponse(html, headers=_NO_STORE)

    @router.get("/admin/lisensi", response_class=HTMLResponse, include_in_schema=False)
    def license_admin(request: Request, sidps_session: Optional[str] = Cookie(default=None)):
        return _license_page(request, sidps_session)

    @router.get("/superuser/lisensi", response_class=HTMLResponse, include_in_schema=False)
    def license_superuser(request: Request, sidps_session: Optional[str] = Cookie(default=None)):
        return _license_page(request, sidps_session)

    return router
