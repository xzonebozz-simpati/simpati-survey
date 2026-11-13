"""simpati_admin.py - klien integrasi server Survei -> SIMPATI 555 untuk login admin & info lisensi.

Server Survei tidak menyimpan password Superadmin. Verifikasi dilakukan ke SIMPATI 555
(POST /api/integrasi/superadmin/verify) memakai SIMPATI_INTEGRATION_TOKEN. Respons sukses wajib
ditandatangani HMAC-SHA256 (kunci = token) dan memuat nonce penanya, sama seperti gerbang lisensi.

Galat dari 555 dipetakan ke exception berbeda supaya pesan ke pengguna tepat:
  401 -> IntegrationMisconfigured  (token integrasi tidak cocok)
  403 -> InvalidCredentials        (username/password salah; hanya bila respons bertanda tangan)
  429 -> LockedOut                 (terkunci sementara di 555)
  503 / jaringan / respons palsu -> Unavailable
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional

logger = logging.getLogger("simpati_admin")


class SimpatiAdminError(Exception):
    """Dasar semua galat integrasi; pesan aman ditampilkan ke pengguna."""


class InvalidCredentials(SimpatiAdminError):
    pass


class LockedOut(SimpatiAdminError):
    def __init__(self, message: str, retry_after: int = 0):
        super().__init__(message)
        self.retry_after = retry_after


class IntegrationMisconfigured(SimpatiAdminError):
    pass


class Unavailable(SimpatiAdminError):
    pass


Fetcher = Callable[[str, str, str, Optional[dict], float], "tuple[int, dict]"]


def _http_fetch(method: str, url: str, token: str, payload: Optional[dict], timeout: float):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"X-SIMPATI-Token": token, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {}
        return e.code, body


class SimpatiAdminClient:
    def __init__(self, api_url: str, token: str, fetcher: Optional[Fetcher] = None,
                 info_ttl_seconds: float = 30.0, clock: Callable[[], float] = time.time):
        self.api_url = (api_url or "").rstrip("/")
        self.token = token or ""
        self._fetch = fetcher or _http_fetch
        self._ttl = info_ttl_seconds
        self._clock = clock
        self._info_lock = threading.Lock()
        self._info_cache: Optional[tuple[float, dict]] = None

    @property
    def configured(self) -> bool:
        return bool(self.api_url and self.token)

    # ---- verifikasi respons ----
    def _verified(self, body: dict, nonce: str) -> dict:
        body = dict(body)
        sig = str(body.pop("signature", ""))
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(self.token.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        if not sig or not hmac.compare_digest(sig, expected):
            raise Unavailable("Respons SIMPATI 555 tidak valid (tanda tangan tidak cocok).")
        if body.get("nonce") != nonce:
            raise Unavailable("Respons SIMPATI 555 tidak valid (nonce tidak cocok).")
        return body

    def _require_configured(self) -> None:
        if not self.configured:
            raise IntegrationMisconfigured(
                "SIMPATI_API_URL dan SIMPATI_INTEGRATION_TOKEN belum dikonfigurasi di server Survei.")

    def _call(self, method: str, path: str, payload: Optional[dict] = None, query: str = "") -> tuple[int, dict]:
        url = f"{self.api_url}{path}{query}"
        try:
            return self._fetch(method, url, self.token, payload, 10.0)
        except Exception as e:  # jaringan putus, DNS, timeout, dsb.
            logger.warning("SIMPATI 555 tidak terjangkau (%s %s): %s", method, path, e)
            raise Unavailable("SIMPATI 555 tidak dapat dihubungi. Coba lagi beberapa saat.") from e

    # ---- API ----
    def verify_superadmin(self, username: str, password: str) -> str:
        """Kembalikan username Superadmin yang sah, atau lempar SimpatiAdminError."""
        self._require_configured()
        nonce = secrets.token_hex(12)
        status, body = self._call("POST", "/api/integrasi/superadmin/verify",
                                  {"username": username, "password": password, "nonce": nonce})
        if status == 200:
            ok = self._verified(body, nonce)
            if ok.get("ok") is True and ok.get("role") == "SUPERADMIN" and ok.get("username"):
                return str(ok["username"])
            raise InvalidCredentials("Username atau password Superadmin salah.")
        if status == 403:
            # Hanya 403 bertanda tangan dari 555 yang berarti kredensial salah; 403 lain
            # (proxy/WAF/Cloudflare) diperlakukan sebagai layanan tidak tersedia.
            try:
                denied = self._verified(body, nonce)
            except Unavailable:
                raise Unavailable("Permintaan ditolak oleh perantara jaringan sebelum sampai ke SIMPATI 555.")
            if denied.get("ok") is False:
                raise InvalidCredentials("Username atau password Superadmin salah.")
            raise Unavailable("Respons penolakan dari SIMPATI 555 tidak dikenali.")
        if status == 429:
            raise LockedOut("Terlalu banyak percobaan gagal di SIMPATI 555. Coba lagi beberapa menit lagi.")
        if status == 401:
            logger.error("SIMPATI 555 menolak token integrasi (401).")
            raise IntegrationMisconfigured(
                "Token integrasi ditolak SIMPATI 555. Periksa SIMPATI_INTEGRATION_TOKEN di kedua server.")
        logger.error("Verifikasi superadmin gagal, HTTP %s dari SIMPATI 555.", status)
        raise Unavailable("SIMPATI 555 belum siap memverifikasi akun Superadmin.")

    def fetch_license_info(self, force: bool = False) -> dict:
        """Data halaman Informasi Lisensi dari 555 (cache singkat, tanda tangan diverifikasi)."""
        self._require_configured()
        with self._info_lock:
            now = self._clock()
            if not force and self._info_cache and now - self._info_cache[0] < self._ttl:
                return dict(self._info_cache[1])
            nonce = secrets.token_hex(12)
            status, body = self._call("GET", "/api/integrasi/lisensi/info",
                                      query="?nonce=" + urllib.parse.quote(nonce))
            if status == 401:
                raise IntegrationMisconfigured("Token integrasi ditolak SIMPATI 555.")
            if status != 200:
                raise Unavailable(f"SIMPATI 555 menjawab HTTP {status} untuk informasi lisensi.")
            info = self._verified(body, nonce).get("info")
            if not isinstance(info, dict):
                raise Unavailable("Respons informasi lisensi dari SIMPATI 555 tidak lengkap.")
            self._info_cache = (now, info)
            return dict(info)


class LoginThrottle:
    """Pembatas percobaan login gagal per kunci (IP). Memori proses; cukup sebagai lapis pertama."""

    def __init__(self, max_failures: int = 5, window_seconds: float = 300.0,
                 clock: Callable[[], float] = time.time):
        self.max, self.window, self._clock = max_failures, window_seconds, clock
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}

    def _prune(self, key: str) -> list[float]:
        now = self._clock()
        fresh = [t for t in self._fails.get(key, []) if now - t < self.window]
        if fresh:
            self._fails[key] = fresh
        else:
            self._fails.pop(key, None)
        return fresh

    def retry_after(self, key: str) -> int:
        with self._lock:
            fresh = self._prune(key)
            if len(fresh) >= self.max:
                return int(self.window - (self._clock() - fresh[0])) + 1
            return 0

    def fail(self, key: str) -> None:
        with self._lock:
            self._prune(key)
            self._fails.setdefault(key, []).append(self._clock())

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
