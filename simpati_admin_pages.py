"""simpati_admin_pages.py - HTML halaman login admin & Informasi Lisensi (tema dark maroon-gold).

Tampilan Informasi Lisensi mengikuti halaman yang sama di menu admin SIMPATI 555
(/admin/lisensi). Perbedaan yang disengaja:
  * semua nilai dari jaringan di-escape (anti XSS),
  * form aktivasi License Key tidak ada: server Survei tidak memegang kredensial License
    Manager; aktivasi/perpanjangan dilakukan di SIMPATI 555,
  * ada blok status penegakan lisensi di server Survei sendiri.

Catatan: tag <style id="theme2-global"> sengaja dipakai agar middleware tema global server.py
tidak menyuntik CSS kedua yang menimpa gaya halaman ini.
"""
from __future__ import annotations

from html import escape
from typing import Optional

_ESC = escape


def _e(value, default: str = "-") -> str:
    if value is None or value == "":
        return default
    return _ESC(str(value), quote=True)


_BASE_CSS = """
:root{color-scheme:dark;--maroon:#20080d;--maroon-dark:#140508;--maroon-light:#421018;--gold:#d4af37;
--text:#f5ede0;--card-bg:#280d12;--border:#4a1c24;--muted:#bcaaa4}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--maroon-dark);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;line-height:1.5;min-height:100vh}
a{color:var(--gold)}
.btn{display:inline-block;padding:8px 16px;border-radius:6px;text-decoration:none;font-weight:600;font-size:.85rem;cursor:pointer;border:1px solid var(--gold);font-family:inherit}
.btn-gold{background:var(--gold);color:var(--maroon)}
.btn-gold:hover{background:#e6c24f}
.btn-outline{background:transparent;color:var(--gold)}
.btn-outline:hover{background:rgba(212,175,55,.15)}
"""

# ---------------------------------------------------------------- LOGIN

_LOGIN_CSS = """
body{display:grid;place-items:center;padding:24px;
background:radial-gradient(ellipse at top right,#421018 0,#20080d 45%,#140508 100%)}
.shell{width:min(430px,100%)}
.card{background:linear-gradient(145deg,#2c0f15 0%,#1a060a 100%);border:1px solid var(--border);
border-top:3px solid var(--gold);border-radius:16px;padding:32px 28px;box-shadow:0 18px 50px rgba(0,0,0,.6)}
.logo{display:block;width:84px;height:84px;object-fit:contain;margin:0 auto 14px;border-radius:50%;
box-shadow:0 0 0 2px var(--gold),0 0 24px rgba(212,175,55,.25);background:#140508}
h1{text-align:center;font-size:1.35rem;color:var(--gold);letter-spacing:.4px}
.sub{text-align:center;color:var(--muted);font-size:.88rem;margin:6px 0 22px}
label{display:block;font-size:.8rem;font-weight:700;color:var(--gold);margin:14px 0 6px}
.field{position:relative}
input{width:100%;padding:12px 14px;border-radius:8px;border:1px solid #624449;background:#140508;color:#fff;font-size:1rem;font-family:inherit}
input:focus{outline:2px solid rgba(212,175,55,.55);border-color:var(--gold)}
.eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:0;color:var(--gold);
cursor:pointer;font-size:.78rem;font-weight:700;padding:8px}
button.submit{margin-top:22px;width:100%;padding:13px;border:0;border-radius:8px;background:var(--gold);color:var(--maroon);
font-weight:800;font-size:1rem;cursor:pointer;font-family:inherit;box-shadow:0 2px 10px rgba(212,175,55,.3)}
button.submit:hover{background:#e6c24f}
button.submit:disabled{opacity:.6;cursor:wait}
.err{background:#7f1d1d;border:1px solid #dc2626;color:#fee2e2;border-radius:8px;padding:11px 13px;font-size:.88rem;margin-bottom:6px}
.note{margin-top:18px;font-size:.78rem;color:var(--muted);text-align:center}
"""


def render_login_html(error: str = "", next_url: str = "", username: str = "") -> str:
    err_html = f'<div class="err" role="alert">{_e(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#20080d"><meta name="robots" content="noindex,nofollow">
<title>Login Admin | Survei GPS 555</title>
<style id="theme2-global">{_BASE_CSS}{_LOGIN_CSS}</style></head>
<body><main class="shell"><div class="card">
<img class="logo" src="/logo.png" alt="Logo 555" onerror="this.style.display='none'">
<h1>Login Admin Survei GPS</h1>
<p class="sub">Masuk dengan akun Superadmin SIMPATI 555</p>
{err_html}
<form method="post" action="/admin/login" autocomplete="on" id="f">
<input type="hidden" name="next" value="{_e(next_url, '')}">
<label for="u">USERNAME SUPERADMIN</label>
<input id="u" name="username" value="{_e(username, '')}" required autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="200" autofocus>
<label for="p">PASSWORD</label>
<div class="field"><input id="p" type="password" name="password" required autocomplete="current-password" maxlength="500">
<button type="button" class="eye" id="eye" aria-label="Tampilkan password">LIHAT</button></div>
<button class="submit" type="submit" id="go">MASUK</button>
</form>
<p class="note">Akun ini dikelola di SIMPATI 555. Server Survei tidak menyimpan password Superadmin.</p>
</div></main>
<script>
var p=document.getElementById('p'),b=document.getElementById('eye');
b.onclick=function(){{var s=p.type==='password';p.type=s?'text':'password';b.textContent=s?'SEMBUNYI':'LIHAT';}};
document.getElementById('f').addEventListener('submit',function(){{var g=document.getElementById('go');g.disabled=true;g.textContent='MEMERIKSA...';}});
</script></body></html>"""


# ---------------------------------------------------------------- INFORMASI LISENSI

_INFO_CSS = """
header.top{background:linear-gradient(135deg,var(--maroon) 0%,var(--maroon-light) 100%);border-bottom:2px solid var(--gold);
padding:18px 28px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.brand{display:flex;align-items:center;gap:12px;font-size:1.25rem;font-weight:800;color:var(--gold);letter-spacing:.5px}
.brand img{width:34px;height:34px;border-radius:50%;object-fit:contain}
.brand small{font-size:.9rem;color:#e0d4c0;font-weight:400}
.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.actions form{display:inline}
.container{max-width:1180px;margin:24px auto;padding:0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:20px;margin-bottom:24px}
.card{background:var(--card-bg);border:1px solid var(--border);border-radius:10px;padding:20px;box-shadow:0 4px 14px rgba(0,0,0,.4)}
.card-header{font-size:1.05rem;font-weight:700;color:var(--gold);margin-bottom:14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border);padding-bottom:10px}
.info-row{display:flex;justify-content:space-between;gap:14px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:.9rem}
.info-label{color:var(--muted);font-weight:500;flex:none}
.info-value{font-weight:600;text-align:right;color:#fff;word-break:break-word}
.mono{font-family:ui-monospace,Consolas,monospace}
.status-banner{border-radius:10px;padding:18px 24px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}
.status-title{font-size:1.3rem;font-weight:800;display:flex;align-items:center;gap:10px}
.table-wrap{overflow-x:auto;background:var(--card-bg);border:1px solid var(--border);border-radius:10px;margin-bottom:24px}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{background:#38141b;color:var(--gold);padding:12px 14px;text-align:left;font-weight:700;border-bottom:2px solid var(--border)}
td{padding:10px 14px;border-bottom:1px solid #3d161d}
.badge{padding:3px 8px;border-radius:4px;font-weight:700;font-size:.75rem;white-space:nowrap;border:1px solid}
.b-ok{background:#064e3b;color:#34d399;border-color:#059669}
.b-warn{background:#7f1d1d;color:#f87171;border-color:#dc2626}
.b-off{background:#374151;color:#9ca3af;border-color:#4b5563}
.lvl{background:#2a1015;border:1px solid var(--gold);color:var(--gold);padding:3px 8px;border-radius:4px;font-size:.75rem;font-weight:700;margin-left:4px;display:inline-block}
.notice-box{background:rgba(212,175,55,.08);border:1px solid rgba(212,175,55,.3);border-radius:8px;padding:14px;font-size:.85rem;color:#e0d4c0;margin-top:16px;display:flex;gap:10px}
.alert{border-radius:10px;padding:14px 18px;margin-bottom:24px;font-size:.92rem;border:2px solid}
.alert.bad{background:#7f1d1d;border-color:#dc2626;color:#fee2e2}
.alert.warn{background:#78350f;border-color:#d97706;color:#fde68a}
.manage{border:2px solid var(--gold);background:linear-gradient(145deg,#280d12 0%,#1a060a 100%);margin-bottom:24px}
"""

_STATUS_STYLE = {
    "ACTIVE": ("#064e3b", "#059669", "#34d399", "🟢", "LENGKAP & AKTIF"),
    "RESTRICTED": ("#7f1d1d", "#dc2626", "#f87171", "🔴", "RESTRICTED MODE (TERBATAS)"),
    "SUSPENDED": ("#7f1d1d", "#dc2626", "#f87171", "🔴", "DITANGGUHKAN"),
    "REVOKED": ("#7f1d1d", "#dc2626", "#f87171", "🔴", "DICABUT"),
}


def _row(label: str, value_html: str, extra: str = "") -> str:
    return (f'<div class="info-row"><span class="info-label">{label}</span>'
            f'<span class="info-value{extra}">{value_html}</span></div>')


def render_license_info_html(
    info: Optional[dict],
    *,
    username: str = "",
    fetch_error: str = "",
    survey_restricted: Optional[bool] = None,
    survey_reason: str = "",
    simpati_url: str = "",
    back_url: str = "/superuser/dashboard",
) -> str:
    """Render halaman Informasi Lisensi. `info` None bila gagal diambil dari SIMPATI 555."""
    manage_url = (_e(simpati_url.rstrip("/") + "/superadmin/lisensi", "") if simpati_url else "")
    manage_btn = (f'<a class="btn btn-gold" href="{manage_url}" target="_blank" rel="noopener noreferrer">'
                  f'Buka Informasi Lisensi di SIMPATI 555 ↗</a>') if manage_url else ""

    header = f"""<header class="top">
<div class="brand"><img src="/logo.png" alt="" onerror="this.style.display='none'">
<span>🛡️ SURVEI GPS 555</span><small>| Informasi Lisensi Resmi</small></div>
<div class="actions"><span style="font-size:.85rem;color:var(--gold)">Superadmin{(' · ' + _e(username)) if username else ''}</span>
<a href="{_e(back_url, '/')}" class="btn btn-outline">← Kembali ke Dashboard</a>
<form method="post" action="/admin/logout"><button class="btn btn-outline" type="submit">Keluar</button></form></div></header>"""

    if info is None:
        body = f"""<main class="container">
<div class="alert bad"><b>Informasi lisensi tidak dapat dimuat.</b><br>{_e(fetch_error or 'SIMPATI 555 tidak dapat dihubungi.')}</div>
<div class="card manage"><div class="card-header">🔑 Aktivasi &amp; Perpanjangan Lisensi</div>
<p style="font-size:.9rem;margin-bottom:14px">Lisensi dikelola di SIMPATI 555. Server Survei hanya menampilkan status.</p>{manage_btn}</div>
{_survey_gate_card(survey_restricted, survey_reason)}</main>"""
        return _page(header, body)

    status = str(info.get("validation_status") or "UNVERIFIED")
    is_offline = bool(info.get("is_offline"))
    if status == "GRACE_PERIOD":
        sb, sbd, st, icon, label = ("#78350f", "#d97706", "#fbbf24", "⚠️",
                                    f"MASA TENGGANG ({'OFFLINE' if is_offline else 'KONTRAK'})")
    elif status in _STATUS_STYLE:
        sb, sbd, st, icon, label = _STATUS_STYLE[status]
    else:
        sb, sbd, st, icon, label = ("#374151", "#6b7280", "#d1d5db", "⚪", status)
    conn_color = "#ef4444" if is_offline else "#10b981"
    conn_icon = "🔴" if is_offline else "🟢"

    rows = []
    for m in info.get("modules") or []:
        lbl = str(m.get("status_label") or "")
        if m.get("is_active"):
            badge = '<span class="badge b-ok">AKTIF</span>'
        elif "DITANGGUHKAN" in lbl:
            badge = '<span class="badge b-warn">DITANGGUHKAN</span>'
        else:
            badge = '<span class="badge b-off">TIDAK BERLISENSI</span>'
        rows.append(
            f'<tr><td class="mono" style="color:var(--gold);font-weight:700">{_e(m.get("code"))}</td>'
            f'<td><div style="font-weight:600;color:#fbf6ec">{_e(m.get("name"))}</div>'
            f'<div style="font-size:.8rem;color:var(--muted)">{_e(m.get("desc"))}</div></td>'
            f'<td style="text-align:center">{badge}</td></tr>')
    levels = "".join(f'<span class="lvl">{_e(l)}</span>' for l in info.get("allowed_levels") or [])
    cap = info.get("capacity") or {}
    grace_color = "#f59e0b" if is_offline else "#34d399"

    body = f"""<main class="container">
<section class="status-banner" style="background:{sb};border:2px solid {sbd}">
<div><div class="status-title" style="color:{st}">{icon} Status Lisensi: {_e(label)}</div>
<div style="font-size:.9rem;color:#e5e7eb;margin-top:4px">Produk: <b>{_e(info.get('product_name'))}</b> · Paket: <b>{_e(info.get('package_name'))}</b></div></div>
<div style="text-align:right"><span style="font-size:.85rem;color:var(--muted)">Koneksi License Manager (via SIMPATI 555):</span><br>
<b style="color:{conn_color}">{conn_icon} {_e(info.get('connection_status'))}</b></div></section>

<div class="card manage"><div class="card-header" style="justify-content:space-between">🔑 AKTIVASI &amp; PERPANJANGAN LISENSI
<span style="font-size:.8rem;font-weight:600">Dikelola di SIMPATI 555</span></div>
<p style="font-size:.88rem;margin-bottom:14px">Server Survei membaca status lisensi dari SIMPATI 555 dan tidak menyimpan License Key atau kredensial License Manager.
Untuk mengaktifkan atau mengganti License Key, gunakan menu Informasi Lisensi di SIMPATI 555.</p>{manage_btn}</div>

{_survey_gate_card(survey_restricted, survey_reason)}

<div class="grid">
<div class="card"><div class="card-header">📄 Identitas Lisensi &amp; Pelanggan</div>
{_row('Pemegang Lisensi', _e(info.get('customer_name')))}
{_row('Cakupan Wilayah', _e(info.get('territory_scope')))}
{_row('License Key', _e(info.get('license_key')), ' mono')}
{_row('Installation Code', _e(info.get('installation_code')), ' mono')}
{_row('Client ID (M2M)', _e(info.get('client_id')), ' mono')}
{_row('Tingkat Diizinkan', levels or '-')}</div>

<div class="card"><div class="card-header">⏳ Masa Berlaku &amp; Validasi</div>
{_row('Tanggal Mulai', _e(info.get('valid_from')))}
{_row('Tanggal Berakhir', _e(info.get('valid_until')))}
{_row('Sisa Masa Aktif', '<span style="color:var(--gold)">' + _e(info.get('remaining_license_time')) + '</span>')}
{_row('Validasi Terakhir', _e(info.get('last_validated_at')))}
{_row('Validasi Berikutnya', _e(info.get('next_validation_due')))}
{_row('Jenis Grace Period', _e(info.get('grace_type')))}
{_row('Sisa Offline Grace', '<span style="color:' + grace_color + '">' + _e(info.get('offline_grace_remaining')) + '</span>')}</div>

<div class="card"><div class="card-header">📊 Kapasitas &amp; Kuota Paket</div>
{_row('Maksimal Anggota', '<span style="color:var(--gold)">' + _e(cap.get('max_members')) + '</span>')}
{_row('Maksimal Akun Petugas', _e(cap.get('max_accounts')))}
{_row('Pengguna Bersamaan', _e(cap.get('max_concurrent_users')) + ' sesi')}
{_row('Penyimpanan Dokumen', _e(cap.get('max_storage_mb')))}
<div class="notice-box"><span>🔒 Halaman ini hanya baca. Pengelolaan lisensi dilakukan dari SIMPATI License Manager.</span></div></div>
</div>

<section class="table-wrap">
<div style="padding:14px 18px;font-weight:700;color:var(--gold);font-size:1.05rem;border-bottom:1px solid var(--border)">🧩 Daftar Modul &amp; Status Fungsionalitas Aplikasi</div>
<table><thead><tr><th style="width:180px">KODE MODUL</th><th>NAMA MODUL &amp; DESKRIPSI</th><th style="width:160px;text-align:center">STATUS HAK AKSES</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="3">Tidak ada data modul.</td></tr>'}</tbody></table></section>
</main>"""
    return _page(header, body)


def _survey_gate_card(restricted: Optional[bool], reason: str) -> str:
    if restricted is None:
        return ""
    if restricted:
        return (f'<div class="alert warn"><b>Server Survei dalam Mode Terbatas.</b> Data survei tidak dapat diubah '
                f'(login dan baca data tetap berfungsi).<br>{_e(reason)}</div>')
    return ('<div class="notice-box" style="margin:0 0 24px"><span>✅ Penegakan lisensi di server Survei: '
            '<b>normal</b>. Modul SURVEI_GPS berlisensi dan semua fitur dapat digunakan.</span></div>')


def _page(header: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Informasi Lisensi | Survei GPS 555</title>
<style id="theme2-global">{_BASE_CSS}{_INFO_CSS}</style></head><body>{header}{body}</body></html>"""
