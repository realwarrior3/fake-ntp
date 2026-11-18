#!/usr/bin/env python3
import base64
import hmac
import ipaddress
import json
import os
import socket
import sqlite3
import struct
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

DB_PATH = "/var/lib/multi-ntp/ntp.db"
NTP_PORT = 123
WEB_PORT = 80
NTP_EPOCH = 2208988800

# Налаштування входу у веб-інтерфейс (можна змінити тут або через systemd Environment)
AUTH_USER = os.environ.get("NTP_WEB_USER", "admin")
AUTH_PASS = os.environ.get("NTP_WEB_PASS", "MyStrongPassword123")

# Кеш правил у пам'яті для миттєвої обробки NTP-пакетів
rules_lock = threading.RLock()
exact_rules = {}     # "192.168.1.51" -> dict
network_rules = []   # [(IPv4Network, dict), ...]
default_rule = {"offset_hours": 0.0, "auto_dst": False, "dst_zone": "Europe/Kyiv"}


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT '',
            offset_hours REAL NOT NULL DEFAULT 0,
            auto_dst INTEGER NOT NULL DEFAULT 0,
            dst_zone TEXT NOT NULL DEFAULT 'Europe/Kyiv',
            hits INTEGER NOT NULL DEFAULT 0,
            last_seen TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        INSERT OR IGNORE INTO rules (target, name, offset_hours, auto_dst, dst_zone)
        VALUES ('0.0.0.0/0', 'За замовчуванням (вся мережа - стандартний UTC)', 0, 0, 'Europe/Kyiv')
    """)
    conn.commit()
    conn.close()


def reload_cache():
    global exact_rules, network_rules, default_rule
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM rules").fetchall()
    conn.close()

    new_exact = {}
    new_nets = []
    new_default = {"id": None, "offset_hours": 0.0, "auto_dst": False, "dst_zone": "Europe/Kyiv"}

    for r in rows:
        item = dict(r)
        target = item["target"].strip()
        if target == "0.0.0.0/0":
            new_default = item
        elif "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
                new_nets.append((net, item))
            except ValueError:
                pass
        else:
            new_exact[target] = item

    new_nets.sort(key=lambda x: x[0].prefixlen, reverse=True)

    with rules_lock:
        exact_rules = new_exact
        network_rules = new_nets
        default_rule = new_default


def get_rule_for_ip(ip_str):
    with rules_lock:
        if ip_str in exact_rules:
            return exact_rules[ip_str]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net, rule in network_rules:
                if ip_obj in net:
                    return rule
        except ValueError:
            pass
        return default_rule


def calculate_offset_seconds(rule):
    base_sec = float(rule["offset_hours"]) * 3600.0
    if rule["auto_dst"]:
        try:
            tz = ZoneInfo(rule.get("dst_zone") or "Europe/Kyiv")
            dst_delta = datetime.now(tz).dst()
            if dst_delta:
                base_sec += dst_delta.total_seconds()
        except Exception:
            pass
    return base_sec


def log_hit_async(rule_id, ip_str):
    if not rule_id:
        return
    try:
        now_str = datetime.now(ZoneInfo("Europe/Kyiv")).strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(DB_PATH, timeout=2)
        conn.execute(
            "UPDATE rules SET hits = hits + 1, last_seen = ? WHERE id = ?",
            (f"{now_str} ({ip_str})", rule_id)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def ntp_server_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", NTP_PORT))
    print(f"[NTP] Listening on UDP 0.0.0.0:{NTP_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if len(data) < 48:
                continue

            client_ip = addr[0]
            rule = get_rule_for_ip(client_ip)
            offset_sec = calculate_offset_seconds(rule)

            unix_ts = time.time() + offset_sec
            ntp_ts = unix_ts + NTP_EPOCH
            sec = int(ntp_ts)
            frac = int((ntp_ts - sec) * (2**32))
            orig_ts = data[40:48]

            packet = struct.pack(
                "!B B B b I I 4s Q 8s Q Q",
                0x1C, 2, 6, -20, 0, 0, b"LOCL",
                (sec << 32) | frac, orig_ts,
                (sec << 32) | frac, (sec << 32) | frac
            )
            sock.sendto(packet, addr)

            threading.Thread(target=log_hit_async, args=(rule.get("id"), client_ip), daemon=True).start()
        except Exception as e:
            print(f"[NTP Error] {e}")


HTML_PAGE = """<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Multi-Timezone NTP Server</title>
<style>
  :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --accent: #3b82f6; --danger: #ef4444; --ok: #22c55e; --border: #334155; }
  body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
  .container { max-width: 1100px; margin: 0 auto; }
  .header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; margin-bottom: 20px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  h1, h2 { margin: 0 0 12px 0; font-size: 1.25rem; }
  .clock-box { background: #0b1120; padding: 10px 16px; border-radius: 8px; border: 1px solid var(--border); font-family: monospace; font-size: 0.95rem; }
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; align-items: end; }
  label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 5px; }
  input[type="text"], input[type="number"], select {
    width: 100%; box-sizing: border-box; padding: 9px 12px; border-radius: 6px;
    border: 1px solid var(--border); background: #0f172a; color: var(--text); font-size: 0.95rem;
  }
  .checkbox-wrap { display: flex; align-items: center; gap: 8px; height: 38px; cursor: pointer; }
  .checkbox-wrap input { width: 18px; height: 18px; cursor: pointer; }
  button { padding: 10px 16px; border-radius: 6px; border: none; font-weight: 600; cursor: pointer; font-size: 0.9rem; }
  .btn-primary { background: var(--accent); color: white; }
  .btn-primary:hover { opacity: 0.9; }
  .btn-danger { background: var(--danger); color: white; padding: 6px 10px; font-size: 0.8rem; }
  .btn-edit { background: #475569; color: white; padding: 6px 10px; font-size: 0.8rem; margin-right: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
  th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; }
  .badge { padding: 3px 8px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; }
  .badge-on { background: rgba(34, 197, 94, 0.2); color: var(--ok); }
  .badge-off { background: rgba(148, 163, 184, 0.2); color: var(--muted); }
  .search-bar { margin-bottom: 12px; max-width: 320px; }
  .hint { font-size: 0.82rem; color: var(--muted); margin-top: 8px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>🕒 Локальний NTP-сервер (керування часом пристроїв)</h1>
      <div class="hint">UDP порт 123 активний • Підтримує окремі IP та підмережі (CIDR)</div>
    </div>
    <div class="clock-box" id="serverClock">Завантаження часу...</div>
  </div>

  <div class="card">
    <h2 id="formTitle">Додати або оновити правило</h2>
    <form id="ruleForm" class="form-grid">
      <div>
        <label>IP-адреса або підмережа *</label>
        <input type="text" id="target" placeholder="192.168.1.51 або 192.168.1.0/24" required>
      </div>
      <div>
        <label>Назва / Примітка</label>
        <input type="text" id="name" placeholder="Камера двір (GMT+0)">
      </div>
      <div>
        <label>Базове зміщення (год)</label>
        <input type="number" id="offset_hours" step="0.5" value="2" required>
      </div>
      <div>
        <label>Сезонний перехід (літо/зима)</label>
        <label class="checkbox-wrap">
          <input type="checkbox" id="auto_dst" checked>
          <span>Авто +1 год влітку (Київ)</span>
        </label>
      </div>
      <div>
        <button type="submit" class="btn-primary" style="width:100%">Зберегти правило</button>
      </div>
    </form>
    <div class="hint">
      💡 <b>Підказка для камер:</b> Якщо на камері виставлено пояс <b>GMT+0</b>, вкажіть зміщення <b>+2</b> та увімкніть <b>Авто +1 год влітку</b> — камера завжди показуватиме точний київський час без ручного переведення. Для стандартного UTC вкажіть <b>0</b> без автопереходу.
    </div>
  </div>

  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:10px;">
      <h2 style="margin:0;">Активні правила (<span id="countRules">0</span>)</h2>
      <input type="text" id="searchInput" class="search-bar" placeholder="Пошук за IP або назвою..." oninput="renderTable()">
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>IP / Підмережа</th>
            <th>Пристрій</th>
            <th>Зміщення</th>
            <th>Літній час (DST)</th>
            <th>Видається зараз</th>
            <th>Запитів / Останній</th>
            <th>Дії</th>
          </tr>
        </thead>
        <tbody id="rulesBody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
let allRules = [];
let serverInfo = {};

async function loadData() {
  const res = await fetch('/api/rules');
  if (res.status === 401) return;
  const data = await res.json();
  allRules = data.rules;
  serverInfo = data.server;
  document.getElementById('serverClock').innerHTML =
    `UTC: <b>${serverInfo.utc}</b> | Київ: <b>${serverInfo.kyiv}</b> (${serverInfo.is_dst ? 'Літній +3' : 'Зимовий +2'})`;
  renderTable();
}

function renderTable() {
  const q = document.getElementById('searchInput').value.toLowerCase();
  const filtered = allRules.filter(r =>
    r.target.toLowerCase().includes(q) || (r.name || '').toLowerCase().includes(q)
  );
  document.getElementById('countRules').textContent = filtered.length;
  const tbody = document.getElementById('rulesBody');
  tbody.innerHTML = filtered.map(r => {
    const sign = r.offset_hours >= 0 ? '+' : '';
    const dstBadge = r.auto_dst
      ? `<span class="badge badge-on">Авто (${serverInfo.is_dst ? '+1 активний' : 'взимку +0'})</span>`
      : `<span class="badge badge-off">Вимкнено</span>`;
    const isDefault = r.target === '0.0.0.0/0';
    return `<tr>
      <td><b>${r.target}</b></td>
      <td>${r.name || '—'}</td>
      <td><b>${sign}${r.offset_hours} год</b></td>
      <td>${dstBadge}</td>
      <td style="font-family:monospace; color:#38bdf8;">${r.effective_time}</td>
      <td style="font-size:0.82rem; color:#94a3b8;">${r.hits} <br>${r.last_seen || 'ще не було'}</td>
      <td>
        <button class="btn-edit" onclick='editRule(${JSON.stringify(r)})'>Змінити</button>
        ${isDefault ? '' : `<button class="btn-danger" onclick="deleteRule(${r.id})">Видалити</button>`}
      </td>
    </tr>`;
  }).join('');
}

function editRule(r) {
  document.getElementById('target').value = r.target;
  document.getElementById('name').value = r.name || '';
  document.getElementById('offset_hours').value = r.offset_hours;
  document.getElementById('auto_dst').checked = !!r.auto_dst;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.getElementById('ruleForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    target: document.getElementById('target').value.trim(),
    name: document.getElementById('name').value.trim(),
    offset_hours: parseFloat(document.getElementById('offset_hours').value),
    auto_dst: document.getElementById('auto_dst').checked ? 1 : 0
  };
  const res = await fetch('/api/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (res.ok) {
    document.getElementById('ruleForm').reset();
    document.getElementById('offset_hours').value = 2;
    document.getElementById('auto_dst').checked = true;
    loadData();
  } else {
    const err = await res.json();
    alert(err.error || 'Помилка збереження');
  }
});

async function deleteRule(id) {
  if (!confirm('Видалити це правило?')) return;
  await fetch('/api/rules?id=' + id, { method: 'DELETE' });
  loadData();
}

loadData();
setInterval(loadData, 5000);
</script>
</body>
</html>
"""


class WebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def check_auth(self):
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                user, pwd = decoded.split(":", 1)
                if hmac.compare_digest(user, AUTH_USER) and hmac.compare_digest(pwd, AUTH_PASS):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Multi-Timezone NTP Server"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("Потрібна авторизація".encode("utf-8"))
        return False

    def send_json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.check_auth():
            return
        if self.path == "/" or self.path.startswith("/?"):
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/rules":
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute("SELECT * FROM rules ORDER BY id ASC").fetchall()]
            conn.close()

            now_utc = datetime.now(timezone.utc)
            now_kyiv = datetime.now(ZoneInfo("Europe/Kyiv"))
            for r in rows:
                eff_sec = calculate_offset_seconds(r)
                eff_dt = datetime.fromtimestamp(time.time() + eff_sec, tz=timezone.utc)
                r["effective_time"] = eff_dt.strftime("%Y-%m-%d %H:%M:%S")

            self.send_json(200, {
                "server": {
                    "utc": now_utc.strftime("%Y-%m-%d %H:%M:%S"),
                    "kyiv": now_kyiv.strftime("%Y-%m-%d %H:%M:%S"),
                    "is_dst": bool(now_kyiv.dst())
                },
                "rules": rows
            })
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self.check_auth():
            return
        if self.path == "/api/rules":
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            target = data.get("target", "").strip()
            name = data.get("name", "").strip()
            offset_hours = float(data.get("offset_hours", 0))
            auto_dst = 1 if data.get("auto_dst") else 0

            try:
                if "/" in target:
                    ipaddress.ip_network(target, strict=False)
                else:
                    ipaddress.ip_address(target)
            except ValueError:
                self.send_json(400, {"error": "Некоректна IP-адреса або підмережа CIDR"})
                return

            conn = sqlite3.connect(DB_PATH)
            conn.execute("""
                INSERT INTO rules (target, name, offset_hours, auto_dst)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target) DO UPDATE SET
                    name=excluded.name,
                    offset_hours=excluded.offset_hours,
                    auto_dst=excluded.auto_dst
            """, (target, name, offset_hours, auto_dst))
            conn.commit()
            conn.close()
            reload_cache()
            self.send_json(200, {"ok": True})

    def do_DELETE(self):
        if not self.check_auth():
            return
        if self.path.startswith("/api/rules?id="):
            rule_id = int(self.path.split("=")[1])
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM rules WHERE id = ? AND target != '0.0.0.0/0'", (rule_id,))
            conn.commit()
            conn.close()
            reload_cache()
            self.send_json(200, {"ok": True})


if __name__ == "__main__":
    init_db()
    reload_cache()
    t_ntp = threading.Thread(target=ntp_server_loop, daemon=True)
    t_ntp.start()
    print(f"[WEB] Listening on HTTP 0.0.0.0:{WEB_PORT}")
    httpd = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), WebHandler)
    httpd.serve_forever()
