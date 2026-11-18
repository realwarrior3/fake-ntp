#!/usr/bin/env python3
"""
Fake NTP Server — локальний NTP-сервер для старих пристроїв.

Усі дані лежать поруч із цим файлом:
    /opt/fake-ntp/server.py
    /opt/fake-ntp/config.json
    /opt/fake-ntp/credentials.json
    /opt/fake-ntp/ntp.db
    /opt/fake-ntp/fake-ntp.service

За замовчуванням сервіс не змінює системний час — він лише додає обчислений
зсув до NTP-відповідей, тому коректно працює у LXC-контейнерах.
За бажанням (окрема галочка у веб-інтерфейсі) може встановлювати системний
час з upstream NTP — для запуску на реальному сервері як заміни NTP-демона.
"""

import base64
import copy
import hmac
import ipaddress
import json
import os
import socket
import sqlite3
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from zoneinfo import ZoneInfo, available_timezones

# ---------------------------------------------------------------------------
# Шляхи та константи
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "ntp.db"
CONFIG_PATH = BASE_DIR / "config.json"
CRED_PATH = BASE_DIR / "credentials.json"

DEFAULT_RULE_TARGET = "0.0.0.0/0"
NTP_EPOCH = 2208988800

try:
    TIMEZONES = sorted(available_timezones())
except Exception:
    # Fallback для систем без встановленої IANA-бази (наприклад, Windows без tzdata)
    TIMEZONES = [
        "UTC", "Europe/Kyiv", "Europe/London", "Europe/Berlin", "Europe/Paris",
        "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
        "America/Sao_Paulo", "Asia/Tokyo", "Asia/Shanghai", "Asia/Kolkata",
        "Australia/Sydney", "Pacific/Auckland",
    ]
TIMEZONE_SET = set(TIMEZONES)
_timezone_options_cache = None

DEFAULT_CONFIG = {
    "ntp_port": 123,
    "web_port": 80,
    "default_timezone": "UTC",
    "default_use_dst": False,
    "upstream": {
        "enabled": False,
        "server": "pool.ntp.org",
        "port": 123,
        "timeout": 2.0,
        "sync_interval": 300,
        "set_system_clock": False,
        "clock_set_threshold": 0.5,
    },
}

config = copy.deepcopy(DEFAULT_CONFIG)
config_lock = threading.RLock()

auth_users = []
setup_lock = threading.Lock()

rules_lock = threading.RLock()
exact_rules = {}
network_rules = []
default_rule = {}

upstream_lock = threading.RLock()
upstream_state = {
    "offset": 0.0,
    "last_sync": None,
    "last_attempt": None,
    "delay": None,
    "error": None,
    "clock_applied": False,
    "last_clock_set": None,
    "clock_error": None,
}
upstream_wake = threading.Event()


# ---------------------------------------------------------------------------
# Конфігурація та облікові дані
# ---------------------------------------------------------------------------

def write_json(path, data, mode=None):
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    if mode is not None:
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def valid_timezone(name):
    return name == "UTC" or name in TIMEZONE_SET


def validate_config(cfg):
    for key in ("ntp_port", "web_port"):
        val = int(cfg[key])
        if not 1 <= val <= 65535:
            raise ValueError(f"{key} має бути в діапазоні 1..65535")
        cfg[key] = val

    if not valid_timezone(cfg["default_timezone"]):
        raise ValueError("Невідомий часовий пояс за замовчуванням")

    up = cfg["upstream"]
    up["server"] = str(up["server"]).strip()
    if not up["server"] or any(c.isspace() for c in up["server"]):
        raise ValueError("Некоректна адреса upstream NTP-сервера")
    up["port"] = int(up["port"])
    if not 1 <= up["port"] <= 65535:
        raise ValueError("Некоректний порт upstream NTP-сервера")
    up["timeout"] = float(up["timeout"])
    if not 0.2 <= up["timeout"] <= 30:
        raise ValueError("timeout має бути в діапазоні 0.2..30")
    up["sync_interval"] = int(up["sync_interval"])
    if not 30 <= up["sync_interval"] <= 86400:
        raise ValueError("sync_interval має бути в діапазоні 30..86400")
    up["enabled"] = bool(up["enabled"])
    up["set_system_clock"] = bool(up["set_system_clock"])
    up["clock_set_threshold"] = float(up["clock_set_threshold"])
    if not 0.01 <= up["clock_set_threshold"] <= 60:
        raise ValueError("clock_set_threshold має бути в діапазоні 0.01..60")
    cfg["default_use_dst"] = bool(cfg["default_use_dst"])
    return cfg


def load_config():
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                user_cfg = json.load(f)
            cfg.update({k: v for k, v in user_cfg.items() if k != "upstream"})
            cfg["upstream"].update(user_cfg.get("upstream", {}))
            cfg = validate_config(cfg)
        except Exception as e:
            print(f"[CONFIG] Помилка читання {CONFIG_PATH}: {e}. Використано значення за замовчуванням.")
            cfg = copy.deepcopy(DEFAULT_CONFIG)
    else:
        write_json(CONFIG_PATH, cfg, 0o600)
        print(f"[CONFIG] Створено {CONFIG_PATH}")
    return cfg


def set_config(new_cfg):
    global config
    with config_lock:
        config = new_cfg


def get_config():
    with config_lock:
        return copy.deepcopy(config)


def init_credentials():
    """
    Завантажує облікові дані. Якщо файлу ще немає — створює порожній список,
    і перший вхід у веб-інтерфейс стане сторінкою створення адміністратора.
    """
    global auth_users
    if not CRED_PATH.exists():
        write_json(CRED_PATH, {"users": []}, 0o600)
        print(f"[AUTH] Облікових даних немає. Відкрийте веб-інтерфейс і створіть логін/пароль адміністратора.")
        auth_users = []
        return
    try:
        with open(CRED_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        users = data.get("users", [])
        if not isinstance(users, list):
            raise ValueError("users має бути списком")
        clean = []
        for u in users:
            username = str(u.get("username", ""))
            password = str(u.get("password", ""))
            role = str(u.get("role", "user"))
            if username and password:
                clean.append({"username": username, "password": password, "role": role})
        auth_users = clean
    except Exception as e:
        raise RuntimeError(f"Не вдалося завантажити {CRED_PATH}: {e}")


def needs_setup():
    return len(auth_users) == 0


def complete_setup(username, password):
    """Створює першого користувача з правами адміна. Повторні виклики ігноруються."""
    global auth_users
    with setup_lock:
        if auth_users:
            return False
        entry = {"username": username, "password": password, "role": "admin"}
        write_json(CRED_PATH, {"users": [entry]}, 0o600)
        auth_users = [entry]
        return True


# ---------------------------------------------------------------------------
# База правил
# ---------------------------------------------------------------------------

RULE_COLUMNS = "id, target, name, offset_hours, tz_name, use_dst, hits, last_seen"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT '',
            offset_hours REAL NOT NULL DEFAULT 0,
            tz_name TEXT NOT NULL DEFAULT 'UTC',
            use_dst INTEGER NOT NULL DEFAULT 0,
            hits INTEGER NOT NULL DEFAULT 0,
            last_seen TEXT DEFAULT ''
        )
    """)
    cfg = get_config()
    conn.execute(
        "INSERT OR IGNORE INTO rules (target, name, offset_hours, tz_name, use_dst) "
        "VALUES (?, ?, 0, ?, ?)",
        (DEFAULT_RULE_TARGET, "За замовчуванням (вся мережа — стандартний час)",
         cfg["default_timezone"], int(cfg["default_use_dst"])),
    )
    conn.execute(
        "UPDATE rules SET tz_name = ?, use_dst = ? WHERE target = ?",
        (cfg["default_timezone"], int(cfg["default_use_dst"]), DEFAULT_RULE_TARGET),
    )
    conn.commit()
    conn.close()
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def reload_cache():
    global exact_rules, network_rules, default_rule
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(f"SELECT {RULE_COLUMNS} FROM rules").fetchall()
    conn.close()

    new_exact = {}
    new_nets = []
    new_default = {
        "id": None, "target": DEFAULT_RULE_TARGET, "name": "За замовчуванням",
        "offset_hours": 0.0, "tz_name": "UTC", "use_dst": 0,
        "hits": 0, "last_seen": "",
    }

    for r in rows:
        item = dict(r)
        target = item["target"].strip()
        if not valid_timezone(item.get("tz_name")):
            item["tz_name"] = "UTC"
        if target == DEFAULT_RULE_TARGET:
            new_default = item
        elif "/" in target:
            try:
                new_nets.append((ipaddress.ip_network(target, strict=False), item))
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


# ---------------------------------------------------------------------------
# Обчислення часу
# ---------------------------------------------------------------------------

def zone_offset_seconds(tz_name, use_dst, at=None):
    """UTC-зсув для IANA-часового поясу. При use_dst=False повертає стандартний зсув."""
    if not tz_name or tz_name == "UTC":
        return 0
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        return 0
    now = at or datetime.now(timezone.utc)
    local = now.astimezone(tz)
    offset = local.utcoffset() or timedelta(0)
    if not use_dst:
        offset -= local.dst() or timedelta(0)
    return int(offset.total_seconds())


def format_offset(seconds):
    """Форматує зсув у вигляді UTC+02:00 / UTC-05:45."""
    total_minutes = int(round(seconds / 60.0))
    sign = "-" if total_minutes < 0 else "+"
    abs_minutes = abs(total_minutes)
    hours = abs_minutes // 60
    minutes = abs_minutes % 60
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def get_timezone_options():
    """
    Повертає список поясів із підписами: стандартний зсув і, якщо відрізняється,
    поточний зсув (активний літній час). Кешується на 1 годину.
    """
    global _timezone_options_cache
    now = datetime.now(timezone.utc)
    if _timezone_options_cache and (now - _timezone_options_cache[0]) < timedelta(hours=1):
        return _timezone_options_cache[1]

    options = []
    for name in TIMEZONES:
        standard = zone_offset_seconds(name, False, now)
        current = zone_offset_seconds(name, True, now)
        label = f"{name} ({format_offset(standard)}"
        if current != standard:
            label += f", зараз {format_offset(current)}"
        label += ")"
        options.append({"name": name, "label": label})

    _timezone_options_cache = (now, options)
    return options


def rule_offset_seconds(rule):
    manual = float(rule.get("offset_hours") or 0) * 3600.0
    zone = zone_offset_seconds(rule.get("tz_name"), bool(rule.get("use_dst")))
    return manual + zone


def upstream_offset():
    cfg = get_config()
    if not cfg["upstream"]["enabled"]:
        return 0.0
    with upstream_lock:
        return float(upstream_state["offset"])


def current_time_for_rule(rule):
    return time.time() + upstream_offset() + rule_offset_seconds(rule)


def log_hit_async(rule_id, ip_str):
    if not rule_id:
        return
    try:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(DB_PATH, timeout=2)
        conn.execute(
            "UPDATE rules SET hits = hits + 1, last_seen = ? WHERE id = ?",
            (f"{now_str} ({ip_str})", rule_id),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Upstream NTP (тільки зсув для відповідей, без зміни системного часу)
# ---------------------------------------------------------------------------

def ntp_to_unix(stamp):
    return (stamp / (2 ** 32)) - NTP_EPOCH


def query_upstream(server, port, timeout):
    packet = struct.pack(
        "!B B B b I I 4s Q Q Q Q",
        0x1B, 3, 0, -20, 0, 0, b"", 0, 0, 0, 0,
    )
    addr = socket.getaddrinfo(server, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t1 = time.time()
        sock.sendto(packet, addr)
        data, _ = sock.recvfrom(1024)
        t4 = time.time()
        if len(data) < 48:
            raise ValueError("Закоротка NTP-відповідь")
        if data[1] == 0:
            raise ValueError("Сервер не синхронізований (stratum 0 / Kiss-o'-Death)")
        t2 = ntp_to_unix(struct.unpack("!Q", data[32:40])[0])
        t3 = ntp_to_unix(struct.unpack("!Q", data[40:48])[0])
        if t3 <= 0 or t2 <= 0:
            raise ValueError("Некоректні часові мітки у відповіді")
        offset = ((t2 - t1) + (t3 - t4)) / 2.0
        delay = (t4 - t1) - (t3 - t2)
        # Оцінений поточний час upstream у момент отримання відповіді.
        return offset, delay, t4 + offset
    finally:
        sock.close()


def set_system_clock(unix_ts):
    """
    Встановлює системний CLOCK_REALTIME через clock_settime(2).
    Потрібні root або CAP_SYS_TIME. У LXC цю функцію слід лишати вимкненою.
    """
    if os.name != "posix":
        raise RuntimeError("Встановлення системного часу підтримується тільки на POSIX-системах")

    import ctypes

    class Timespec(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]

    sec = int(unix_ts)
    nsec = int(round((unix_ts - sec) * 1_000_000_000))
    if nsec >= 1_000_000_000:
        sec += 1
        nsec -= 1_000_000_000

    ts = Timespec(sec, nsec)
    libc = ctypes.CDLL(None, use_errno=True)
    # 0 == CLOCK_REALTIME у Linux/macOS
    if libc.clock_settime(0, ctypes.byref(ts)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def upstream_loop():
    while True:
        cfg = get_config()
        up = cfg["upstream"]
        interval = up["sync_interval"]

        if not up["enabled"]:
            with upstream_lock:
                upstream_state.update({
                    "offset": 0.0, "last_sync": None, "last_attempt": None,
                    "delay": None, "error": None, "clock_applied": False,
                    "last_clock_set": None, "clock_error": None,
                })
        else:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with upstream_lock:
                upstream_state["last_attempt"] = now_str
            try:
                offset, delay, corrected_now = query_upstream(
                    up["server"], up["port"], up["timeout"]
                )
                with upstream_lock:
                    upstream_state.update({
                        "offset": offset, "delay": delay, "last_sync": now_str,
                        "error": None,
                    })
                print(f"[UPSTREAM] {up['server']}: зсув {offset:+.6f} c, затримка {delay:.4f} c")

                if up["set_system_clock"] and abs(offset) >= up["clock_set_threshold"]:
                    try:
                        set_system_clock(corrected_now)
                        # Системний час уже виправлено — більше не додаємо зсув
                        # до NTP-відповідей, інакше вийде подвійний облік.
                        with upstream_lock:
                            upstream_state.update({
                                "offset": 0.0,
                                "clock_applied": True,
                                "last_clock_set": now_str,
                                "clock_error": None,
                            })
                        print(f"[CLOCK] Системний час встановлено з {up['server']} ({now_str})")
                    except Exception as e:
                        with upstream_lock:
                            upstream_state.update({
                                "clock_applied": False,
                                "clock_error": str(e),
                            })
                        print(f"[CLOCK] Не вдалося встановити системний час: {e}")
                else:
                    # Галочка вимкнена — гарантовано не змінюємо системний час.
                    if not up["set_system_clock"]:
                        with upstream_lock:
                            upstream_state.update({
                                "clock_applied": False,
                                "last_clock_set": None,
                                "clock_error": None,
                            })
            except Exception as e:
                with upstream_lock:
                    upstream_state["error"] = str(e)
                print(f"[UPSTREAM] Помилка: {e}")
        upstream_wake.wait(interval)
        upstream_wake.clear()


# ---------------------------------------------------------------------------
# NTP-сервер
# ---------------------------------------------------------------------------

def ntp_server_loop():
    cfg = get_config()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", cfg["ntp_port"]))
    print(f"[NTP] Listening on UDP 0.0.0.0:{cfg['ntp_port']}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if len(data) < 48:
                continue

            rule = get_rule_for_ip(addr[0])
            unix_ts = current_time_for_rule(rule)
            ntp_ts = unix_ts + NTP_EPOCH
            sec = int(ntp_ts)
            frac = int((ntp_ts - sec) * (2 ** 32))
            stamp = (sec << 32) | frac
            orig_ts = data[40:48]

            packet = struct.pack(
                "!B B B b I I 4s Q 8s Q Q",
                0x1C, 2, 6, -20, 0, 0, b"LOCL",
                stamp, orig_ts, stamp, stamp,
            )
            sock.sendto(packet, addr)
            threading.Thread(
                target=log_hit_async, args=(rule.get("id"), addr[0]), daemon=True
            ).start()
        except Exception as e:
            print(f"[NTP Error] {e}")


# ---------------------------------------------------------------------------
# Веб-інтерфейс
# ---------------------------------------------------------------------------

SETUP_PAGE = """<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fake NTP Server — перше налаштування</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }
  .card { max-width: 480px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 24px; }
  h1 { font-size: 1.25rem; margin: 0 0 8px; }
  .hint { font-size: 0.85rem; color: #94a3b8; margin-bottom: 20px; }
  label { display: block; font-size: 0.85rem; color: #94a3b8; margin: 12px 0 5px; }
  input { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #f8fafc; font-size: 0.95rem; }
  button { margin-top: 20px; width: 100%; padding: 11px; border: none; border-radius: 6px; background: #3b82f6; color: white; font-weight: 600; cursor: pointer; }
  #msg { margin-top: 14px; font-size: 0.85rem; color: #fca5a5; min-height: 1em; }
</style>
</head>
<body>
<div class="card">
  <h1>Перше налаштування Fake NTP Server</h1>
  <div class="hint">Створіть логін і пароль адміністратора. Ці дані зберігатимуться у файлі credentials.json і захищатимуть веб-інтерфейс та API.</div>
  <form id="setupForm">
    <label for="username">Логін</label>
    <input type="text" id="username" autocomplete="username" required minlength="3" maxlength="64">

    <label for="password">Пароль (мінімум 8 символів)</label>
    <input type="password" id="password" autocomplete="new-password" required minlength="8" maxlength="256">

    <label for="confirm">Повторіть пароль</label>
    <input type="password" id="confirm" autocomplete="new-password" required minlength="8" maxlength="256">

    <button type="submit">Створити адміністратора</button>
  </form>
  <div id="msg"></div>
</div>
<script>
document.getElementById('setupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msg = document.getElementById('msg');
  msg.textContent = '';
  const payload = {
    username: document.getElementById('username').value.trim(),
    password: document.getElementById('password').value,
    confirm: document.getElementById('confirm').value
  };
  if (payload.password !== payload.confirm) {
    msg.textContent = 'Паролі не збігаються.';
    return;
  }
  try {
    const res = await fetch('/api/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      msg.style.color = '#86efac';
      msg.textContent = 'Готово. Зараз відкриється запит авторизації — введіть щойно створені дані.';
      setTimeout(() => location.reload(), 1200);
    } else {
      msg.textContent = data.error || 'Не вдалося створити користувача.';
    }
  } catch (err) {
    msg.textContent = "Помилка з'єднання з сервером.";
  }
});
</script>
</body>
</html>
"""

HTML_PAGE = """<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fake NTP Server</title>
<style>
  :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --accent: #3b82f6; --danger: #ef4444; --ok: #22c55e; --border: #334155; }
  body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
  .container { max-width: 1180px; margin: 0 auto; }
  .header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; margin-bottom: 20px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  h1, h2 { margin: 0 0 12px 0; font-size: 1.25rem; }
  .clock-box { background: #0b1120; padding: 10px 16px; border-radius: 8px; border: 1px solid var(--border); font-family: monospace; font-size: 0.95rem; }
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; align-items: end; }
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
  .mono { font-family: monospace; color: #38bdf8; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>Fake NTP Server — керування часом старих пристроїв</h1>
      <div class="hint">UDP 123 активний • довільні IANA-часові пояси • точний час за бажанням береться з upstream NTP</div>
    </div>
    <div class="clock-box" id="serverClock">Завантаження часу...</div>
  </div>

  <div class="card">
    <h2>Додати або оновити правило</h2>
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
        <label>Часовий пояс *</label>
        <select id="tz_name" required></select>
      </div>
      <div>
        <label>Літній час (DST) для цього поясу</label>
        <label class="checkbox-wrap">
          <input type="checkbox" id="use_dst" checked>
          <span>Враховувати переходи автоматично</span>
        </label>
      </div>
      <div>
        <label>Додаткова корекція (год)</label>
        <input type="number" id="offset_hours" step="0.5" value="0">
      </div>
      <div>
        <button type="submit" class="btn-primary" style="width:100%">Зберегти правило</button>
      </div>
    </form>
    <div class="hint">
      Сервер сам обчислює поточний UTC-зсув для обраного поясу. Якщо пристрій уже показує інший час,
      додайте корекцію вручну. Вимкніть DST, щоб видавати постійний стандартний час без літнього переходу.
    </div>
  </div>

  <div class="card">
    <h2>Глобальні налаштування</h2>
    <form id="settingsForm" class="form-grid">
      <div>
        <label>Часовий пояс за замовчуванням</label>
        <select id="default_timezone"></select>
      </div>
      <div>
        <label>DST для правила за замовчуванням</label>
        <label class="checkbox-wrap">
          <input type="checkbox" id="default_use_dst">
          <span>Враховувати літній час</span>
        </label>
      </div>
      <div>
        <label>Upstream NTP сервер</label>
        <input type="text" id="upstream_server" placeholder="pool.ntp.org">
      </div>
      <div>
        <label>Період синхронізації (сек)</label>
        <input type="number" id="sync_interval" min="30" max="86400" step="30">
      </div>
      <div>
        <label>Використовувати точний час з upstream</label>
        <label class="checkbox-wrap">
          <input type="checkbox" id="upstream_enabled">
          <span>Увімкнено (інакше локальний час хоста)</span>
        </label>
      </div>
      <div>
        <label>Змінювати системний час (тільки реальний сервер)</label>
        <label class="checkbox-wrap">
          <input type="checkbox" id="set_system_clock">
          <span>Змінювати системний час (тільки реальний сервер)</span>
        </label>
      </div>
      <div>
        <button type="submit" class="btn-primary" style="width:100%">Зберегти налаштування</button>
      </div>
    </form>
    <div class="hint" id="upstreamStatus">Завантаження статусу...</div>
    <div class="hint">
      Без галочки «Змінювати системний час (тільки реальний сервер)» сервіс лише додає різницю до NTP-відповідей
      і не чіпає годинник хоста — це безпечний режим для LXC, де час задається батьківським хостом.
      Якщо сервіс запущено на реальному сервері, увімкніть цю галочку: тоді після успішного опитування
      upstream буде встановлено системний час, і сервіс працюватиме як повноцінна заміна NTP-демона.
      Потрібні права root або CAP_SYS_TIME. Після встановлення часу додатковий зсув у відповідях
      обнуляється автоматично, щоб не було подвійного врахування.
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
            <th>Часовий пояс</th>
            <th>Літній час</th>
            <th>Корекція</th>
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

const ESC = {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"};
function esc(v) { return String(v ?? "").replace(/[&<>"']/g, c => ESC[c]); }

function fmtOffset(sec) {
  const sign = sec < 0 ? "-" : "+";
  const a = Math.abs(sec);
  const h = Math.floor(a / 3600);
  const m = Math.round((a % 3600) / 60);
  return `UTC${sign}${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}`;
}

async function loadData() {
  try {
    const res = await fetch('/api/rules');
    if (res.status === 401) {
      document.querySelector('.container').innerHTML = '<div class="card">Потрібна авторизація. Оновіть сторінку.</div>';
      return;
    }
    const data = await res.json();
    allRules = data.rules;
    serverInfo = data.server;
    fillTimezoneSelects();
    renderSettings();
    document.getElementById('serverClock').innerHTML =
      `UTC: <b>${esc(serverInfo.utc)}</b> | ${esc(serverInfo.default_timezone)}: <b>${esc(serverInfo.local_time)}</b>`;
    renderTable();
  } catch (e) {
    console.error(e);
  }
}

function tzOptions(selected) {
  return (serverInfo.timezone_options || []).map(o =>
    `<option value="${esc(o.name)}"${o.name === selected ? ' selected' : ''}>${esc(o.label)}</option>`
  ).join('');
}

function fillTimezoneSelects() {
  const ruleSel = document.getElementById('tz_name');
  if (ruleSel && !ruleSel.options.length) ruleSel.innerHTML = tzOptions('UTC');
  const defSel = document.getElementById('default_timezone');
  if (defSel && !defSel.options.length) defSel.innerHTML = tzOptions(serverInfo.default_timezone);
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (el && document.activeElement !== el) el.value = val;
}
function setChk(id, val) {
  const el = document.getElementById(id);
  if (el && document.activeElement !== el) el.checked = !!val;
}

function renderSettings() {
  const up = serverInfo.upstream || {};
  setVal('default_timezone', serverInfo.default_timezone);
  setChk('default_use_dst', serverInfo.default_use_dst);
  setVal('upstream_server', up.server);
  setVal('sync_interval', up.sync_interval);
  setChk('upstream_enabled', up.enabled);
  setChk('set_system_clock', up.set_system_clock);
  const clockBox = document.getElementById('set_system_clock');
  if (clockBox) clockBox.disabled = !up.enabled;

  let txt = up.enabled
    ? `Upstream увімкнено: ${esc(up.server)} • зсув ${Number(up.offset_seconds || 0).toFixed(6)} c • остання синхронізація ${esc(up.last_sync || 'ще не було')}`
    : 'Upstream вимкнено — використовується локальний час хоста.';
  if (up.error) txt += ` • Помилка: ${esc(up.error)}`;
  if (up.set_system_clock) {
    txt += up.clock_applied
      ? ` • Системний час оновлено: ${esc(up.last_clock_set || '—')}`
      : ' • Системний час: ще не застосовано';
    if (up.clock_error) txt += ` • Помилка встановлення часу: ${esc(up.clock_error)}`;
  } else {
    txt += ' • Системний час не змінюється (режим контейнера).';
  }
  document.getElementById('upstreamStatus').textContent = txt;
}

function renderTable() {
  const q = document.getElementById('searchInput').value.toLowerCase();
  const filtered = allRules.filter(r =>
    String(r.target).toLowerCase().includes(q) || String(r.name || '').toLowerCase().includes(q)
  );
  document.getElementById('countRules').textContent = filtered.length;
  const tbody = document.getElementById('rulesBody');
  tbody.innerHTML = filtered.map(r => {
    const isDefault = r.target === '0.0.0.0/0';
    const correction = Number(r.offset_hours || 0);
    const sign = correction >= 0 ? '+' : '';
    const dstBadge = r.use_dst
      ? '<span class="badge badge-on">Авто</span>'
      : '<span class="badge badge-off">Вимкнено</span>';
    return `<tr>
      <td><b>${esc(r.target)}</b></td>
      <td>${esc(r.name || '—')}</td>
      <td class="mono">${esc(r.tz_label || r.tz_name)}</td>
      <td>${dstBadge}</td>
      <td>${sign}${correction} год</td>
      <td style="font-family:monospace; color:#38bdf8;">${esc(r.effective_time)} <span class="hint">${esc(fmtOffset(Number(r.total_offset_seconds || 0)))}</span></td>
      <td style="font-size:0.82rem; color:#94a3b8;">${esc(r.hits)} <br>${esc(r.last_seen || 'ще не було')}</td>
      <td>
        <button class="btn-edit" data-action="edit" data-id="${r.id ?? ''}">Змінити</button>
        ${isDefault ? '' : `<button class="btn-danger" data-action="delete" data-id="${r.id ?? ''}">Видалити</button>`}
      </td>
    </tr>`;
  }).join('');
}

document.getElementById('rulesBody').addEventListener('click', e => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const id = btn.dataset.id;
  if (btn.dataset.action === 'edit') {
    const rule = allRules.find(r => String(r.id ?? '') === id);
    if (rule) editRule(rule);
  } else if (btn.dataset.action === 'delete') {
    deleteRule(Number(id));
  }
});

function editRule(r) {
  document.getElementById('target').value = r.target;
  document.getElementById('name').value = r.name || '';
  document.getElementById('tz_name').value = r.tz_name;
  document.getElementById('use_dst').checked = !!r.use_dst;
  document.getElementById('offset_hours').value = r.offset_hours;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.getElementById('ruleForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    target: document.getElementById('target').value.trim(),
    name: document.getElementById('name').value.trim(),
    tz_name: document.getElementById('tz_name').value,
    use_dst: document.getElementById('use_dst').checked ? 1 : 0,
    offset_hours: parseFloat(document.getElementById('offset_hours').value) || 0
  };
  const res = await fetch('/api/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (res.ok) {
    document.getElementById('ruleForm').reset();
    document.getElementById('offset_hours').value = 0;
    document.getElementById('use_dst').checked = true;
    loadData();
  } else {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Помилка збереження');
  }
});

document.getElementById('settingsForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    default_timezone: document.getElementById('default_timezone').value,
    default_use_dst: document.getElementById('default_use_dst').checked ? 1 : 0,
    upstream: {
      enabled: document.getElementById('upstream_enabled').checked ? 1 : 0,
      set_system_clock: document.getElementById('set_system_clock').checked ? 1 : 0,
      server: document.getElementById('upstream_server').value.trim(),
      sync_interval: parseInt(document.getElementById('sync_interval').value, 10) || 300
    }
  };
  const res = await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (res.ok) {
    loadData();
  } else {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Помилка збереження налаштувань');
  }
});

async function deleteRule(id) {
  if (!confirm('Видалити це правило?')) return;
  await fetch('/api/rules?id=' + encodeURIComponent(id), { method: 'DELETE' });
  loadData();
}

loadData();
setInterval(loadData, 5000);
</script>
</body>
</html>
"""


class WebHandler(BaseHTTPRequestHandler):
    server_version = "FakeNTP/1.0"

    def log_message(self, fmt, *args):
        pass

    def check_auth(self):
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:]).decode("utf-8")
                user, pwd = decoded.split(":", 1)
                for entry in auth_users:
                    if (hmac.compare_digest(user, entry["username"])
                            and hmac.compare_digest(pwd, entry["password"])):
                        return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Fake NTP Server"')
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

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def send_page(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_setup(self):
        if not needs_setup():
            self.send_json(403, {"error": "Адміністратор уже створений"})
            return
        try:
            data = self.read_json()
        except Exception:
            self.send_json(400, {"error": "Некоректний JSON"})
            return

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        confirm = str(data.get("confirm", ""))

        if not 3 <= len(username) <= 64:
            self.send_json(400, {"error": "Логін має містити від 3 до 64 символів"})
            return
        if not 8 <= len(password) <= 256:
            self.send_json(400, {"error": "Пароль має містити від 8 до 256 символів"})
            return
        if password != confirm:
            self.send_json(400, {"error": "Паролі не збігаються"})
            return
        if not complete_setup(username, password):
            self.send_json(403, {"error": "Адміністратор уже створений"})
            return

        print(f"[AUTH] Створено адміністратора '{username}' (роль admin)")
        self.send_json(200, {"ok": True})

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            if needs_setup():
                self.send_page(SETUP_PAGE)
            else:
                if not self.check_auth():
                    return
                self.send_page(HTML_PAGE)
            return

        if not self.check_auth():
            return
        if self.path == "/api/rules":
            self.api_rules()
        else:
            self.send_response(404)
            self.end_headers()

    def api_rules(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(
            f"SELECT {RULE_COLUMNS} FROM rules ORDER BY id ASC"
        ).fetchall()]
        conn.close()

        cfg = get_config()
        tz_default = cfg["default_timezone"]
        tz_options = get_timezone_options()
        tz_labels = {o["name"]: o["label"] for o in tz_options}
        try:
            local_now = datetime.now(ZoneInfo(tz_default)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            local_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        up_offset = upstream_offset()
        for r in rows:
            if not valid_timezone(r.get("tz_name")):
                r["tz_name"] = "UTC"
            r["tz_label"] = tz_labels.get(r["tz_name"], r["tz_name"])
            total = up_offset + rule_offset_seconds(r)
            eff = datetime.fromtimestamp(time.time() + total, tz=timezone.utc)
            r["total_offset_seconds"] = total
            r["effective_time"] = eff.strftime("%Y-%m-%d %H:%M:%S")

        with upstream_lock:
            up_state = dict(upstream_state)
        upstream_public = {
            "enabled": cfg["upstream"]["enabled"],
            "server": cfg["upstream"]["server"],
            "sync_interval": cfg["upstream"]["sync_interval"],
            "set_system_clock": cfg["upstream"]["set_system_clock"],
            "offset_seconds": up_state["offset"] if cfg["upstream"]["enabled"] else 0.0,
            "last_sync": up_state["last_sync"],
            "error": up_state["error"] if cfg["upstream"]["enabled"] else None,
            "clock_applied": up_state["clock_applied"] if cfg["upstream"]["enabled"] else False,
            "last_clock_set": up_state["last_clock_set"],
            "clock_error": up_state["clock_error"] if cfg["upstream"]["enabled"] else None,
        }

        self.send_json(200, {
            "server": {
                "utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "local_time": local_now,
                "default_timezone": tz_default,
                "default_use_dst": cfg["default_use_dst"],
                "timezone_options": tz_options,
                "upstream": upstream_public,
            },
            "rules": rows,
        })

    def do_POST(self):
        if self.path == "/api/setup":
            self.handle_setup()
            return

        if not self.check_auth():
            return
        try:
            data = self.read_json()
        except Exception:
            self.send_json(400, {"error": "Некоректний JSON"})
            return

        if self.path == "/api/rules":
            self.save_rule(data)
        elif self.path == "/api/settings":
            self.save_settings(data)
        else:
            self.send_response(404)
            self.end_headers()

    def save_rule(self, data):
        target = str(data.get("target", "")).strip()
        name = str(data.get("name", "")).strip()
        tz_name = str(data.get("tz_name", "UTC")).strip() or "UTC"
        try:
            offset_hours = float(data.get("offset_hours", 0))
        except (TypeError, ValueError):
            self.send_json(400, {"error": "Некоректне зміщення"})
            return
        use_dst = 1 if data.get("use_dst") else 0

        if not valid_timezone(tz_name):
            self.send_json(400, {"error": "Невідомий часовий пояс"})
            return
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
            INSERT INTO rules (target, name, offset_hours, tz_name, use_dst)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target) DO UPDATE SET
                name=excluded.name,
                offset_hours=excluded.offset_hours,
                tz_name=excluded.tz_name,
                use_dst=excluded.use_dst
        """, (target, name, offset_hours, tz_name, use_dst))
        conn.commit()
        conn.close()

        if target == DEFAULT_RULE_TARGET:
            cfg = get_config()
            cfg["default_timezone"] = tz_name
            cfg["default_use_dst"] = bool(use_dst)
            try:
                cfg = validate_config(cfg)
            except ValueError as e:
                self.send_json(400, {"error": str(e)})
                return
            set_config(cfg)
            write_json(CONFIG_PATH, cfg, 0o600)

        reload_cache()
        self.send_json(200, {"ok": True})

    def save_settings(self, data):
        cfg = get_config()
        cfg["default_timezone"] = str(data.get("default_timezone", cfg["default_timezone"]))
        cfg["default_use_dst"] = bool(data.get("default_use_dst"))

        incoming = data.get("upstream", {})
        if not isinstance(incoming, dict):
            incoming = {}
        for key in ("enabled", "server", "sync_interval", "port", "timeout",
                    "set_system_clock", "clock_set_threshold"):
            if key in incoming:
                cfg["upstream"][key] = incoming[key]

        try:
            cfg = validate_config(cfg)
        except (ValueError, TypeError) as e:
            self.send_json(400, {"error": str(e)})
            return

        set_config(cfg)
        write_json(CONFIG_PATH, cfg, 0o600)

        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE rules SET tz_name = ?, use_dst = ? WHERE target = ?",
            (cfg["default_timezone"], int(cfg["default_use_dst"]), DEFAULT_RULE_TARGET),
        )
        conn.commit()
        conn.close()
        reload_cache()
        upstream_wake.set()
        self.send_json(200, {"ok": True})

    def do_DELETE(self):
        if not self.check_auth():
            return
        if self.path.startswith("/api/rules?id="):
            try:
                rule_id = int(self.path.split("=", 1)[1])
            except ValueError:
                self.send_json(400, {"error": "Некоректний id"})
                return
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "DELETE FROM rules WHERE id = ? AND target != ?",
                (rule_id, DEFAULT_RULE_TARGET),
            )
            conn.commit()
            conn.close()
            reload_cache()
            self.send_json(200, {"ok": True})
        else:
            self.send_response(404)
            self.end_headers()


def main():
    global config
    config = load_config()
    init_credentials()
    init_db()
    reload_cache()

    threading.Thread(target=ntp_server_loop, daemon=True).start()
    threading.Thread(target=upstream_loop, daemon=True).start()

    cfg = get_config()
    print(f"[WEB] Listening on HTTP 0.0.0.0:{cfg['web_port']}")
    httpd = ThreadingHTTPServer(("0.0.0.0", cfg["web_port"]), WebHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
