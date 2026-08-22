"""
MeshMessenger Dashboard — веб-мониторинг сервера.

Подключается к чат-серверу как обычный клиент (с тем же secret.key),
авторизуется под сервисным аккаунтом и раздаёт страницу со статистикой:
онлайн, список пользователей и комнат.

ВАЖНО: дашборд НЕ видит содержимое сообщений — они сквозь зашифрованы
между клиентами (E2E), и это принципиально. Только метаданные.

Запуск:  python web/server_web.py   →  http://127.0.0.1:8080
Аккаунт: переменные MESH_WEB_USER / MESH_WEB_PASS (по умолчанию
webmon/webmon — при первом запуске регистрируется сам).
"""
import json
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from modules.crypto import encrypt_message, decrypt_message  # noqa: E402
from modules.config import config  # noqa: E402
from modules.protocol import (  # noqa: E402
    recv_frame,
    send_frame,
    set_tcp_nodelay,
    TYPE_MESSAGE,
    TYPE_COMMAND,
    TYPE_VERSION,
    PROTOCOL_VERSION,
)

WEB_USER = os.environ.get("MESH_WEB_USER", "webmon")
WEB_PASS = os.environ.get("MESH_WEB_PASS", "webmon")
HTTP_HOST = os.environ.get("MESH_WEB_HOST", "127.0.0.1")
HTTP_PORT = int(os.environ.get("MESH_WEB_PORT", "8080"))

stats_lock = threading.Lock()
stats = {"online": 0, "room": "-", "users": [], "rooms": [], "connected": False}


def _resp(cmd, pending, sock):
    ev = threading.Event()
    pending["ev"] = ev
    pending["result"] = None
    send_frame(sock, TYPE_COMMAND, encrypt_message(cmd))
    ev.wait(timeout=3)
    return pending["result"] or ""


def poll_server():
    """Подключение к чат-серверу и опрос метаданных раз в 5 секунд."""
    host = config["server"]["host"]
    port = int(config["server"]["port"])
    while True:
        pending = {}
        try:
            sock = socket.create_connection((host, port), timeout=5)
            set_tcp_nodelay(sock)
            send_frame(sock, TYPE_MESSAGE, WEB_USER)
            send_frame(sock, TYPE_VERSION, str(PROTOCOL_VERSION))

            def reader():
                while True:
                    frame = recv_frame(sock)
                    if frame is None:
                        break
                    ftype, payload = frame
                    if ftype != TYPE_COMMAND:
                        continue
                    dec = decrypt_message(payload.decode("utf-8", errors="replace"))
                    if not dec:
                        continue
                    text = dec.strip()
                    if text.startswith("[RESP]"):
                        pending["result"] = text[len("[RESP]"):].strip()
                        if pending.get("ev"):
                            pending["ev"].set()
            threading.Thread(target=reader, daemon=True).start()

            # Авторизация (при первом запуске — регистрация сервисного аккаунта)
            resp = _resp(f"/login {WEB_USER} {WEB_PASS}", pending, sock)
            if "[AUTH]" in resp or resp == "":
                _resp(f"/register {WEB_USER} {WEB_PASS} {WEB_PASS}", pending, sock)
            time.sleep(1)

            while True:
                status = _resp("/status", pending, sock) or ""
                users = _resp("/users", pending, sock) or ""
                rooms = _resp("/rooms", pending, sock) or ""
                m = re.search(r"Онлайн:\s*(\d+).*?комната:\s*(\S+)", status)
                u = re.search(r"\((\d+)\):\s*(.*)$", users)
                with stats_lock:
                    stats["connected"] = True
                    stats["online"] = int(m.group(1)) if m else 0
                    stats["room"] = m.group(2) if m else "-"
                    stats["users"] = [x.strip() for x in u.group(2).split(",") if x.strip()] if u else []
                    stats["rooms"] = [r.strip() for r in rooms.replace("[КОМНАТЫ]", "").split(",") if r.strip()]
                time.sleep(5)
        except Exception:
            with stats_lock:
                stats.update(connected=False, online=0, users=[])
            time.sleep(5)


PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>MeshMessenger — Dashboard</title><meta http-equiv="refresh" content="5">
<style>body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:2rem}
h1{color:#38bdf8}.card{background:#1e293b;border-radius:12px;padding:1rem 1.5rem;margin:1rem 0}
.ok{color:#4ade80}.bad{color:#f87171}code{color:#94a3b8}ul{columns:2}</style></head><body>
<h1>🛡️ MeshMessenger — Dashboard</h1>
<div class="card">Состояние: <b class="{cls}">{state}</b></div>
<div class="card"><h2>Онлайн</h2><p style="font-size:2rem;margin:.2rem">{online}</p>
<p>комната дашборда: <code>{room}</code></p></div>
<div class="card"><h2>Пользователи в комнате main</h2>{userlist}</div>
<div class="card"><h2>Комнаты</h2>{roomlist}</div>
<p style="color:#64748b">Обновление каждые 5 с. Дашборд видит только метаданные —
содержимое сообщений зашифровано (E2E).</p></body></html>"""


if __name__ == "__main__":
    threading.Thread(target=poll_server, daemon=True).start()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with stats_lock:
                snap = dict(stats)
            if self.path == "/api/stats":
                body, ctype = json.dumps(snap).encode(), "application/json"
            else:
                cls = "ok" if snap["connected"] else "bad"
                state = "подключён к серверу" if snap["connected"] else "НЕТ СВЯЗИ С СЕРВЕРОМ"
                ulist = "<ul>" + "".join(f"<li>{u}</li>" for u in snap["users"]) + "</ul>" if snap["users"] else "<p>—</p>"
                rlist = "<ul>" + "".join(f"<li>{r}</li>" for r in snap["rooms"]) + "</ul>" if snap["rooms"] else "<p>—</p>"
                body = PAGE.format(cls=cls, state=state, online=snap["online"],
                                   room=snap["room"], userlist=ulist, roomlist=rlist).encode("utf-8")
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    print(f"[WEB] Дашборд: http://{HTTP_HOST}:{HTTP_PORT}")
    ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), Handler).serve_forever()