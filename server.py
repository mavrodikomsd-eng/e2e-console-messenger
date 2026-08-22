import base64
import hashlib
import hmac
import json
import os
import socket
import threading
import traceback
from datetime import datetime
from argon2.low_level import hash_secret_raw, Type as Argon2Type
from modules.crypto import encrypt_message, decrypt_message
from modules.config import config
from modules.protocol import (
    send_frame,
    recv_frame,
    set_tcp_nodelay,
    TYPE_MESSAGE,
    TYPE_COMMAND,
    TYPE_FILE,
    TYPE_REGISTER,
    TYPE_VERSION,
    PROTOCOL_VERSION,
)

clients = []
clients_lock = threading.Lock()
rooms = {}
ACCOUNTS_FILE = "accounts.json"


def load_accounts():
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_accounts():
    fd = os.open(ACCOUNTS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(accounts, f, ensure_ascii=False, indent=2)


def valid_username(name):
    if not name or len(name) > 32:
        return False
    for ch in name:
        if ch in "\x00;:\n\r":
            return False
    return True


ARGON_TIME = 2
ARGON_MEMORY = 64 * 1024
ARGON_THREADS = 1
ARGON_KEY_LEN = 32


def _b64nopad(data):
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64d_pad(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def argon2_hash(password):
    salt = os.urandom(16)
    raw = hash_secret_raw(
        password.encode("utf-8"), salt,
        ARGON_TIME, ARGON_MEMORY, ARGON_THREADS, ARGON_KEY_LEN,
        type=Argon2Type.ID,
    )
    return {
        "alg": "argon2id",
        "salt": _b64nopad(salt),
        "hash": _b64nopad(raw),
        "time": ARGON_TIME,
        "memory": ARGON_MEMORY,
        "threads": ARGON_THREADS,
    }


def argon2_verify(acc, password):
    try:
        salt = _b64d_pad(acc["salt"])
        raw = hash_secret_raw(
            password.encode("utf-8"), salt,
            acc["time"], acc["memory"], acc["threads"], ARGON_KEY_LEN,
            type=Argon2Type.ID,
        )
        return hmac.compare_digest(_b64nopad(raw), acc["hash"])
    except Exception:
        return False


accounts = load_accounts()


class Client:
    def __init__(self, sock, addr, name):
        self.sock = sock
        self.addr = addr
        self.name = name
        self.pub = ""
        self.room = "main"
        self.authed = False
        self.activated = False
        self.login_attempts = 0
        self.proto_version = 1
        self.msg_times = []  # таймстампы сообщений для rate limit


# ── Rate limit (анти-флуд): не более RATE_MAX сообщений за RATE_WINDOW секунд ──
_rate_cfg = config.get("server", {}).get("rate_limit", {})
RATE_MAX = int(_rate_cfg.get("max_messages", 30))
RATE_WINDOW = float(_rate_cfg.get("window_seconds", 5))


def check_rate(client):
    """True — если клиент превысил лимит сообщений."""
    import time as _time
    now = _time.monotonic()
    client.msg_times = [t for t in client.msg_times if now - t < RATE_WINDOW]
    client.msg_times.append(now)
    return len(client.msg_times) > RATE_MAX


def log_message(username, message_preview):
    """Пишет ТОЛЬКО метаданные события (без содержимого сообщений) + ротация."""
    logging_cfg = config.get("logging", {})
    if not logging_cfg.get("enabled", True):
        return
    log_path = logging_cfg.get("file", "messages.log")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {username}: {message_preview}"
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    except Exception:
        pass
    try:
        # Ротация: не даём логу расти бесконечно
        if os.path.exists(log_path) and os.path.getsize(log_path) > logging_cfg.get("max_bytes", 1_000_000):
            os.replace(log_path, log_path + ".1")
    except Exception:
        pass
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")


def find_client(sock):
    with clients_lock:
        for c in clients:
            if c.sock == sock:
                return c
    return None


def broadcast_frame(frame_type, payload, sender_socket=None, target=None):
    with clients_lock:
        for c in clients:
            if c.sock == sender_socket:
                continue
            if target is not None and c.name != target:
                continue
            if target is not None and not c.authed:
                continue
            try:
                send_frame(c.sock, frame_type, payload)
            except Exception:
                pass


def broadcast_to_room(frame_type, payload, sender, room):
    with clients_lock:
        for c in clients:
            if c is not sender and c.room == room:
                try:
                    send_frame(c.sock, frame_type, payload)
                except Exception:
                    pass


def pubkeys_table():
    with clients_lock:
        return ";".join(f"{c.name}:{c.pub}" for c in clients if c.authed and c.pub)


def activate(client):
    if client.activated:
        return
    client.activated = True
    send_frame(client.sock, TYPE_COMMAND, encrypt_message("[ПУБКЛЮЧИ]" + pubkeys_table()))
    broadcast_frame(TYPE_COMMAND, encrypt_message("[НОВЫЙ]" + client.name + ":" + client.pub), client.sock)
    broadcast_to_room(TYPE_COMMAND, encrypt_message(f"\n[СИСТЕМА] {client.name} присоединился к чату"), client, client.room)
    print(f"[АВТОРИЗАЦИЯ] {client.name} вошёл в систему")


def handle_client(client_socket, client_address):
    username = None
    client = None
    try:
        first = recv_frame(client_socket)
        if first is None:
            client_socket.close()
            return

        username = first[1].decode("utf-8").strip()
        if not valid_username(username):
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Недопустимое имя пользователя"))
            client_socket.close()
            return

        with clients_lock:
            if any(c.name == username for c in clients):
                send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Имя уже занято, выбери другое"))
                client_socket.close()
                return
            max_clients = config.get("server", {}).get("max_clients", 0)
            if max_clients and len(clients) >= max_clients:
                send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Достигнут лимит клиентов"))
                client_socket.close()
                return
            client = Client(client_socket, client_address, username)
            clients.append(client)

        print(f"[ПОДКЛЮЧЕНИЕ] {username} подключился с {client_address}")

        if username in accounts:
            hint = "[AUTH]Аккаунт есть — войди: /login ник пароль"
        else:
            hint = "[AUTH]Новый ник — зарегистрируйся: /register ник пароль пароль"
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(hint))

        while True:
            frame = recv_frame(client_socket)
            if frame is None:
                break

            frame_type, payload = frame

            if not client.authed and frame_type in (TYPE_MESSAGE, TYPE_FILE):
                send_frame(client_socket, TYPE_COMMAND, encrypt_message(
                    "[AUTH]Сначала авторизуйтесь: /login ник пароль или /register ник пароль пароль"))
                continue

            # Анти-флуд: превышение лимита — предупреждение и отключение
            if check_rate(client):
                send_frame(client_socket, TYPE_COMMAND, encrypt_message(
                    "[ОШИБКА] Слишком много сообщений. Соединение закрыто (анти-флуд)."))
                print(f"[АНТИ-ФЛУД] {username} отключён (превышен лимит)")
                break

            if frame_type == TYPE_VERSION:
                ver = payload.decode("utf-8", errors="replace").strip()
                if ver != str(PROTOCOL_VERSION):
                    send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Неподдерживаемая версия протокола"))
                    client_socket.close()
                    return
                client.proto_version = PROTOCOL_VERSION
                continue

            if frame_type == TYPE_MESSAGE:
                if payload.count(b"\x00") >= 2:
                    try:
                        _, target_bytes, _ = payload.split(b"\x00", 2)
                        target_name = target_bytes.decode("utf-8", errors="replace").strip()
                    except Exception:
                        target_name = None
                    if target_name:
                        log_message(username, f"(личное для {target_name})")
                        broadcast_frame(TYPE_MESSAGE, payload, client_socket, target=target_name)
                        print(f"[{username}] -> {target_name}: (личное E2E сообщение)")
                        continue
                log_message(username, "(E2E сообщение)")
                broadcast_to_room(TYPE_MESSAGE, payload, client, client.room)
                print(f"[{username}]: (E2E сообщение → комната {client.room})")

            elif frame_type == TYPE_COMMAND:
                decrypted = decrypt_message(payload.decode("utf-8", errors="replace"))
                if decrypted is None:
                    print(f"[!!] {username} отправил невалидную команду")
                    send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Не удалось расшифровать команду. Проверьте, что у клиента и сервера одинаковый secret.key"))
                    continue
                handle_command(decrypted, find_client(client_socket))

            elif frame_type == TYPE_FILE:
                _p = payload.split(b"\x00")
                _target = ""
                if len(_p) >= 2:
                    _target = _p[1].decode("utf-8", errors="replace").strip()
                if _target:
                    broadcast_frame(TYPE_FILE, payload, client_socket, target=_target)
                else:
                    broadcast_to_room(TYPE_FILE, payload, client, client.room)

            elif frame_type == TYPE_REGISTER:
                if client is None or not client.authed:
                    continue
                _p = payload.split(b"\x00")
                if len(_p) >= 2:
                    new_pub = _p[1].decode("utf-8", errors="replace")
                    was_empty = not client.pub
                    client.pub = new_pub
                    if not client.activated:
                        activate(client)
                    elif was_empty:
                        # Ключ пришёл только после авторизации (клиент шлёт R ещё раз).
                        # Раздаём обновлённый ключ соседям, чтобы они могли писать нам.
                        send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ПУБКЛЮЧИ]" + pubkeys_table()))
                        broadcast_frame(TYPE_COMMAND, encrypt_message("[НОВЫЙ]" + client.name + ":" + client.pub), client_socket)

    except Exception:
        print("\n========== TRACEBACK ==========")
        traceback.print_exc()
        print("===============================")

    finally:
        if username:
            room = "main"
            with clients_lock:
                if client in clients:
                    clients.remove(client)
                    room = client.room
            leave_text = f"\n[СИСТЕМА] {username} покинул чат"
            broadcast_to_room(TYPE_COMMAND, encrypt_message(leave_text), client, room)
            print(f"[ОТКЛЮЧЕНИЕ] {username} отключился")
        try:
            client_socket.close()
        except Exception:
            pass


def handle_command(command, client):
    if client is None:
        return
    client_socket = client.sock
    command = command.strip()

    if not client.authed and not (command.startswith("/register") or command.startswith("/login")):
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("[AUTH]Сначала вход: /login ник пароль"))
        return

    if command.startswith("/register"):
        parts = command.split()
        if len(parts) != 4:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Формат: /register ник пароль пароль"))
            return
        _, nick, p1, p2 = parts
        if nick != client.name:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Ник должен совпадать с именем подключения"))
            return
        if nick in accounts:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Ник уже зарегистрирован"))
            return
        if p1 != p2:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Пароли не совпадают"))
            return
        accounts[nick] = argon2_hash(p1)
        save_accounts()
        client.authed = True
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("[AUTH]OK"))
        activate(client)
        return

    elif command.startswith("/login"):
        parts = command.split()
        if len(parts) != 3:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Формат: /login ник пароль"))
            return
        _, nick, pwd = parts
        if nick != client.name:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Ник должен совпадать с именем подключения"))
            return
        acc = accounts.get(nick)
        valid = False
        if acc:
            if acc.get("alg"):
                valid = argon2_verify(acc, pwd)
            else:
                valid = hmac.compare_digest(
                    hashlib.sha256((acc["salt"] + pwd).encode("utf-8")).hexdigest(),
                    acc["hash"],
                )
                if valid:
                    accounts[nick] = argon2_hash(pwd)
                    save_accounts()
        if not valid:
            client.login_attempts += 1
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Неверные учётные данные"))
            if client.login_attempts >= 5:
                client_socket.close()
            return
        client.authed = True
        client.login_attempts = 0
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("[AUTH]OK"))
        activate(client)
        return

    if command == "/users":
        with clients_lock:
            names = [c.name for c in clients if c.room == client.room]
        response = f"\n[ПОЛЬЗОВАТЕЛИ] Комната {client.room} ({len(names)}): {', '.join(names)}"
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(response))

    elif command == "/rooms":
        with clients_lock:
            parts = []
            for rname, pwd in rooms.items():
                mark = "🔒" if pwd else "открыта"
                parts.append(f"{rname}({mark})")
        response = "\n[КОМНАТЫ] " + ", ".join(parts)
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(response))

    elif command.startswith("/createroom "):
        parts = command.split(maxsplit=2)
        rname = parts[1].strip() if len(parts) > 1 else ""
        pwd = parts[2] if len(parts) > 2 else ""
        if not rname:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Формат: /createroom <название> <пароль>"))
            return
        with clients_lock:
            if rname in rooms:
                send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Комната уже существует: " + rname))
                return
            if pwd:
                rsalt = os.urandom(16).hex()
                rooms[rname] = rsalt + ":" + hashlib.sha256((rsalt + pwd).encode("utf-8")).hexdigest()
            else:
                rooms[rname] = ""
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(f"\n[КОМНАТА] Создана комната {rname}"))

    elif command.startswith("/join "):
        parts = command.split(maxsplit=2)
        rname = parts[1].strip() if len(parts) > 1 else ""
        pwd = parts[2] if len(parts) > 2 else ""
        if not rname:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Формат: /join <комната> [пароль]"))
            return
        with clients_lock:
            if rname == "main":
                client.room = rname
            elif rname in rooms:
                expected = rooms[rname]
                ok_pass = not expected
                if expected:
                    if ":" in expected:
                        rsalt, rhash = expected.split(":", 1)
                        ok_pass = hmac.compare_digest(hashlib.sha256((rsalt + pwd).encode("utf-8")).hexdigest(), rhash)
                    else:
                        ok_pass = hmac.compare_digest(hashlib.sha256(pwd.encode("utf-8")).hexdigest(), expected)
                if not ok_pass:
                    send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Неверный пароль для " + rname))
                    return
                client.room = rname
            else:
                send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Комнаты нет: " + rname + ". Создай: /createroom <имя> [пароль]"))
                return
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("\n[КОМНАТА] Вы в комнате: " + rname))
        print(f"[{client.name}] перешёл в комнату {rname}")

    elif command == "/leave":
        client.room = "main"
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("\n[КОМНАТА] Вы вернулись в main"))

    elif command == "/roommembers":
        with clients_lock:
            parts = [f"{c.name}:{c.pub}" for c in clients if c.room == client.room and c.authed and c.pub]
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("[RESP]" + ";".join(parts)))

    elif command.startswith("/pubkey "):
        name = command.split(maxsplit=1)[1].strip()
        pub = ""
        with clients_lock:
            for c in clients:
                if c.name == name and c.authed and c.pub:
                    pub = c.pub
                    break
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("[RESP]" + (pub or "ERR")))

    elif command == "/time":
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("\n[ВРЕМЯ] " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    elif command == "/ping":
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("\n[PING] pong"))

    elif command == "/status":
        with clients_lock:
            total = len(clients)
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(f"\n[СТАТУС] Онлайн: {total}, комната: {client.room}"))

    elif command == "/about":
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("\n[О ПРОЕКТЕ] MeshMessenger v1.5\nЗащищённый мессенджер с E2E-шифрованием (X25519 + AES-256-GCM).\nОсновной сервер: Go."))

    elif command == "/clear":
        send_frame(client_socket, TYPE_COMMAND, encrypt_message("\n" * 50))

    elif command == "/help":
        help_text = "\n[КОМАНДЫ]\n/users /rooms /roommembers\n/join <комната> [пароль] /leave\n/createroom <название> <пароль>\n/file <путь>\n/msg Имя текст - личное\n/time /status /ping /about\n/clear /exit /help"
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(help_text))

    elif command == "/exit":
        client_socket.close()

    else:
        if command:
            send_frame(client_socket, TYPE_COMMAND, encrypt_message("[ОШИБКА] Неизвестная команда: " + command + ". Список команд: /help"))


def start_server(host=None, port=None):
    host = host or os.environ.get("MESH_HOST", config["server"]["host"])
    port = port or int(os.environ.get("MESH_PORT", config["server"]["port"]))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[СЕРВЕР] Запущен на {host}:{port}")
    print("[СЕРВЕР] Режим: E2E шифрование (сервер НЕ видит содержимое сообщений)\n")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            set_tcp_nodelay(client_socket)
            # Медленный/зависший клиент не должен держать поток вечно
            idle_timeout = float(config.get("server", {}).get("idle_timeout", 600))
            client_socket.settimeout(idle_timeout)
            thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[СЕРВЕР] Остановлен")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()


