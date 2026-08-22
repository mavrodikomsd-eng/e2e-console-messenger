import base64
import os
import socket
import sys
import threading
import time
from modules.crypto import (
    encrypt_message,
    decrypt_message,
    load_or_create_identity,
    encrypt_to_peer,
    decrypt_from_peer,
)
from modules.config import config
from modules.ui import show_banner
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

print_lock = threading.Lock()
RESP_PREFIX = "[RESP]"


def safe_print(text):
    with print_lock:
        print("\r" + str(text))
        print(">>> ", end="", flush=True)


class Client:
    def __init__(self, sock, username):
        self.sock = sock
        self.username = username
        self.connected = True
        self.seed_b64, self.pub_b64 = load_or_create_identity()
        self.authed = False
        self.known_keys = {}
        self.pending_event = None
        self.pending_result = None
        self.recv = threading.Thread(target=self._reader, daemon=True)

    def request(self, cmd):
        ev = threading.Event()
        self.pending_event = ev
        self.pending_result = None
        send_frame(self.sock, TYPE_COMMAND, encrypt_message(cmd))
        ev.wait(timeout=3)
        self.pending_event = None
        return self.pending_result

    def _insert_keys(self, text):
        cut = text.find("]")
        if cut != -1:
            text = text[cut + 1:]
        for item in text.split(";"):
            item = item.strip()
            if ":" in item:
                n, p = item.split(":", 1)
                self.known_keys[n] = p

    def _resend_register(self):
        """Повторная регистрация публичного ключа после авторизации.
        Сервер принимает кадр R только у аутентифицированных клиентов, поэтому
        после /register или /login нужно прислать ключ ещё раз, иначе сервер
        не узнает публичный ключ и не сможет маршрутизировать сообщения."""
        try:
            send_frame(self.sock, TYPE_REGISTER,
                       self.username.encode("utf-8") + b"\x00" + self.pub_b64.encode("utf-8"))
        except Exception:
            pass

    def _wait_auth(self, timeout=2.0):
        """Ожидает, пока сервер не подтвердит вход ([AUTH]OK). Используется после
        ввода /login или /register, чтобы следующее сообщение случайно не ушло
        «вхолостую» до того, как клиент узнал об успешной авторизации."""
        t0 = time.time()
        while not self.authed and self.connected and time.time() - t0 < timeout:
            time.sleep(0.05)

    def _reader(self):
        while self.connected:
            try:
                frame = recv_frame(self.sock)
            except Exception:
                break
            if frame is None:
                break
            frame_type, payload = frame
            if frame_type == TYPE_COMMAND:
                dec = decrypt_message(payload.decode("utf-8", errors="replace"))
                if not dec:
                    continue
                text = dec.strip()
                if text.startswith(RESP_PREFIX):
                    self.pending_result = text[len(RESP_PREFIX):].strip()
                    if self.pending_event:
                        self.pending_event.set()
                    continue
                if text.startswith("[ПУБКЛЮЧИ]") or text.startswith("[НОВЫЙ]"):
                    self._insert_keys(text)
                    continue
                if text.startswith("[AUTH]OK"):
                    # Вход выполнен — повторно регистрируем публичный ключ,
                    # т.к. до авторизации сервер его игнорирует.
                    self.authed = True
                    self._resend_register()
                    safe_print("✅ Авторизация успешна. Можно общаться!")
                    continue
                if text.startswith("[AUTH]") and "[AUTH]OK" not in text:
                    # Ответ сервера о том, что вход ещё не выполнен/нужен.
                    self.authed = False
                safe_print(text)
            elif frame_type == TYPE_MESSAGE:
                self._handle_message(payload)
            elif frame_type == TYPE_FILE:
                self._handle_file(payload)
        self.connected = False

    def _handle_message(self, payload):
        parts = payload.split(b"\x00")
        if len(parts) < 3:
            safe_print("[ОШИБКА] Повреждённый кадр сообщения")
            return
        sender = parts[0].decode("utf-8", errors="replace")
        ct = parts[2].decode("utf-8", errors="replace")
        pub = self.known_keys.get(sender)
        if not pub:
            safe_print(f"[{sender}]: (неизвестный публичный ключ)")
            return
        plain = decrypt_from_peer(ct, pub, self.seed_b64)
        if plain:
            safe_print(f"[{sender}]: {plain.rstrip()}")
        else:
            safe_print(f"[{sender}]: (не удалось расшифровать — подмена/ключ)")

    def _handle_file(self, payload):
        parts = payload.split(b"\x00")
        if len(parts) < 4:
            safe_print("[ОШИБКА] Повреждённый кадр файла")
            return
        sender = parts[0].decode("utf-8", errors="replace")
        fname = parts[2].decode("utf-8", errors="replace")
        data = parts[3].decode("utf-8", errors="replace")
        pub = self.known_keys.get(sender)
        if not pub:
            safe_print(f"[{sender}] отправил файл: {fname}, но ключ неизвестен")
            return
        plain = decrypt_from_peer(data, pub, self.seed_b64)
        if plain is None:
            safe_print(f"[{sender}] отправил файл: {fname}, но расшифровать не удалось")
            return
        raw = base64.b64decode(plain)
        base = self._safe_save_file(fname, raw)
        if base is None:
            safe_print(f"[{sender}] отправил файл: {fname}, но сохранить не удалось")
            return
        safe_print(f"[{sender}] отправил файл: {base} ({len(raw)} байт) — сохранён")

    @staticmethod
    def _safe_save_file(fname, raw):
        base = os.path.basename(fname).strip()
        if base in ("", ".", "..") or "/" in base or "\\" in base:
            return None
        downloads = os.path.abspath(os.path.join(os.getcwd(), "downloads"))
        os.makedirs(downloads, exist_ok=True)
        final = os.path.abspath(os.path.join(downloads, base))
        if not final.startswith(downloads + os.sep):
            return None
        try:
            fd = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        except OSError:
            return None
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
        except Exception:
            return None
        return base

    def _recipient_pub(self, name):
        pub = self.known_keys.get(name)
        if not pub:
            resp = self.request("/pubkey " + name)
            if resp and resp != "ERR":
                pub = resp
                self.known_keys[name] = pub
        return pub

    def send_to(self, target, text):
        if not self.authed:
            safe_print("[ВНИМАНИЕ] Сначала авторизуйтесь: /login ник пароль или /register ник пароль пароль")
            return False
        pub = self._recipient_pub(target)
        if not pub or pub == "ERR":
            safe_print(f"[ОШИБКА] Не знаю публичный ключ для {target}")
            return False
        ct = encrypt_to_peer(text, pub, self.pub_b64, self.seed_b64)
        payload = self.username.encode("utf-8") + b"\x00" + target.encode("utf-8") + b"\x00" + ct.encode("utf-8")
        send_frame(self.sock, TYPE_MESSAGE, payload)
        return True

    def _room_targets(self):
        resp = self.request("/roommembers")
        targets = []
        if resp and resp != "ERR":
            for item in resp.split(";"):
                item = item.strip()
                if ":" in item:
                    n, p = item.split(":", 1)
                    self.known_keys[n] = p
                    if n != self.username:
                        targets.append((n, p))
        return targets

    def send_to_room(self, text):
        if not self.authed:
            safe_print("[ВНИМАНИЕ] Сначала авторизуйтесь: /login ник пароль или /register ник пароль пароль")
            return
        targets = self._room_targets()
        for name, pub in targets:
            ct = encrypt_to_peer(text, pub, self.pub_b64, self.seed_b64)
            payload = self.username.encode("utf-8") + b"\x00" + name.encode("utf-8") + b"\x00" + ct.encode("utf-8")
            send_frame(self.sock, TYPE_MESSAGE, payload)
        safe_print(f"[Я]: {text}")

    def send_file_to_room(self, path):
        if not self.authed:
            safe_print("[ВНИМАНИЕ] Сначала авторизуйтесь: /login ник пароль или /register ник пароль пароль")
            return
        if not os.path.exists(path):
            safe_print("[ОШИБКА] Файл не найден:", path)
            return
        fname = os.path.basename(path)
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) > 400000:
            safe_print("[ОШИБКА] Файл слишком большой (до 400 КБ)")
            return
        b64str = base64.b64encode(raw).decode("utf-8")
        targets = self._room_targets()
        for name, pub in targets:
            data_b64 = encrypt_to_peer(b64str, pub, self.pub_b64, self.seed_b64)
            payload = self.username.encode("utf-8") + b"\x00" + name.encode("utf-8") + b"\x00" + fname.encode("utf-8") + b"\x00" + data_b64.encode("utf-8")
            send_frame(self.sock, TYPE_FILE, payload)
        safe_print(f"[Я] файл: {fname} отправлен в комнату")

    def send_messages(self):
        while self.connected:
            try:
                message = input(">>> ").strip()
            except (EOFError, KeyboardInterrupt):
                safe_print("[ВЫХОД] До свидания!")
                self.connected = False
                break
            if not message:
                continue
            try:
                if message.startswith("/msg "):
                    parts = message.split(maxsplit=2)
                    if len(parts) < 3:
                        safe_print("[ОШИБКА] Формат: /msg Имя текст")
                        continue
                    target, text = parts[1], parts[2]
                    if self.send_to(target, text):
                        safe_print(f"[Я] -> {target}: {text}")
                elif message.startswith("/file "):
                    self.send_file_to_room(message.split(maxsplit=1)[1].strip())
                elif message.startswith("/"):
                    send_frame(self.sock, TYPE_COMMAND, encrypt_message(message))
                    if message.startswith("/login ") or message.startswith("/register "):
                        self._wait_auth()
                else:
                    self.send_to_room(message)
            except (ConnectionResetError, BrokenPipeError, OSError):
                self.connected = False
                break


def start_client():
    show_banner()
    host = config["server"]["host"]
    port = config["server"]["port"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        set_tcp_nodelay(sock)
        print(f"[ПОДКЛЮЧЕНИЕ] Подключено к {host}:{port}")
        username = input("Введи своё имя: ").strip()
        if not username:
            username = "Аноним"
        send_frame(sock, TYPE_MESSAGE, username)
        send_frame(sock, TYPE_VERSION, str(PROTOCOL_VERSION))
        c = Client(sock, username)
        send_frame(sock, TYPE_REGISTER, c.username.encode("utf-8") + b"\x00" + c.pub_b64.encode("utf-8"))
        print(f"\nДобро пожаловать, {username}!")
        print("Команды: /join <комната>, /msg Имя текст, /file <путь>, /users, /rooms, /roommembers, /help, /exit\n")
        print("🔐 Перед общением нужно авторизоваться:")
        print("   🔑 Уже есть аккаунт:  /login ник пароль")
        print("   📝 Впервые:           /register ник пароль пароль")
        c.recv.start()
        c.send_messages()
    except ConnectionRefusedError:
        print(f"[ОШИБКА] Не удалось подключиться к {host}:{port}")
    except Exception as e:
        print(f"[ОШИБКА] {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    start_client()

