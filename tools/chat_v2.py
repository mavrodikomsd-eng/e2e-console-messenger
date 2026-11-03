"""Консольный клиент протокола v2 — живой собеседник для проверки GUI.

Запуск (из корня проекта):
  python tools/chat_v2.py @tester пароль [@bre]

Подключается к server_v2, логинится, публикует X25519-ключ и работает
как полноценный peer: умеет принимать/отправлять личные E2E-сообщения
(те же, что шлёт GUI), показывает системные события. Пригоден для
проверки звука, счётчика непрочитанных и тостов в одиночку.
"""
import base64
import socket
import sys
import threading
import time

sys.path.insert(0, __file__.rsplit("tools", 1)[0])

from modules.crypto import (
    decrypt_from_peer,
    decrypt_message,
    encrypt_message,
    encrypt_to_peer,
    fingerprint,
    load_or_create_identity,
)
from modules.protocol import (
    TYPE_COMMAND,
    TYPE_MESSAGE,
    TYPE_VERSION,
    recv_frame,
    send_frame,
)

MY = sys.argv[1] if len(sys.argv) > 1 else "@tester"
PASS = sys.argv[2] if len(sys.argv) > 2 else "testpass123"
PEER = sys.argv[3] if len(sys.argv) > 3 else ""

if not MY.startswith("@"):
    MY = "@" + MY

seed_b64, pub_b64 = load_or_create_identity()
peers = {}          # @name -> pub_b64
s = socket.create_connection(("127.0.0.1", 1301), timeout=5)
s.settimeout(None)


def send_cmd(cmd: str) -> None:
    send_frame(s, TYPE_COMMAND, encrypt_message(cmd).encode("utf-8"))


def send_peer(target: str, text: str) -> None:
    pk = peers.get(target)
    if not pk:
        print(f"[!] нет ключа {target}, запрашиваю…")
        send_cmd(f"/pubkey {target}")
        time.sleep(0.6)
        pk = peers.get(target)
        if not pk:
            print(f"[!] {target} не в сети или ключ не получен")
            return
    ct = encrypt_to_peer(text, pk, pub_b64, seed_b64)
    send_frame(s, TYPE_MESSAGE, f"{MY}\x00{target}\x00".encode("utf-8") + ct.encode("utf-8"))
    print(f"[Я] -> {target}: {text}")


def reader() -> None:
    while True:
        try:
            f = recv_frame(s)
        except OSError:
            print("[ОТКЛЮЧЕНО]")
            return
        if f is None:
            print("[ОТКЛЮЧЕНО]")
            return
        ftype, payload = f
        if ftype == TYPE_COMMAND:
            try:
                text = decrypt_message(payload.decode("utf-8", "replace"))
            except Exception:
                continue
            if text.startswith("[ПУБКЛЮЧИ]") or text.startswith("[RESP]"):
                body = text.split("]", 1)[1].strip()
                for part in body.replace("\n", ";").split(";"):
                    if ":" not in part:
                        continue
                    name, _, pk = part.strip().partition(":")
                    if name.startswith("@") and len(pk) > 20:
                        peers[name] = pk
                continue
            if text.startswith("[НОВЫЙ]"):
                name, _, pk = text[7:].strip().partition(":")
                if name.startswith("@") and len(pk) > 20:
                    peers[name] = pk
            print(f"[С] {text}")
        elif ftype == TYPE_MESSAGE:
            parts = payload.split(b"\x00")
            sender = parts[0].decode("utf-8", "replace")
            pk = peers.get(sender, "")
            if not pk:
                send_cmd(f"/pubkey {sender}")
                time.sleep(0.4)
                pk = peers.get(sender, "")
            if len(parts) >= 3:
                ct = parts[2].decode("utf-8", "replace")
            else:
                ct = parts[-1].decode("utf-8", "replace")
            plain = decrypt_from_peer(ct, pk, seed_b64) if pk else None
            if plain:
                fp = fingerprint(pk) if pk else "?"
                print(f"\n[{sender} ({fp[:9]}…)]: {plain.decode('utf-8', 'replace')}")
            else:
                print(f"\n[{sender}]: (не удалось расшифровать — нет ключа)")


send_frame(s, TYPE_MESSAGE, MY.encode("utf-8"))
send_frame(s, TYPE_VERSION, b"2")
send_frame(s, 0x52, MY.encode("utf-8") + b"\x00" + pub_b64.encode("utf-8"))  # TYPE_REGISTER

threading.Thread(target=reader, daemon=True).start()
time.sleep(0.7)
send_cmd(f"/login {MY} {PASS}")
time.sleep(1.0)

print(f"=== {MY} в сети. Пиши строки — уйдут как личные E2E для {PEER or 'указанного пира'}. ===")
print("=== Команды: /exit — выход, /pub @ник — запросить ключ ===")
while True:
    try:
        line = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        break
    if not line:
        continue
    if line == "/exit":
        break
    if line.startswith("/pub "):
        send_cmd(f"/pubkey {line[5:].strip()}")
        continue
    if PEER:
        send_peer(PEER, line)
    else:
        send_cmd("/users")
        print("[i] пир не указан: задай третьим аргументом, кому отправлять")

send_cmd("/exit")
time.sleep(0.3)
