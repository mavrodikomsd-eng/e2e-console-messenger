"""Пингер GUI для проверки звука и счётчика непрочитанных.

Запуск:  python tools/ping_gui.py "@bre" "текст сообщения"
Первый аргумент — твой ник в GUI (для личного) или "" для публичного
в общую комнату. Клиент представляется как @ping.

Пример:
  python tools/ping_gui.py "" "Проверка звука!"
"""
import socket
import sys
import time

sys.path.insert(0, __file__.rsplit("tools", 1)[0])

from modules.protocol import (
    TYPE_MESSAGE,
    TYPE_VERSION,
    recv_frame,
    send_frame,
)
from modules.crypto import encrypt_message

TARGET = sys.argv[1] if len(sys.argv) > 1 else ""
TEXT = sys.argv[2] if len(sys.argv) > 2 else "Проверка звука и счётчика 🔔"
ME = "@ping"

s = socket.create_connection(("127.0.0.1", 1301), timeout=5)
send_frame(s, TYPE_MESSAGE, ME.encode())
send_frame(s, TYPE_VERSION, b"2")

# даем серверу ответить (hint), регистрируемся, затем шлём
time.sleep(0.6)
try:
    recv_frame(s)
except Exception:
    pass
send_frame(s, TYPE_MESSAGE, f"{ME}\x00{encrypt_message('/register pingpass123 pingpass123')}".encode())
time.sleep(0.8)
try:
    recv_frame(s)
except Exception:
    pass

if TARGET:
    payload = f"{ME}\x00{TARGET}\x00".encode() + encrypt_message(TEXT).encode()
else:
    payload = f"{ME}\x00".encode() + encrypt_message(TEXT).encode()
send_frame(s, TYPE_MESSAGE, payload)
print("[PING] отправлено:", TEXT)
time.sleep(1)
