"""Интеграционные тесты: реальный сервер + клиенты через TCP-сокеты."""
import base64
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server as srv  # noqa: E402
from modules.crypto import decrypt_from_peer, decrypt_message, encrypt_to_peer, encrypt_message  # noqa: E402
from modules.protocol import recv_frame, send_frame, TYPE_COMMAND, TYPE_MESSAGE, TYPE_REGISTER, TYPE_VERSION, PROTOCOL_VERSION  # noqa: E402
from Crypto.Protocol import DH  # noqa: E402


def make_identity():
    seed = base64.b64encode(os.urandom(32)).decode()
    priv = DH.import_x25519_private_key(base64.b64decode(seed))
    pub = base64.b64encode(priv.public_key().export_key(format="raw")).decode()
    return seed, pub


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestClient:
    """Минимальный клиент для интеграционных тестов."""

    def __init__(self, port, name, seed, pub):
        self.name, self.seed, self.pub = name, seed, pub
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.known = {}
        self.responses = []
        self.messages = []  # полученные TYPE_MESSAGE кадры
        send_frame(self.sock, TYPE_MESSAGE, name)
        send_frame(self.sock, TYPE_VERSION, str(PROTOCOL_VERSION))
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            try:
                frame = recv_frame(self.sock)
            except Exception:
                return
            if frame is None:
                return
            ftype, payload = frame
            if ftype == TYPE_MESSAGE:
                self.messages.append(payload)
                continue
            if ftype != TYPE_COMMAND:
                continue
            dec = decrypt_message(payload.decode("utf-8", errors="replace"))
            if not dec:
                continue
            text = dec.strip()
            self.responses.append(text)
            if text.startswith("[RESP]"):
                self.pub_resp = text[6:].strip()
            elif ":" in text and ("ПУБКЛЮЧИ" in text or "НОВЫЙ" in text):
                body = text[text.find("]") + 1:]
                for item in body.split(";"):
                    item = item.strip()
                    if ":" in item:
                        n, p = item.split(":", 1)
                        self.known[n] = p

    def auth(self, password):
        send_frame(self.sock, TYPE_COMMAND,
                   encrypt_message(f"/register {self.name} {password} {password}"))
        time.sleep(0.5)
        # Повторная регистрация ключа после входа (как в реальном клиенте)
        send_frame(self.sock, TYPE_REGISTER,
                   self.name.encode() + b"\x00" + self.pub.encode())

    def wait_for(self, predicate, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.tmp = tempfile.mkdtemp()
        srv.ACCOUNTS_FILE = os.path.join(cls.tmp, "accounts.json")
        srv.accounts = {}
        threading.Thread(target=srv.start_server, args=("127.0.0.1", cls.port), daemon=True).start()
        time.sleep(0.5)

    def test_invalid_username_rejected(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        send_frame(sock, TYPE_MESSAGE, "")  # пустое имя недопустимо
        frame = recv_frame(sock)
        self.assertIsNotNone(frame)
        self.assertIn("Недопустимое имя", decrypt_message(frame[1].decode()))
        sock.close()

    def test_unauthed_message_gets_auth_hint(self):
        seed, pub = make_identity()
        c = TestClient(self.port, "intruder_it", seed, pub)
        time.sleep(0.3)
        send_frame(c.sock, TYPE_MESSAGE, "intruder_it\x00victim\x00ZmFrZQ==")
        self.assertTrue(c.wait_for(lambda: any("[AUTH]" in r for r in c.responses)))

    def test_two_users_e2e_exchange(self):
        a_seed, a_pub = make_identity()
        b_seed, b_pub = make_identity()
        alice = TestClient(self.port, "alice_it", a_seed, a_pub)
        bob = TestClient(self.port, "bob_it", b_seed, b_pub)
        alice.auth("pw123")
        bob.auth("pw123")
        time.sleep(0.5)

        # Bob получает ключ Alice (через broadcast [НОВЫЙ] или /pubkey)
        if "alice_it" not in bob.known:
            send_frame(bob.sock, TYPE_COMMAND, encrypt_message("/pubkey alice_it"))
        self.assertTrue(bob.wait_for(lambda: "alice_it" in bob.known))
        self.assertEqual(bob.known["alice_it"], a_pub)

        # Bob -> Alice персональное E2E-сообщение
        secret_text = "секретное сообщение от Боба"
        ct = encrypt_to_peer(secret_text, a_pub, b_pub, b_seed)
        send_frame(bob.sock, TYPE_MESSAGE, f"bob_it\x00alice_it\x00{ct}".encode())

        found = None
        time.sleep(0.5)  # пауза на доставку
        deadline = time.time() + 3
        while time.time() < deadline and found is None:
            for payload in list(alice.messages):
                parts = payload.split(b"\x00")
                if len(parts) >= 3 and parts[0].decode() == "bob_it":
                    found = decrypt_from_peer(parts[2].decode(), b_pub, a_seed)
            time.sleep(0.05)
        self.assertIsNotNone(found, "сообщение не доставлено")
        self.assertEqual(found, secret_text)

    def test_rate_limit_kicks_in(self):
        old_max = srv.RATE_MAX
        srv.RATE_MAX = 3
        try:
            seed, pub = make_identity()
            c = TestClient(self.port, "flooder_it", seed, pub)
            c.auth("pw123")
            time.sleep(0.3)
            for _ in range(10):
                try:
                    send_frame(c.sock, TYPE_MESSAGE, "flooder_it\x00t\x00eGg=")
                except Exception:
                    break
                time.sleep(0.02)
            closed = False
            deadline = time.time() + 3
            while time.time() < deadline:
                try:
                    if recv_frame(c.sock) is None:
                        closed = True
                        break
                except Exception:
                    closed = True
                    break
                time.sleep(0.05)
            self.assertTrue(closed, "анти-флуд не отключил клиента")
        finally:
            srv.RATE_MAX = old_max


if __name__ == "__main__":
    unittest.main()
