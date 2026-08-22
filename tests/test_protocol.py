"""Тесты протокола (фрейминг) и серверных утилит."""
import os
import sys
import socket
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.protocol import (  # noqa: E402
    HEADER_SIZE,
    MAX_MESSAGE_SIZE,
    TYPE_COMMAND,
    TYPE_MESSAGE,
    recv_frame,
    send_frame,
)
from server import argon2_hash, argon2_verify, valid_username  # noqa: E402


def _socketpair():
    a, b = socket.socketpair()
    return a, b


class FramingTests(unittest.TestCase):
    def test_roundtrip(self):
        a, b = _socketpair()
        try:
            send_frame(a, TYPE_MESSAGE, "привет")
            ftype, payload = recv_frame(b)
            self.assertEqual(ftype, TYPE_MESSAGE)
            self.assertEqual(payload.decode("utf-8"), "привет")
        finally:
            a.close()
            b.close()

    def test_large_payload_chunked(self):
        """Крупный payload должен корректно собираться из нескольких recv."""
        a, b = _socketpair()
        try:
            data = os.urandom(200_000)
            send_frame(a, TYPE_COMMAND, data)
            ftype, payload = recv_frame(b)
            self.assertEqual(ftype, TYPE_COMMAND)
            self.assertEqual(payload, data)
        finally:
            a.close()
            b.close()

    def test_oversize_rejected_on_send(self):
        a, b = _socketpair()
        try:
            with self.assertRaises(ValueError):
                send_frame(a, TYPE_MESSAGE, b"x" * (MAX_MESSAGE_SIZE + 1))
        finally:
            a.close()
            b.close()

    def test_closed_connection_returns_none(self):
        a, b = _socketpair()
        b.close()
        try:
            self.assertIsNone(recv_frame(a))
        finally:
            a.close()


class UsernameValidationTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(valid_username("alice"))
        self.assertTrue(valid_username("Пётр_1"))

    def test_invalid(self):
        self.assertFalse(valid_username(""))
        self.assertFalse(valid_username(None))
        self.assertFalse(valid_username("a" * 33))
        self.assertFalse(valid_username("a;b"))
        self.assertFalse(valid_username("a:b"))
        self.assertFalse(valid_username("a\x00b"))
        self.assertFalse(valid_username("a\nb"))


class Argon2Tests(unittest.TestCase):
    def test_verify_correct_and_wrong(self):
        acc = argon2_hash("пароль123")
        self.assertEqual(acc["alg"], "argon2id")
        self.assertTrue(argon2_verify(acc, "пароль123"))
        self.assertFalse(argon2_verify(acc, "другой"))

    def test_salts_unique(self):
        h1 = argon2_hash("same")
        h2 = argon2_hash("same")
        self.assertNotEqual(h1["salt"], h2["salt"])
        self.assertNotEqual(h1["hash"], h2["hash"])

    def test_verify_broken_record(self):
        self.assertFalse(argon2_verify({"salt": "!!!"}, "x"))


if __name__ == "__main__":
    unittest.main()
