"""Тесты AES-256-GCM и идентичности X25519."""
import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.crypto import (  # noqa: E402
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    _gcm_decrypt,
    _gcm_encrypt,
    decrypt_message,
    encrypt_message,
    load_or_create_identity,
)


class GcmTests(unittest.TestCase):
    KEY = b"A" * KEY_SIZE

    def test_roundtrip_str(self):
        ct = _gcm_encrypt(self.KEY, "привет, мир 🌍")
        self.assertEqual(_gcm_decrypt(self.KEY, ct), "привет, мир 🌍")

    def test_roundtrip_bytes_and_aad(self):
        ct = _gcm_encrypt(self.KEY, b"payload", aad=b"meta")
        self.assertEqual(_gcm_decrypt(self.KEY, ct, aad=b"meta"), "payload")

    def test_wrong_key_fails(self):
        ct = _gcm_encrypt(self.KEY, "secret")
        self.assertIsNone(_gcm_decrypt(b"C" * KEY_SIZE, ct))

    def test_aad_mismatch_fails(self):
        ct = _gcm_encrypt(self.KEY, "secret", aad="pub1")
        self.assertIsNone(_gcm_decrypt(self.KEY, ct, aad="pub2"))

    def test_tampered_ciphertext_fails(self):
        raw = bytearray(base64.b64decode(_gcm_encrypt(self.KEY, "secret")))
        raw[NONCE_SIZE] ^= 0xFF  # портим первый байт шифротекста
        ct = base64.b64encode(bytes(raw)).decode()
        self.assertIsNone(_gcm_decrypt(self.KEY, ct))

    def test_unique_nonces(self):
        a = _gcm_encrypt(self.KEY, "x")
        b = _gcm_encrypt(self.KEY, "x")
        self.assertNotEqual(a[:NONCE_SIZE], b[:NONCE_SIZE])

    def test_format_nonce_ct_tag(self):
        raw = base64.b64decode(_gcm_encrypt(self.KEY, "12345"))
        self.assertGreater(len(raw), NONCE_SIZE + TAG_SIZE)

    def test_encrypt_message_uses_global_key(self):
        self.assertEqual(decrypt_message(encrypt_message("hello")), "hello")


class IdentityTests(unittest.TestCase):
    def test_identity_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.environ.get("MESH_IDENTITY_FILE")
            os.environ["MESH_IDENTITY_FILE"] = os.path.join(tmp, "id.key")
            try:
                seed1, pub1 = load_or_create_identity()
                seed2, pub2 = load_or_create_identity()
                self.assertEqual(seed1, seed2)
                self.assertEqual(pub1, pub2)
            finally:
                if old is None:
                    os.environ.pop("MESH_IDENTITY_FILE", None)
                else:
                    os.environ["MESH_IDENTITY_FILE"] = old


if __name__ == "__main__":
    unittest.main()
