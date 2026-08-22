"""Тесты E2E-криптографии между пирами (X25519 ECDH) и TOFU-хранилища."""
import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Protocol import DH  # noqa: E402

from modules.crypto import KEY_SIZE, decrypt_from_peer, encrypt_to_peer  # noqa: E402
from modules.tofu import TofuStore, fingerprint  # noqa: E402


def make_identity():
    """Возвращает (seed_b64, pub_b64)."""
    seed = base64.b64encode(os.urandom(KEY_SIZE)).decode()
    priv = DH.import_x25519_private_key(base64.b64decode(seed))
    pub = base64.b64encode(priv.public_key().export_key(format="raw")).decode()
    return seed, pub


class PeerCryptoTests(unittest.TestCase):
    def test_ecdh_roundtrip(self):
        a_seed, a_pub = make_identity()
        b_seed, b_pub = make_identity()

        ct = encrypt_to_peer("секретное сообщение", b_pub, a_pub, a_seed)
        self.assertEqual(decrypt_from_peer(ct, a_pub, b_seed), "секретное сообщение")

        ct2 = encrypt_to_peer("ответ", a_pub, b_pub, b_seed)
        self.assertEqual(decrypt_from_peer(ct2, b_pub, a_seed), "ответ")

    def test_wrong_sender_key_rejected(self):
        a_seed, a_pub = make_identity()
        _, b_pub = make_identity()
        e_seed, _ = make_identity()  # Ева

        ct = encrypt_to_peer("msg", b_pub, a_pub, a_seed)
        # Ева пытается расшифровать чужое сообщение своим ключом — должна провалиться
        self.assertIsNone(decrypt_from_peer(ct, a_pub, e_seed))

    def test_spoofed_sender_aad_rejected(self):
        """AAD привязывает шифротекст к публичному ключу отправителя."""
        a_seed, a_pub = make_identity()
        b_seed, b_pub = make_identity()

        ct = encrypt_to_peer("msg", b_pub, a_pub, a_seed)
        # Подмена «отправителя»: получатель проверяет AAD = ключ Евы, а не Алисы
        e_seed, e_pub = make_identity()
        self.assertIsNone(decrypt_from_peer(ct, e_pub, b_seed))
        # А настоящий ключ отправителя по-прежнему работает
        self.assertEqual(decrypt_from_peer(ct, a_pub, b_seed), "msg")


class TofuTests(unittest.TestCase):
    PUB_A = base64.b64encode(b"public-key-alice-0000000000").decode()
    PUB_B = base64.b64encode(b"public-key-bob--00000000000").decode()

    def _store(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        return TofuStore(path)

    def test_new_then_ok(self):
        store = self._store()
        self.assertEqual(store.check("alice", self.PUB_A), "new")
        self.assertEqual(store.check("alice", self.PUB_A), "ok")

    def test_changed_detected(self):
        store = self._store()
        store.check("alice", self.PUB_A)
        self.assertEqual(store.check("alice", self.PUB_B), "changed")

    def test_persistence(self):
        s1 = self._store()
        s1.check("bob", self.PUB_B)
        s2 = TofuStore(s1.path)
        self.assertEqual(s2.known.get("bob"), fingerprint(self.PUB_B))

    def test_trust_overrides(self):
        store = self._store()
        store.check("alice", self.PUB_A)
        store.trust("alice", self.PUB_B)
        self.assertEqual(store.check("alice", self.PUB_B), "ok")

    def test_fingerprint_format(self):
        fp = fingerprint(self.PUB_A)
        self.assertEqual(len(fp.replace(":", "")), 64)  # SHA-256 hexdigest
        self.assertTrue(all(len(g) == 4 for g in fp.split(":")))


if __name__ == "__main__":
    unittest.main()
