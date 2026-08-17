import base64
import hashlib
import json
import os
import sys
from Crypto.Cipher import AES
from Crypto.Protocol import DH

KEY_FILE = "secret.key"
CONFIG_FILE = "config.json"

# ─────────────────────────────────────────────
#  AES-256-GCM
#  Формат сообщения:
#    base64( nonce(12) + ciphertext + tag(16) )
#
#  Секретный ключ НЕ хранится в config.json / репозитории.
#  Он лежит в отдельном файле secret.key (см. .gitignore).
#  Файл создаётся сам при первом запуске.
# ─────────────────────────────────────────────
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32  # AES-256


def _write_key_file(key: bytes) -> None:
    """Сохраняет ключ (base64) в файл secret.key."""
    with open(KEY_FILE, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(key).decode("ascii") + "\n")


def _generate_key() -> bytes:
    """Генерирует криптостойкий ключ AES-256."""
    return os.urandom(KEY_SIZE)


def _load_key() -> bytes:
    """
    В порядке приоритета:
      1. secret.key            — основной источник секрета
      2. config.json           — миграция со старой версии (копия в secret.key)
      3. генерация нового ключа, если секрета нигде нет
    """
    # 1) Файл секрета
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r", encoding="utf-8") as f:
            key_b64 = f.read().strip()
        key = base64.b64decode(key_b64)
        if len(key) == KEY_SIZE:
            return key
        raise ValueError(
            f"secret.key повреждён: ключ должен быть "
            f"{KEY_SIZE} байт (AES-256) в base64."
        )

    # 2) Миграция: раньше ключ лежал в config.json — переносим в secret.key
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            key_b64 = cfg.get("crypto", {}).get("key")
            if key_b64:
                key = base64.b64decode(key_b64)
                if len(key) == KEY_SIZE:
                    _write_key_file(key)
                    print(
                        f"[ВНИМАНИЕ] Ключ перенесён из {CONFIG_FILE} в {KEY_FILE}. "
                        f"Удали поле crypto.key из конфигов и закоммить изменение.",
                        file=sys.stderr,
                    )
                    return key
        except Exception:
            pass  # если конфиг битый — просто сгенерируем новый ключ

    # 3) Секрета нет — генерируем новый
    key = _generate_key()
    _write_key_file(key)
    print(
        f"[СОЗДАНИЕ] Ключ AES-256 сгенерирован и сохранён в {KEY_FILE}. "
        f"Поделись им с участниками чата (никогда не коммить его в git).",
        file=sys.stderr,
    )
    return key


KEY = _load_key()


def encrypt_message(plaintext, aad=b""):
    return _gcm_encrypt(KEY, plaintext, aad)


def decrypt_message(encoded, aad=b""):
    return _gcm_decrypt(KEY, encoded, aad)


def _gcm_encrypt(key, plaintext, aad=b""):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if isinstance(aad, str):
        aad = aad.encode("utf-8")
    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(nonce + ciphertext + tag).decode("utf-8")


def _gcm_decrypt(key, encoded, aad=b""):
    try:
        payload = base64.b64decode(encoded)
        nonce = payload[:NONCE_SIZE]
        tag = payload[-TAG_SIZE:]
        ciphertext = payload[NONCE_SIZE:-TAG_SIZE]
        if isinstance(aad, str):
            aad = aad.encode("utf-8")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
    except Exception:
        return None


IDENTITY_FILE = "identity.key"


def load_or_create_identity():
    path = os.environ.get("MESH_IDENTITY_FILE", IDENTITY_FILE)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            parts = f.read().split()
        if len(parts) == 2:
            return parts[0], parts[1]
    seed = os.urandom(KEY_SIZE)
    priv = DH.import_x25519_private_key(seed)
    pub = priv.public_key().export_key(format="raw")
    seed_b64 = base64.b64encode(seed).decode("ascii")
    pub_b64 = base64.b64encode(pub).decode("ascii")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{seed_b64} {pub_b64}\n")
    return seed_b64, pub_b64


def _derive_key(our_seed_b64, peer_pub_b64):
    seed = base64.b64decode(our_seed_b64)
    peer_pub = base64.b64decode(peer_pub_b64)
    priv = DH.import_x25519_private_key(seed)
    pub = DH.import_x25519_public_key(peer_pub)

    def _kdf(shared):
        return hashlib.sha256(shared).digest()

    return DH.key_agreement(static_priv=priv, static_pub=pub, kdf=_kdf)


def encrypt_to_peer(plaintext, peer_pub_b64, self_pub_b64, our_seed_b64):
    key = _derive_key(our_seed_b64, peer_pub_b64)
    return _gcm_encrypt(key, plaintext, aad=self_pub_b64)


def decrypt_from_peer(encoded, sender_pub_b64, our_seed_b64):
    key = _derive_key(our_seed_b64, sender_pub_b64)
    return _gcm_decrypt(key, encoded, aad=sender_pub_b64)
