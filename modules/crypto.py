import base64
import json
import os
from Crypto.Cipher import AES

CONFIG_FILE = "config.json"

# ─────────────────────────────────────────────
#  AES-256-GCM
#  Формат сообщения:
#    base64( nonce(12) + ciphertext + tag(16) )
# ─────────────────────────────────────────────
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32  # AES-256


def _load_key() -> bytes:
    """Читает и валидирует ключ AES-256 из config.json"""
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    key_b64 = cfg["crypto"]["key"]
    key = base64.b64decode(key_b64)

    if len(key) != KEY_SIZE:
        raise ValueError(
            f"Ключ должен быть {KEY_SIZE} байт (AES-256), "
            f"получено {len(key)} байт. Сгенерируй новый: "
            f"openssl rand -base64 32"
        )

    return key


KEY = _load_key()


def encrypt_message(plaintext: str) -> str:
    """
    Аутентифицированное шифрование AES-256-GCM.
    Возвращает base64(nonce + ciphertext + tag).
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    payload = nonce + ciphertext + tag
    return base64.b64encode(payload).decode("utf-8")


def decrypt_message(encoded: str) -> str | None:
    """
    Расшифровка и проверка подлинности AES-256-GCM.
    Возвращает None при ошибке (битый ciphertext, подмена, неверный ключ).
    """
    try:
        payload = base64.b64decode(encoded)

        nonce = payload[:NONCE_SIZE]
        tag = payload[-TAG_SIZE:]
        ciphertext = payload[NONCE_SIZE:-TAG_SIZE]

        cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")

    except Exception:
        # Любая ошибка расшифровки = сообщение повреждено/подменено/не для нас
        return None