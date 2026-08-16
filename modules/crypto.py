import base64
import json
import os
import sys
from Crypto.Cipher import AES

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


def encrypt_message(plaintext: str, aad: bytes | str = b"") -> str:
    """
    Аутентифицированное шифрование AES-256-GCM.

    aad (Additional Authenticated Data) — открытые данные, которые
    ПРИВЯЗАНЫ к шифротексту: любое их изменение ломает проверку тега.
    Используй aad=имя отправителя, чтобы подмена имени в кадре
    не проходила незамеченной.

    Возвращает base64(nonce + ciphertext + tag).
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if isinstance(aad, str):
        aad = aad.encode("utf-8")

    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)  # привязка имени отправителя к шифротексту
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    payload = nonce + ciphertext + tag
    return base64.b64encode(payload).decode("utf-8")


def decrypt_message(encoded: str, aad: bytes | str = b"") -> str | None:
    """
    Расшифровка и проверка подлинности AES-256-GCM.
    aad должен совпадать с тем, что был передан при шифровании.

    Возвращает None при ошибке (битый ciphertext, подмена/изменение
    aad, неверный ключ).
    """
    try:
        payload = base64.b64decode(encoded)

        nonce = payload[:NONCE_SIZE]
        tag = payload[-TAG_SIZE:]
        ciphertext = payload[NONCE_SIZE:-TAG_SIZE]
        if isinstance(aad, str):
            aad = aad.encode("utf-8")

        cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)  # должно совпадать с AAD при шифровании
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")

    except Exception:
        # Любая ошибка расшифровки = сообщение повреждено/подменено/не для нас
        return None