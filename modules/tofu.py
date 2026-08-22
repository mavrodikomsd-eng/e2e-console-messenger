import base64
import hashlib
import json
import os

# ─────────────────────────────────────────────
#  TOFU (Trust On First Use) — защита от MITM.
#  Публичные ключи пиров запоминаются при первой встрече (отпечаток SHA-256).
#  Если ключ пира позже изменился — это возможная атака «человек посередине»
#  или переустановка identity у собеседника: клиент предупреждает и требует
#  явного подтверждения (/trust <ник>).
# ─────────────────────────────────────────────
TOFU_FILE = "tofu.json"


def fingerprint(pub_b64: str) -> str:
    """Человекочитаемый отпечаток публичного ключа: группы по 4 hex-символа."""
    digest = hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, len(digest), 4)).upper()


class TofuStore:
    def __init__(self, path=None):
        self.path = path or os.environ.get("MESH_TOFU_FILE", TOFU_FILE)
        self.known = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.known = {str(k): str(v) for k, v in data.items()}
            except Exception:
                pass  # битый файл — начинаем с пустого хранилища

    def save(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.known, f, ensure_ascii=False, indent=2)

    def check(self, name: str, pub_b64: str) -> str:
        """
        Проверяет ключ пира. Возвращает:
          'new'      — пир увиден впервые, ключ сохранён;
          'ok'       — ключ совпадает с ранее сохранённым;
          'changed'  — КЛЮЧ ИЗМЕНИЛСЯ (возможен MITM).
        """
        fp = fingerprint(pub_b64)
        old = self.known.get(name)
        if old is None:
            self.known[name] = fp
            self.save()
            return "new"
        if old == fp:
            return "ok"
        return "changed"

    def trust(self, name: str, pub_b64: str) -> None:
        """Явное подтверждение нового ключа пользователем."""
        self.known[name] = fingerprint(pub_b64)
        self.save()
