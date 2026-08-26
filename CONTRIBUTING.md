# 🤝 Contributing to MeshMessenger

Спасибо за интерес к проекту! Вот как начать.

## Быстрый старт

1. Форкни репозиторий
2. Клонируй:
   ```bash
   git clone [https://github.com/TVOY_USERNAME/mesh.git](https://github.com/mavrodikomsd-eng/e2e-console-messenger.git)
   ```
3. Запусти сервер:
   ```bash
   go build server.go && ./server.exe
   ```
4. Запусти GUI:
   ```bash
   cd rust_gui && cargo build --release
   ```

## Структура проекта

| Папка | Что внутри | Язык |
|-------|-----------|------|
| `server_v2/` | GUI-сервер (SQLite) | Go |
| `server.go` | CLI-сервер | Go |
| `rust_gui/` | Графический клиент | Rust |
| `client.py` | Консольный клиент | Python |
| `go_client/` | CLI-клиент | Go |
| `rust_client/` | CLI-клиент | Rust |
| `modules/` | Крипто, протокол, TOFU | Python |
| `admin/` | Админ-панель | Python |
| `landing/` | Product-page | HTML |
| `tests/` | Автотесты | Python |

## Правила

### Код
- Следуй стилю существующего кода
- Не добавляй комментарии без необходимости
- Не коммить секреты (`secret.key`, `identity.key`, `accounts.json`)
- Проверяй сборку перед коммитом:
  ```bash
  go build server.go
  cd rust_gui && cargo build --release
  python -m py_compile client.py
  ```

### Коммиты
- Пиши на русском или английском
- Формат: `тип: описание` (пример: `gui: добавил реакции на сообщения`)
- Типы: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`
- Релизы: `v1.6.0 - описание`

### Pull Request
1. Создай ветку от `main`
2. Внеси изменения
3. Проверь сборку
4. Обнови `CHANGELOG.md`
5. Открой PR с описанием изменений

## Тесты

```bash
# Python тесты
python -m unittest discover tests

# Go тесты
go test ./...

# Rust сборка
cd rust_gui && cargo build --release
```

## Криптография

Если меняешь крипто-часть:
- X25519 + AES-256-GCM — не трогай без веской причины
- TOFU — формат `tofu.json` должен оставаться совместимым
- Пароли — только argon2id, не SHA-256

## Вопросы?

Открой Issue в GitHub или напиши в обсуждении.
