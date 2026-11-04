import json
import os


# Путь — от корня проекта (родитель modules/), а не от cwd.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(PROJECT_ROOT, "config.json")

# Значения по умолчанию: клиент/сервер запускаются даже без config.json
# рядом с исполняемым файлом (раньше это был FileNotFoundError на старте).
DEFAULT_CONFIG = {
    "server": {
        "host": "localhost",
        "port": 1301,
        "max_clients": 100,
    },
    "logging": {
        "enabled": True,
        "file": "data/logs/messages.log",
    },
    "client": {
        "auto_reconnect": True,
    },
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG

    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


config = load_config()