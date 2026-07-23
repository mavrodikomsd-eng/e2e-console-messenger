import json
import os


CONFIG_FILE = "config.json"


def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(
            "config.json не найден"
        )

    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


config = load_config()