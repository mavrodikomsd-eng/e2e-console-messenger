def handle_command(command):

    if command == "/help":
        return "Команды: /help /users /clear /exit /about /time /status /ping"

    elif command == "/users":
        return "USERS"

    elif command == "/clear":
        return "CLEAR"

    elif command == "/exit":
        return "EXIT"

    elif command == "/about":
        return (
            "MeshMessenger\n"
            "Версия: 0.1\n"
            "Локальный P2P-мессенджер."
        )

    elif command == "/time":
        return "TIME"

    elif command == "/status":
        return "STATUS"

    elif command == "/ping":
        return "PING"

    else:
        return None