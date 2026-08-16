import os
import socket
import threading
import traceback
from datetime import datetime
from modules.crypto import encrypt_message, decrypt_message
from modules.config import config
from modules.protocol import (
    send_frame,
    recv_frame,
    set_tcp_nodelay,
    TYPE_MESSAGE,
    TYPE_COMMAND,
)

clients = []  # (socket, address, username)
clients_lock = threading.Lock()


def log_message(username, message_preview):
    logging_cfg = config.get("logging", {})
    if not logging_cfg.get("enabled", True):
        return
    log_path = logging_cfg.get("file", "messages.log")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {username}: {message_preview}"
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    except Exception:
        pass
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")


def broadcast_frame(frame_type, payload, sender_socket=None, target=None):
    """Пересылает кадр ВСЕМ клиентам, кроме отправителя (E2E: содержимое не читаем).
    Если задан target — только этому пользователю."""
    with clients_lock:
        for client_socket, client_address, username in clients:
            if client_socket == sender_socket:
                continue
            if target is not None and username != target:
                continue
            try:
                send_frame(client_socket, frame_type, payload)
            except Exception:
                pass


def handle_client(client_socket, client_address):
    username = None
    try:
        # Первый кадр — имя пользователя (без шифрования)
        first = recv_frame(client_socket)
        if first is None:
            client_socket.close()
            return

        username = first[1].decode("utf-8").strip()
        if not username:
            username = f"User_{client_address[1]}"

        with clients_lock:
            max_clients = config.get("server", {}).get("max_clients", 0)
            if max_clients and len(clients) >= max_clients:
                print(f"[ОТКАЗ] {username}: достигнут лимит {max_clients} клиентов")
                client_socket.close()
                return
            clients.append((client_socket, client_address, username))

        print(f"[ПОДКЛЮЧЕНИЕ] {username} подключился с {client_address}")

        # Системное сообщение о подключении шлём типом C (зашифровано)
        # — кто угодно может прочитать (все знают ключ)
        join_text = f"\n[СИСТЕМА] {username} присоединился к чату"
        broadcast_frame(TYPE_COMMAND, encrypt_message(join_text), client_socket)

        while True:
            frame = recv_frame(client_socket)
            if frame is None:
                break

            frame_type, payload = frame

            if frame_type == TYPE_MESSAGE:
                # ── E2E: сервер НЕ смотрит содержимое ──
                # Формат: имя + \x00 + шифротекст
                # Личное: имя + \x00 + получатель + \x00 + шифротекст

                # Личное сообщение: два разделителя — пересылаем только адресату
                if payload.count(b"\x00") >= 2:
                    try:
                        _, target_bytes, _ = payload.split(b"\x00", 2)
                        target_name = target_bytes.decode("utf-8").strip()
                    except Exception:
                        target_name = None

                    if target_name:
                        log_message(username, f"(личное для {target_name})")
                        broadcast_frame(TYPE_MESSAGE, payload, client_socket, target=target_name)
                        print(f"[{username}] -> {target_name}: (личное E2E сообщение)")
                        continue

                # Обычное сообщение: пересылаем всем
                log_message(username, "(E2E сообщение)")
                broadcast_frame(TYPE_MESSAGE, payload, client_socket)
                print(f"[{username}]: (E2E сообщение → переслано)")

            elif frame_type == TYPE_COMMAND:
                # Команду расшифровываем (это служебные данные)
                decrypted = decrypt_message(payload.decode("utf-8", errors="replace"))
                if decrypted is None:
                    print(f"[!!] {username} отправил невалидную команду")
                    continue
                handle_command(decrypted, username, client_socket)

    except Exception:
        print("\n========== TRACEBACK ==========")
        traceback.print_exc()
        print("===============================")

    finally:
        if username:
            with clients_lock:
                clients[:] = [(s, a, u) for s, a, u in clients if s != client_socket]
            leave_text = f"\n[СИСТЕМА] {username} покинул чат"
            broadcast_frame(TYPE_COMMAND, encrypt_message(leave_text))
            print(f"[ОТКЛЮЧЕНИЕ] {username} отключился")
        try:
            client_socket.close()
        except:
            pass


def handle_command(command, username, client_socket):
    """Обработка команд от клиента (ответ шлём типом C, зашифрованный)."""
    command = command.strip()

    if command == "/users":
        with clients_lock:
            user_list = [u for _, _, u in clients]
        response = f"\n[ПОЛЬЗОВАТЕЛИ] Онлайн ({len(user_list)}): {', '.join(user_list)}"
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(response))

    elif command == "/clear":
        response = "\n" * 50
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(response))

    elif command == "/help":
        help_text = "\n[КОМАНДЫ]\n/users - список пользователей\n/msg Имя текст - личное сообщение\n/clear - очистить экран\n/exit - выход\n/help - справка"
        send_frame(client_socket, TYPE_COMMAND, encrypt_message(help_text))

    elif command == "/exit":
        client_socket.close()


def start_server():
    host = config["server"]["host"]
    port = config["server"]["port"]
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[СЕРВЕР] Запущен на {host}:{port}")
    print("[СЕРВЕР] Режим: E2E шифрование (сервер НЕ видит содержимое сообщений)\n")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            set_tcp_nodelay(client_socket)
            thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[СЕРВЕР] Остановлен")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()