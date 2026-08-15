import socket
import sys
import threading
from modules.crypto import encrypt_message, decrypt_message
from modules.config import config
from modules.ui import show_banner
from modules.protocol import (
    send_frame,
    recv_frame,
    set_tcp_nodelay,
    TYPE_MESSAGE,
    TYPE_COMMAND,
)

connected = True
print_lock = threading.Lock()


def safe_print(text: str):
    """Печатает текст из потока приёма, не ломая строку ввода."""
    with print_lock:
        print("\r" + text)
        print(">>> ", end="", flush=True)


def receive_messages(sock):
    """Поток для получения сообщений от сервера (E2E: сервер не видит текст)."""
    global connected
    while connected:
        try:
            frame = recv_frame(sock)
            if frame is None:
                safe_print("[СЕРВЕР] Соединение закрыто")
                break

            frame_type, payload = frame

            if frame_type == TYPE_MESSAGE:
                # Формат: имя + b'\x00' + шифротекст
                sep = payload.find(b"\x00")
                if sep == -1:
                    safe_print("[ОШИБКА] Повреждённый кадр сообщения")
                    continue

                sender_name = payload[:sep].decode("utf-8", errors="replace")
                encrypted = payload[sep + 1:].decode("utf-8", errors="replace")

                decrypted = decrypt_message(encrypted)
                if decrypted:
                    safe_print(f"[{sender_name}]: {decrypted.rstrip()}")
                else:
                    safe_print(f"[{sender_name}]: (не удалось расшифровать)")

            elif frame_type == TYPE_COMMAND:
                # Как M-кадр, но это системный/серверный ответ
                decrypted = decrypt_message(payload.decode("utf-8", errors="replace"))
                if decrypted:
                    safe_print(decrypted.rstrip())

        except Exception as e:
            safe_print(f"[ОШИБКА] {e}")
            break

    connected = False


def send_messages(sock, username):
    """Поток для отправки сообщений на сервер."""
    global connected
    while connected:
        try:
            message = input(">>> ").strip()
            if not message:
                continue

            if not connected:
                print("[ОШИБКА] Соединение уже потеряно")
                break

            try:
                encrypted = encrypt_message(message)

                if message.startswith("/"):
                    # Команда — сервер должен расшифровать сам
                    send_frame(sock, TYPE_COMMAND, encrypted)
                else:
                    # Сообщение — сервер НЕ должен видеть текст.
                    # Клиент сам добавляет имя: name + \x00 + шифротекст
                    send_frame(sock, TYPE_MESSAGE, username.encode("utf-8") + b"\x00" + encrypted.encode("utf-8"))
                print(f"[Я]: {message}")
            except (ConnectionResetError, BrokenPipeError, OSError):
                connected = False
                print("[ОШИБКА] Соединение потеряно, отправка невозможна")
                break

        except KeyboardInterrupt:
            print("\n[ВЫХОД] До свидания!")
            connected = False
            try:
                sock.close()
            except:
                pass
            sys.exit(0)
        except EOFError:
            print("\n[ВЫХОД] Ввод закрыт")
            connected = False
            break


def start_client():
    show_banner()

    host = config["server"]["host"]
    port = config["server"]["port"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((host, port))
        set_tcp_nodelay(sock)
        print(f"[ПОДКЛЮЧЕНИЕ] Подключено к {host}:{port}")

        username = input("Введи своё имя: ").strip()
        if not username:
            username = "Аноним"

        # Имя пользователя — фреймом M (сервер читает по фреймингу)
        send_frame(sock, TYPE_MESSAGE, username)
        print(f"\nДобро пожаловать, {username}!")
        print("Команды: /users, /clear, /help, /exit\n")

        recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
        recv_thread.start()

        send_messages(sock, username)

    except ConnectionRefusedError:
        print(f"[ОШИБКА] Не удалось подключиться к {host}:{port}")
        print("Убедитесь, что сервер запущен: python server.py  (или: go run server.go)")
    except Exception as e:
        print(f"[ОШИБКА] {e}")
    finally:
        try:
            sock.close()
        except:
            pass


if __name__ == "__main__":
    start_client()