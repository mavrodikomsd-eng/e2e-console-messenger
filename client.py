import socket
import threading
import sys
from modules.crypto import encrypt_message, decrypt_message
from modules.config import config
from modules.ui import show_banner, show_help
from modules.commands import handle_command

def receive_messages(sock):
    """Поток для получения сообщений от сервера"""
    while True:
        try:
            # Получаем bytes из сокета
            encrypted_message_bytes = sock.recv(1024)
            if encrypted_message_bytes:
                # Декодируем в строку для decrypt_message
                encrypted_message = encrypted_message_bytes.decode("utf-8")
                decrypted = decrypt_message(encrypted_message)
                if decrypted:
                    print(decrypted, end="")
                else:
                    print("[ОШИБКА] Не удалось расшифровать", end="")
                print(">>> ", end="", flush=True)
            else:
                break
        except:
            break

def send_messages(sock):
    """Поток для отправки сообщений на сервер"""
    while True:
        try:
            message = input(">>> ")
            if message:
                encrypted = encrypt_message(message)
                # encrypted уже строка, кодируем в bytes для отправки
                sock.send(encrypted.encode("utf-8"))
        except KeyboardInterrupt:
            print("\n[ВЫХОД] До свидания!")
            sock.close()
            sys.exit(0)
        except:
            break

def start_client():
    show_banner()

    host = config["server"]["host"]
    port = config["server"]["port"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect((host, port))
        print(f"[ПОДКЛЮЧЕНИЕ] Подключено к {host}:{port}")
        
        username = input("Введи своё имя: ").strip()
        if not username:
            username = "Аноним"
        
        # Отправляем имя пользователя
        sock.send(username.encode("utf-8"))
        print(f"\nДобро пожаловать, {username}!")
        print("Команды: /users (список), /clear (очистить), /help (справка), /exit (выход)\n")
        
        # Запускаем поток для получения сообщений
        receive_thread = threading.Thread(target=receive_messages, args=(sock,))
        receive_thread.daemon = True
        receive_thread.start()
        
        # Основной поток отправляет сообщения
        send_messages(sock)
    
    except ConnectionRefusedError:
        print(f"[ОШИБКА] Не удалось подключиться к {host}:{port}")
        print("Убедитесь, что сервер запущен: python server.py")
    except Exception as e:
        print(f"[ОШИБКА] {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    start_client()
