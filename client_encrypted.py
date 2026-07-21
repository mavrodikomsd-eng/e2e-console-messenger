import socket
import threading
import sys
from crypto import encrypt_message, decrypt_message

def receive_messages(sock):
    while True:
        try:
            encrypted_message = sock.recv(1024).decode("utf-8")
            if encrypted_message:
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
    while True:
        try:
            message = input(">>> ")
            if message:
                encrypted = encrypt_message(message)
                sock.send(encrypted.encode("utf-8"))
        except KeyboardInterrupt:
            print("\n[ВЫХОД] До свидания!")
            sock.close()
            sys.exit(0)
        except:
            break

def start_client(host="localhost", port=1301):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect((host, port))
        print(f"[ПОДКЛЮЧЕНИЕ] Подключено к {host}:{port}")
        
        username = input("Введи своё имя: ").strip()
        if not username:
            username = "Аноним"
        
        sock.send(username.encode("utf-8"))
        print(f"\nДобро пожаловать, {username}!")
        print("Команды: /users (список), /clear (очистить), /help (справка), /exit (выход)\n")
        
        receive_thread = threading.Thread(target=receive_messages, args=(sock,))
        receive_thread.daemon = True
        receive_thread.start()
        
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
