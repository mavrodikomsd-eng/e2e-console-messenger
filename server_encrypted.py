import socket
import threading
from datetime import datetime
from crypto import decrypt_message, encrypt_message

clients = []
clients_lock = threading.Lock()

def log_message(username, message_preview):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {username}: {message_preview}"
    with open("messages.txt", "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")

def broadcast(encrypted_message, sender_socket=None):
    with clients_lock:
        for client_socket, client_address, username in clients:
            if client_socket != sender_socket:
                try:
                    client_socket.send(encrypted_message.encode("utf-8"))
                except:
                    pass

def handle_client(client_socket, client_address):
    username = None
    try:
        username = client_socket.recv(1024).decode("utf-8").strip()
        if not username:
            username = f"User_{client_address[1]}"
        
        with clients_lock:
            clients.append((client_socket, client_address, username))
        
        join_message = f"\n[СИСТЕМА] {username} присоединился к чату\n"
        encrypted_join = encrypt_message(join_message)
        broadcast(encrypted_join, client_socket)
        print(f"[ПОДКЛЮЧЕНИЕ] {username} подключился с {client_address}")
        
        while True:
            encrypted_data = client_socket.recv(1024).decode("utf-8").strip()
            if not encrypted_data:
                break
            
            if encrypted_data.startswith("/") or encrypted_data.startswith(b"/"):
                decrypted = decrypt_message(encrypted_data)
                if decrypted and decrypted.startswith("/"):
                    handle_command(decrypted, username, client_socket)
            else:
                formatted_message = f"[{username}]: (зашифровано)\n"
                log_message(username, "(зашифровано)")
                
                broadcast(encrypted_data, client_socket)
                
                encrypted_confirm = encrypt_message(f"[ТЫ]: отправлено\n")
                client_socket.send(encrypted_confirm.encode("utf-8"))
                print(f"[{username}]: отправил зашифрованное сообщение")
    
    except Exception as e:
        print(f"[ОШИБКА] {e}")
    
    finally:
        if username:
            with clients_lock:
                clients[:] = [(s, a, u) for s, a, u in clients if s != client_socket]
            leave_message = f"\n[СИСТЕМА] {username} покинул чат\n"
            encrypted_leave = encrypt_message(leave_message)
            broadcast(encrypted_leave)
            print(f"[ОТКЛЮЧЕНИЕ] {username} отключился")
        client_socket.close()

def handle_command(command, username, client_socket):
    if command == "/users":
        with clients_lock:
            user_list = [u for _, _, u in clients]
        response = f"\n[ПОЛЬЗОВАТЕЛИ] Онлайн: {', '.join(user_list)}\n"
        encrypted_response = encrypt_message(response)
        client_socket.send(encrypted_response.encode("utf-8"))
    
    elif command == "/clear":
        response = "\n" * 50
        encrypted_response = encrypt_message(response)
        client_socket.send(encrypted_response.encode("utf-8"))
    
    elif command == "/help":
        help_text = "\n[КОМАНДЫ]\n/users - список пользователей\n/clear - очистить экран\n/exit - выход\n/help - справка\n"
        encrypted_help = encrypt_message(help_text)
        client_socket.send(encrypted_help.encode("utf-8"))
    
    elif command == "/exit":
        client_socket.close()

def start_server(host="localhost", port=1301):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[СЕРВЕР] Запущен на {host}:{port}")
    print(f"[СЕРВЕР] Режим: E2E шифрование (сервер не видит содержимое)\n")
    
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[СЕРВЕР] Остановлен")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
