import datetime

import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import winsound

try:
    from modules.crypto import encrypt_message, decrypt_message
    from modules.config import config
    from modules.protocol import (
        send_frame,
        recv_frame,
        set_tcp_nodelay,
        TYPE_MESSAGE,
        TYPE_COMMAND,
    )
except ImportError:
    config = {"server": {"host": "localhost", "port": 1301}}
    def encrypt_message(m, aad=b""): return m
    def decrypt_message(m, aad=b""): return m
    def send_frame(s, t, p): s.send(p.encode("utf-8"))
    def recv_frame(s): return (b"M", s.recv(1024))
    def set_tcp_nodelay(s): pass
    TYPE_MESSAGE = b"M"
    TYPE_COMMAND = b"C"


class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("my-messenger")
        self.root.geometry("700x600")
        self.root.configure(bg="#1e1e2e")

        self.sock = None
        self.username = None
        self.connected = False
        self.lock = threading.Lock()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._build_ui()
        self._connect()

    def _build_ui(self):
        # Заголовок
        header = tk.Frame(self.root, bg="#1e1e2e")
        header.pack(fill=tk.X, padx=10, pady=(10, 5))

        tk.Label(header, text="💬 my-messenger", font=("Arial", 18, "bold"),
                bg="#1e1e2e", fg="#50fa7b").pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="Подключение...")
        tk.Label(header, textvariable=self.status_var, font=("Arial", 10),
                bg="#1e1e2e", fg="#6272a4").pack(side=tk.RIGHT)

        # Чат
        self.chat_text = scrolledtext.ScrolledText(
            self.root, state="disabled", wrap=tk.WORD,
            bg="#282a36", fg="#f8f8f2", font=("Segoe UI", 11),
            padx=10, pady=10, relief=tk.FLAT, borderwidth=0,
            insertbackground="#f8f8f2"
        )
        self.chat_text.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)

        # Теги стилей
        self.chat_text.tag_config("time", foreground="#6272a4", font=("Segoe UI", 9))
        self.chat_text.tag_config("my_name", foreground="#50fa7b", font=("Segoe UI", 11, "bold"))
        self.chat_text.tag_config("other_name", foreground="#ff79c6", font=("Segoe UI", 11, "bold"))
        self.chat_text.tag_config("system", foreground="#8be9fd", font=("Segoe UI", 10, "italic"))
        self.chat_text.tag_config("text", foreground="#f8f8f2", font=("Segoe UI", 11))
        self.chat_text.tag_config("error", foreground="#ff5555", font=("Segoe UI", 10, "bold"))

        # Нижняя панель
        bottom = tk.Frame(self.root, bg="#1e1e2e")
        bottom.pack(padx=10, pady=(0, 10), fill=tk.X)

        self.entry = tk.Entry(
            bottom, font=("Arial", 11), bg="#44475a", fg="#f8f8f2",
            insertbackground="#f8f8f2", relief=tk.FLAT, borderwidth=0
        )
        self.entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, ipady=8, padx=(0, 6))
        self.entry.bind("<Return>", lambda e: self.send_message())

        tk.Button(bottom, text="📤 Отправить", command=self.send_message,
                 bg="#50fa7b", fg="#1e1e2e", relief=tk.FLAT, font=("Arial", 10, "bold"),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(bottom, text="/users", command=lambda: self.quick_cmd("/users"),
                 bg="#8be9fd", fg="#1e1e2e", relief=tk.FLAT, font=("Arial", 9),
                 padx=10, pady=8).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(bottom, text="/clear", command=lambda: self.quick_cmd("/clear"),
                 bg="#ffb86c", fg="#1e1e2e", relief=tk.FLAT, font=("Arial", 9),
                 padx=10, pady=8).pack(side=tk.LEFT)

    def _connect(self):
        username = simpledialog.askstring("Имя", "Введи своё имя:", parent=self.root)
        if not username:
            username = "Аноним"
        self.username = username

        host = config["server"]["host"]
        port = config["server"]["port"]

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            set_tcp_nodelay(self.sock)
            # Имя пользователя — фреймом M (без шифрования)
            send_frame(self.sock, TYPE_MESSAGE, self.username)
            self.connected = True
            self.status_var.set(f"✅ Подключено как {self.username}")
            self._append(f"Добро пожаловать, {self.username}!\n")

            threading.Thread(target=self._receive_loop, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться: {e}")
            self.root.destroy()

    def _receive_loop(self):
        while self.connected:
            try:
                frame = recv_frame(self.sock)
                if frame is None:
                    break

                frame_type, payload = frame

                if frame_type == TYPE_MESSAGE:
                    # Формат: имя + b'\x00' + шифротекст
                    sep = payload.find(b"\x00")
                    if sep == -1:
                        time_str = datetime.datetime.now().strftime("%H:%M")
                        self._append(f"[{time_str}] ", "time")
                        self._append("[❌] Повреждённый кадр сообщения\n", "error")
                        continue

                    sender_name = payload[:sep].decode("utf-8", errors="replace")
                    encrypted = payload[sep + 1:].decode("utf-8", errors="replace")

                    # AAD = имя отправителя: подмена имени сломает проверку тега
                    decrypted = decrypt_message(encrypted, aad=sender_name)
                    time_str = datetime.datetime.now().strftime("%H:%M")
                    if decrypted:
                        self._append(f"[{time_str}] ", "time")
                        self._append(f"{sender_name}: ", "other_name")
                        self._append(f"{decrypted.rstrip()}\n", "text")
                        try:
                            winsound.Beep(800, 200)
                        except:
                            pass
                    else:
                        self._append(f"[{time_str}] ", "time")
                        self._append(f"{sender_name}: ", "other_name")
                        self._append("(не удалось расшифровать — возможно, подменено имя)\n", "error")

                elif frame_type == TYPE_COMMAND:
                    decrypted = decrypt_message(payload.decode("utf-8", errors="replace"))
                    if decrypted:
                        time_str = datetime.datetime.now().strftime("%H:%M")
                        self._append(f"[{time_str}] ", "time")
                        self._append(f"{decrypted.rstrip()}\n", "system")

            except Exception:
                break

        self.connected = False
        self.status_var.set("❌ Соединение потеряно")

    def send_message(self):
        if not self.connected:
            return

        message = self.entry.get().strip()
        if not message:
            return

        try:
            with self.lock:
                if message.startswith("/msg "):
                    # Личное сообщение: /msg Имя текст
                    parts = message.split(maxsplit=2)
                    encrypted = ""
                    if len(parts) >= 3:
                        target_name, text = parts[1], parts[2]
                        encrypted = encrypt_message(text, aad=self.username)
                        send_frame(
                            self.sock,
                            TYPE_MESSAGE,
                            self.username.encode("utf-8") + b"\x00" + target_name.encode("utf-8") + b"\x00" + encrypted.encode("utf-8"),
                        )
                        self._append(f"[Я] → {target_name}: {text}\n")
                    else:
                        self._append("[❌] Формат: /msg Имя текст\n", "error")
                elif message.startswith("/"):
                    # Команда — сервер расшифровывает сам, AAD не нужен
                    encrypted = encrypt_message(message)
                    send_frame(self.sock, TYPE_COMMAND, encrypted)
                else:
                    # AAD = имя отправителя (привязка имени к шифротексту)
                    encrypted = encrypt_message(message, aad=self.username)
                    # E2E: имя добавляет клиент, сервер не видит текст
                    send_frame(
                        self.sock,
                        TYPE_MESSAGE,
                        self.username.encode("utf-8") + b"\x00" + encrypted.encode("utf-8"),
                    )

            if not message.startswith("/"):
                self._append(f"[Я]: {message}\n")

            self.entry.delete(0, tk.END)
        except Exception as e:
            self._append(f"[❌ ОШИБКА] {e}\n")

    def _append(self, text, tag="text"):
        def _do():
            self.chat_text.configure(state="normal")
            self.chat_text.insert(tk.END, text, tag)
            self.chat_text.see(tk.END)
            self.chat_text.configure(state="disabled")
        self.root.after(0, _do)

    def quick_cmd(self, cmd):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, cmd)
        self.send_message()

    def on_close(self):
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    ChatClientGUI(root)
    root.mainloop()