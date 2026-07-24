import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
from modules.crypto import encrypt_message, decrypt_message
from modules.config import config


class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("my-messenger")
        self.root.geometry("600x500")
        self.root.configure(bg="#1e1e2e")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.sock = None
        self.username = None
        self.connected = False

        self._build_ui()
        self._connect()

    def _build_ui(self):
        # История чата
        self.chat_area = scrolledtext.ScrolledText(
            self.root, state="disabled", wrap=tk.WORD,
            bg="#282a36", fg="#f8f8f2", insertbackground="#f8f8f2",
            font=("Consolas", 11), padx=8, pady=8
        )
        self.chat_area.pack(padx=10, pady=(10, 5), fill=tk.BOTH, expand=True)

        # Нижняя панель: поле ввода + кнопки
        bottom_frame = tk.Frame(self.root, bg="#1e1e2e")
        bottom_frame.pack(padx=10, pady=(0, 10), fill=tk.X)

        self.entry = tk.Entry(
            bottom_frame, font=("Consolas", 11),
            bg="#44475a", fg="#f8f8f2", insertbackground="#f8f8f2",
            relief=tk.FLAT
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6, padx=(0, 6))
        self.entry.bind("<Return>", lambda e: self.send_message())

        send_btn = tk.Button(
            bottom_frame, text="Отправить", command=self.send_message,
            bg="#50fa7b", fg="#1e1e2e", relief=tk.FLAT, font=("Consolas", 10, "bold")
        )
        send_btn.pack(side=tk.LEFT, padx=(0, 6))

        users_btn = tk.Button(
            bottom_frame, text="/users", command=lambda: self.send_command("/users"),
            bg="#8be9fd", fg="#1e1e2e", relief=tk.FLAT, font=("Consolas", 10)
        )
        users_btn.pack(side=tk.LEFT, padx=(0, 6))

        clear_btn = tk.Button(
            bottom_frame, text="Очистить", command=self.clear_chat,
            bg="#ffb86c", fg="#1e1e2e", relief=tk.FLAT, font=("Consolas", 10)
        )
        clear_btn.pack(side=tk.LEFT)

        # Статус-бар
        self.status_var = tk.StringVar(value="Подключение...")
        status_bar = tk.Label(
            self.root, textvariable=self.status_var, anchor="w",
            bg="#1e1e2e", fg="#6272a4", font=("Consolas", 9)
        )
        status_bar.pack(padx=10, pady=(0, 5), fill=tk.X)

    def _connect(self):
        self.username = simpledialog.askstring("Имя", "Введи своё имя:", parent=self.root)
        if not self.username:
            self.username = "Аноним"

        host = config["server"]["host"]
        port = config["server"]["port"]

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.sock.send(self.username.encode("utf-8"))
            self.connected = True
            self.status_var.set(f"Подключено к {host}:{port} как {self.username}")

            recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
            recv_thread.start()

            self._append_line(f"Добро пожаловать, {self.username}!\n")
        except ConnectionRefusedError:
            messagebox.showerror("Ошибка", f"Не удалось подключиться к {host}:{port}.\nЗапусти сервер: python server.py")
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            self.root.destroy()

    def _receive_loop(self):
        while self.connected:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                encrypted_message = data.decode("utf-8")
                decrypted = decrypt_message(encrypted_message)
                if decrypted:
                    self._append_line(decrypted)
                else:
                    self._append_line("[ОШИБКА] Не удалось расшифровать сообщение\n")
            except Exception:
                break
        self.connected = False
        self.status_var.set("Соединение потеряно")

    def send_message(self):
        message = self.entry.get().strip()
        if not message or not self.connected:
            return
        try:
            encrypted = encrypt_message(message)
            self.sock.send(encrypted.encode("utf-8"))
            if not message.startswith("/"):
                self._append_line(f"[Я]: {message}\n")
            self.entry.delete(0, tk.END)
        except Exception as e:
            self._append_line(f"[ОШИБКА ОТПРАВКИ] {e}\n")

    def send_command(self, command):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, command)
        self.send_message()

    def clear_chat(self):
        self.chat_area.configure(state="normal")
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.configure(state="disabled")

    def _append_line(self, text):
        def _do():
            self.chat_area.configure(state="normal")
            self.chat_area.insert(tk.END, text)
            self.chat_area.see(tk.END)
            self.chat_area.configure(state="disabled")
        self.root.after(0, _do)

    def on_close(self):
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.root.destroy()


def start_gui_client():
    root = tk.Tk()
    ChatClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    start_gui_client()
