import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import winsound

try:
    from modules.crypto import encrypt_message, decrypt_message
    from modules.config import config
except ImportError:
    config = {"server": {"host": "localhost", "port": 1301}}
    def encrypt_message(m): return m
    def decrypt_message(m): return m

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
            bg="#282a36", fg="#f8f8f2", font=("Courier", 11),
            padx=8, pady=8, relief=tk.FLAT, borderwidth=0
        )
        self.chat_text.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        
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
            self.sock.send(self.username.encode("utf-8"))
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
                data = self.sock.recv(4096)
                if not data:
                    break
                
                encrypted = data.decode("utf-8")
                decrypted = decrypt_message(encrypted)
                
                if decrypted:
                    # Звук уведомления
                    try:
                        winsound.Beep(800, 200)
                    except:
                        pass
                    self._append(decrypted)
                else:
                    self._append("[❌] Не удалось расшифровать\n")
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
            encrypted = encrypt_message(message)
            
            with self.lock:
                self.sock.send(encrypted.encode("utf-8"))
            
            if not message.startswith("/"):
                self._append(f"[Я]: {message}\n")
            
            self.entry.delete(0, tk.END)
        except Exception as e:
            self._append(f"[❌ ОШИБКА] {e}\n")

    def _append(self, text):
        def _do():
            self.chat_text.configure(state="normal")
            self.chat_text.insert(tk.END, text)
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