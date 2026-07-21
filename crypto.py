from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

SHARED_KEY = b"mysecretkey12345"

def encrypt_message(message):
    iv = get_random_bytes(16)
    cipher = AES.new(SHARED_KEY, AES.MODE_CBC, iv)
    padded = pad(message.encode("utf-8"), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode("utf-8")

def decrypt_message(encrypted_message):
    try:
        data = base64.b64decode(encrypted_message)
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(SHARED_KEY, AES.MODE_CBC, iv)
        padded = cipher.decrypt(encrypted)
        return unpad(padded, AES.block_size).decode("utf-8")
    except:
        return None
