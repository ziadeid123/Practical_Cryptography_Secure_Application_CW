import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend


class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Client")
        self.client_socket = None

        # GUI Elements
        self.encryption_choice = tk.StringVar(value="AES")
        self.method_dropdown = tk.OptionMenu(root, self.encryption_choice, "AES", "ChaCha20")
        self.method_dropdown.pack(pady=5)

        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.pack(pady=5)

        self.send_button = tk.Button(root, text="Send Message", command=self.send_message)
        self.send_button.pack(pady=5)

        self.log_area = ScrolledText(root, width=60, height=20)
        self.log_area.pack(pady=5)

        # Open the log file in append mode
        self.encrypted_log_file = open("client_encrypted_messages.txt", "a")

    def log(self, message):
        self.log_area.insert(tk.END, f"{message}\n")
        self.log_area.see(tk.END)

    def connect_to_server(self):
        host = '127.0.0.1'
        port = 65432
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        self.log("Connected to server.")

    def send_message(self):
        if not self.client_socket:
            self.connect_to_server()

        message = self.message_entry.get()
        if not message:
            self.log("Message cannot be empty!")
            return

        self.message_entry.delete(0, tk.END)

        encryption_choice = self.encryption_choice.get().lower()
        if encryption_choice == "aes":
            key = os.urandom(32)
            iv = os.urandom(16)
            ciphertext = self.encrypt_message_aes(message.encode(), key, iv)
            payload = iv + ciphertext
        else:
            key = os.urandom(32)
            nonce = os.urandom(12)
            ciphertext = self.encrypt_message_chacha20(message.encode(), key, nonce)
            payload = nonce + ciphertext

        with open("server_public_key.pem", "rb") as key_file:
            public_key = load_pem_public_key(key_file.read(), backend=default_backend())
        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Log encrypted message
        self.encrypted_log_file.write(f"Encrypted Message Sent: {payload.hex()}\n")
        self.encrypted_log_file.flush()

        self.client_socket.sendall(len(encrypted_key).to_bytes(4, 'big'))
        self.client_socket.sendall(encrypted_key)
        self.client_socket.sendall(payload)

        self.log(f"Sent ({encryption_choice.upper()}): {message}")

    @staticmethod
    def encrypt_message_aes(message, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(message) + encryptor.finalize()

    @staticmethod
    def encrypt_message_chacha20(message, key, nonce):
        chacha = ChaCha20Poly1305(key)
        return chacha.encrypt(nonce, message, None)

    def __del__(self):
        # Ensure the log file is closed when the program exits
        if self.encrypted_log_file:
            self.encrypted_log_file.close()


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
