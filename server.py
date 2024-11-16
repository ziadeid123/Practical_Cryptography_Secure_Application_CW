import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Server")
        self.server_socket = None
        self.conn = None
        self.running = False

        # GUI Elements
        self.start_button = tk.Button(root, text="Start Server", command=self.start_server)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.log_area = ScrolledText(root, width=60, height=20)
        self.log_area.pack(pady=5)

    def log(self, message):
        self.log_area.insert(tk.END, f"{message}\n")
        self.log_area.see(tk.END)

    def start_server(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.server_program, daemon=True).start()

    def stop_server(self):
        self.running = False
        if self.conn:
            self.conn.close()
        if self.server_socket:
            self.server_socket.close()
        self.log("Server stopped.")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def server_program(self):
        host = '127.0.0.1'
        port = 65432
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(1)
        self.log(f"Server listening on port {port}...")

        try:
            self.conn, address = self.server_socket.accept()
            self.log(f"Connection from: {address}")

            with open("server_private_key.pem", "rb") as key_file:
                private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

            while self.running:
                try:
                    symmetric_key_size = int.from_bytes(self.conn.recv(4), 'big')
                    encrypted_symmetric_key = self.conn.recv(symmetric_key_size)

                    symmetric_key = private_key.decrypt(
                        encrypted_symmetric_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    encrypted_message = self.conn.recv(1024)
                    iv_or_nonce = encrypted_message[:16]
                    ciphertext = encrypted_message[16:]

                    try:
                        decrypted_message = self.decrypt_message_aes(ciphertext, symmetric_key, iv_or_nonce)
                        self.log(f"AES Decrypted: {decrypted_message.decode()}")
                    except:
                        iv_or_nonce = encrypted_message[:12]
                        ciphertext = encrypted_message[12:]
                        decrypted_message = self.decrypt_message_chacha20(ciphertext, symmetric_key, iv_or_nonce)
                        self.log(f"ChaCha20 Decrypted: {decrypted_message.decode()}")

                except Exception as e:
                    self.log(f"Error: {e}")
                    break
        except Exception as e:
            self.log(f"Server error: {e}")

    @staticmethod
    def decrypt_message_aes(ciphertext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def decrypt_message_chacha20(ciphertext, key, nonce):
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ciphertext, None)


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
