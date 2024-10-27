import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Helper function to decrypt AES-encrypted message
def decrypt_message_aes(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Helper function to decrypt ChaCha20-encrypted message
def decrypt_message_chacha20(ciphertext, key, nonce):
    chacha = ChaCha20Poly1305(key)
    plaintext = chacha.decrypt(nonce, ciphertext, None)
    return plaintext

# Server code to listen to client communication
def server_program():
    host = '127.0.0.1'
    port = 65432

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server listening on port:", port)

    conn, address = server_socket.accept()
    print("Connection from:", address)
    
    # Load server's private key to decrypt symmetric key
    with open("server_private_key.pem", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    # Open a file to append decrypted messages; will keep appending new messages if file exists
    with open("decrypted_messages.txt", "a") as f:
        while True:
            try:
                # First, receive the size of the encrypted symmetric key
                symmetric_key_size = int.from_bytes(conn.recv(4), 'big')

                # Then receive the encrypted symmetric key
                encrypted_symmetric_key = conn.recv(symmetric_key_size)

                # Decrypt symmetric key using server's private key
                symmetric_key = private_key.decrypt(
                    encrypted_symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Now receive the encrypted message
                encrypted_message = conn.recv(1024)

                # Display the encrypted message (hex format)
                print("Encrypted message (hex):", encrypted_message.hex())

                # Determine if the encryption used AES or ChaCha20
                if len(encrypted_message) >= 28:  # 16 bytes for IV (AES) or 12 bytes for nonce (ChaCha20)
                    iv_or_nonce = encrypted_message[:16]  # Try AES first
                    ciphertext = encrypted_message[16:]

                    try:
                        decrypted_message = decrypt_message_aes(ciphertext, symmetric_key, iv_or_nonce)
                        # Log the decrypted message to the file
                        f.write(f"AES: {decrypted_message.decode()}\n")
                        f.flush()  # Ensure it's written to file immediately
                    except Exception:
                        # If AES decryption fails, try ChaCha20
                        iv_or_nonce = encrypted_message[:12]  # 12-byte nonce for ChaCha20
                        ciphertext = encrypted_message[12:]
                        decrypted_message = decrypt_message_chacha20(ciphertext, symmetric_key, iv_or_nonce)
                        # Log the decrypted message to the file
                        f.write(f"ChaCha20: {decrypted_message.decode()}\n")
                        f.flush()  # Ensure it's written to file immediately

            except Exception as e:
                print(f"Decryption error: {e}")
                break

    conn.close()

if __name__ == '__main__':
    server_program()
