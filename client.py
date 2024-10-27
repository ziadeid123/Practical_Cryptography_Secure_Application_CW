import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Helper function to generate a key for AES encryption
def generate_aes_key(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password)

# Helper function to encrypt a message with AES
def encrypt_message_aes(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message) + encryptor.finalize()

# Helper function to encrypt a message with ChaCha20-Poly1305
def encrypt_message_chacha20(message, key, nonce):
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, message, None)
    return ciphertext

# Client code to send encrypted message to server
def client_program():
    host = '127.0.0.1'
    port = 65432

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    # Load server's public key to encrypt AES/ChaCha20 key
    with open("server_public_key.pem", "rb") as key_file:
        public_key = load_pem_public_key(key_file.read(), backend=default_backend())

    # Ask user to choose encryption method
    encryption_choice = input("Choose encryption method (AES or ChaCha20): ").strip().lower()

    if encryption_choice not in ['aes', 'chacha20']:
        print("Invalid choice! Defaulting to AES.")
        encryption_choice = 'aes'

    # Generate symmetric key based on user's choice
    if encryption_choice == 'aes':
        password = b'my_secure_password'
        salt = os.urandom(16)
        symmetric_key = generate_aes_key(password, salt)
    elif encryption_choice == 'chacha20':
        symmetric_key = os.urandom(32)  # ChaCha20 uses a 256-bit key

    while True:
        # Get user input to send
        message = input("Enter a message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            print("Exiting the program.")
            break

        # Convert the message to bytes
        message = message.encode()

        # Encrypt the message using the chosen encryption method
        if encryption_choice == 'aes':
            iv = os.urandom(16)
            ciphertext = encrypt_message_aes(message, symmetric_key, iv)
        elif encryption_choice == 'chacha20':
            nonce = os.urandom(12)  # ChaCha20 uses a 12-byte nonce
            ciphertext = encrypt_message_chacha20(message, symmetric_key, nonce)

        # Encrypt symmetric key with server's public key
        try:
            encrypted_symmetric_key = public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"Encryption error: {e}")
            continue

        # Send the encrypted symmetric key, and message (with IV/nonce if necessary)
        client_socket.sendall(len(encrypted_symmetric_key).to_bytes(4, 'big'))  # Send key size
        client_socket.sendall(encrypted_symmetric_key)  # Send encrypted key
        
        if encryption_choice == 'aes':
            client_socket.sendall(iv + ciphertext)  # Send IV and ciphertext for AES
        elif encryption_choice == 'chacha20':
            client_socket.sendall(nonce + ciphertext)  # Send nonce and ciphertext for ChaCha20

    client_socket.close()

if __name__ == '__main__':
    client_program()
