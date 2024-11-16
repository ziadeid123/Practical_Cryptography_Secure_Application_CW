# Practical_Cryptography_Secure_Application_CW
This is a secure chat application, which will aim to demonstrate the encrypted communication of a client with a server. The application will make use of symmetric encryption, either AES or ChaCha20, to encrypt the messages; for the symmetric key exchange, it will safely use public-key cryptography, RSA.

**Features**
Symmetric Encryption Options: Messages can be encrypted using either AES (Advanced Encryption Standard) or ChaCha20-Poly1305.
Public-Key Cryptography: RSA is used to exchange symmetric encryption keys securely.
GUI for Client and Server: Both the client and server have a user-friendly graphical interface built using Tkinter.
(Real-time Logging): Encrypted messages sent from the client and received by the server are logged in real time to separate text files for debugging and auditing.

**Prerequisites**
Python 3.11 or higher.
***Required Python libraries***:
|cryptography|
|tkinter|
You can install the necessary libraries using pip:
[pip install cryptography]
Tkinter is included by default in most Python installations.

**Files in the Repository**
generate_keys.py: Script to generate RSA public and private keys.
server.py: Server-side application with GUI.
client.py: Client-side application with GUI.
README.md: This file, which explains the functionality and setup of the project.

**How the Application Works**
(Key Generation):
RSA public and private keys are generated using the generate_keys.py script.
The server makes use of the private key to decrypt symmetric keys sent by the client.
The client also uses the public key to encrypt the symmetric key before sending it to the server.

Encryption:
Messages are encrypted on the client side using either AES or ChaCha20.
The encrypted message and symmetric key are sent to the server.

Decryption:
The server decrypts the symmetric key using its RSA private key.
The server then decrypts the received message using the symmetric key.

Logging:
Both the client and server log the encrypted messages into respective files:
client_encrypted_messages.txt: Stores encrypted messages sent by the client.
server_encrypted_messages.txt: Stores encrypted messages received by the server.

**How to Run**
Step 1: Generate RSA Keys
Run the generate_keys.py script to create RSA public and private keys:
[python3 generate_keys.py]
This will generate two files in the current directory:
server_private_key.pem
server_public_key.pem

Step 2: Start the Server
Run the server.py script to start the server:
[python3 server.py]
The server GUI will launch. Click the Start Server button to begin awaiting connection from the client end.

Step 3: Start the Client
Run the client.py script to start the client:
[python3 client.py]
The client GUI will launch. Use the dropdown menu to select the encryption method (AES or ChaCha20), type a message, and click Send Message.

Step 4: Check Logs
Encrypted messages are logged in the following files:
Client: client_encrypted_messages.txt
Server: server_encrypted_messages.txt

**How to Use**
Server Setup:
Start the server application.
Wait for the client to connect.

Client Messaging:
Open the client application.
Select the encryption method (AES or ChaCha20) from the dropdown menu.
Enter a message in the input field and click Send Message.
The client will encrypt the message, send it to the server, and log the encrypted message.

Server Logging:
The server receives the encrypted message, decrypts it, and logs both the encrypted and decrypted messages in real time in a txt file on your pc.

