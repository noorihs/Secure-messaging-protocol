# Secure-messaging-protocol
# Secure Messaging Protocol

## Overview
This project implements a secure messaging protocol using RSA for key exchange and AES for encrypted communication. The server generates an RSA key pair, shares its public key with the client, and then decrypts an AES key sent by the client. The actual message exchange between the server and the client is encrypted using AES in ECB mode.

## Features
- **RSA Key Exchange:** The server generates a pair of RSA keys (private and public). The public key is shared with the client for secure AES key transmission.
- **AES Encryption (ECB Mode):** Messages exchanged between the server and client are encrypted using AES.
- **Encrypted Communication:** Ensures that messages are transmitted securely and decrypted correctly on both ends.

## Requirements
Make sure you have the following installed:
- Python 3.x
- Required libraries:
  ```bash
  pip install cryptography pycryptodome
  ```

## How It Works
1. **Server Setup:**
   - The server generates an RSA key pair.
   - It shares the public key with the client.
   - It listens for an encrypted AES key from the client.
   - Once received, it decrypts the AES key using its private RSA key.
   
2. **Message Exchange:**
   - The server waits for an encrypted message from the client.
   - Messages are decrypted using AES in ECB mode.
   - The server can also send encrypted messages back to the client.
   - The communication continues until a termination keyword (e.g., "thanks") is received.

## How to Run the Server
1. Open a terminal and execute the server script:
   ```bash
   python server.py
   ```
2. Before running, make sure to enter the correct IP address and port in the designated places in the script.
3. The server will wait for a connection from the client.
4. It will share its RSA public key and decrypt the received AES key.
5. Messages can then be exchanged securely.

## How to Run the Client
Once the client-side script is implemented, you can run it as follows:
```bash
python client.py
```
The client should:
- Generate an AES key.
- Encrypt and send the AES key using the server’s public RSA key.
- Encrypt messages using AES in ECB mode before sending them to the server.
- Decrypt received messages from the server.
- Before running, make sure to enter the correct IP address and port in the designated places in the script.

## Notes
- Ensure that the client and server are using the same IP address and port for communication.
- ECB mode in AES is used here for simplicity but is not recommended for production use due to security vulnerabilities. Consider using CBC or GCM for better security.

## Future Improvements
- Implement AES-GCM mode for better security.
- Add authentication mechanisms to prevent man-in-the-middle attacks.
- Handle larger messages efficiently with padding and chunking techniques.

