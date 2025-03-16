#protocole de messagerie sécurisé ( coté serveur)

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Création du socket serveur
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(( """ip_adress""","""port""" ))  
server_socket.listen(1)
print("Serveur en attente d'une connexion...")

# Génération de la paire de clés RSA du serveur
private_key = rsa.generate_private_key(
public_exponent=65537,
key_size=2048,
backend=default_backend()
)

public_key = private_key.public_key()

# Conversion en PEM
public_key_pem = public_key.public_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Clé privée RSA :\n")
print(private_key.private_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PrivateFormat.PKCS8,
encryption_algorithm=serialization.NoEncryption()
).decode())

print("\nClé publique RSA :\n")
print(public_key_pem.decode())

# Accepter la connexion du client
conn, addr = server_socket.accept()
print(f"Connexion acceptée depuis {addr}")

try:
        # Envoyer la clé publique au client
        print("LEN Clé publique ",len(public_key_pem))
        conn.send(public_key_pem)
        print("Clé publique envoyée au client.")

        # Recevoir le message chiffré du client
        key_aes_ch = conn.recv(1024)  
        print(f"Message chiffré reçu : {len(key_aes_ch)} ,  {key_aes_ch}")

        # Déchiffrer le message avec la clé privée du serveur
        key_aes = private_key.decrypt(
        key_aes_ch,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        )

        # Affichage du message déchiffré
        print("Message déchiffré :", len(key_aes),key_aes)

        #envoie d'un message en utilisant la méthode ecb avec la clé que j'ai reçu
        while 1:

            ciphertext_ecb = conn.recv(1024)  # Taille maximale de la clé publique
            print(ciphertext_ecb)
            decipher_ecb = AES.new(key_aes, AES.MODE_ECB)
            decrypted_ecb = decipher_ecb.decrypt(ciphertext_ecb)
            print("Déchiffrement ECB :", decrypted_ecb)
            if  decrypted_ecb.startswith(b"thanks"):
                print("discussion terminée")
                break

            plaintext = input("enter a text: ")
            cipher_ecb = AES.new(key_aes, AES.MODE_ECB)
            ciphertext_ecb = cipher_ecb.encrypt(pad(plaintext.encode(), AES.block_size))
            print("Chiffrement ECB :", ciphertext_ecb)
            conn.send(ciphertext_ecb)
            if plaintext.startswith("thanks"):
                print("discussion terminée")
                break
except Exception as e:
        print(f"Erreur lors de la communication avec le client")

finally:
        # Fermeture de la connexion
        conn.close()
        server_socket.close()
        print("Connexion fermée, serveur arrêté.")








