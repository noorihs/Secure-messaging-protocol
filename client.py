#socket
import socket

# Création du socket (IPv4, TCP)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connexion au serveur
client_socket.connect(("192.168.100.208",12346))

# Recevoir un message du serveur

# Envoyer un message
client_socket.send(b"Bonjour serveur !")



message = client_socket.recv(1024).decode()
print(f"Message du serveur: {message}")

# Fermer la connexion
client_socket.close()
