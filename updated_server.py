import pickle
import socket
import string
import threading
import os
import random
from AES import AESEncryption  # Ensure this class is defined in a separate file

class Server:
    def __init__(self, port=8080):
        self.host = '127.0.0.1'
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.clients = []
        print(f"Server listening on {self.host}:{self.port}")
        self.characters = string.ascii_letters + string.digits  # a-zA-Z0-9

    def broadcast(self, message, source_client):
        for client in self.clients:
            if client != source_client:
                try:
                    # Encrypt the message with the receiving client's encryption object
                    encryption_object = self.clients[client]  # Assuming you store encryption objects in a dictionary
                    encrypted_message = encryption_object.encrypt(message)
                    client.sendall(len(encrypted_message).to_bytes(4, byteorder='big') + encrypted_message)
                except Exception as e:
                    print(f"Error broadcasting to client: {e}")

    def handle_client(self, client_socket, address):
        print(f"Connection from {address}")
        self.clients.append(client_socket)

        # Wait for the 'P' message type for password setup
        message_type = client_socket.recv(1).decode()
        if message_type != 'P':
            print(f"Invalid message type from {address}")
            client_socket.close()
            return
        # Generate and send salt for password setup
        salt = os.urandom(16)
        client_socket.sendall(len(salt).to_bytes(4, byteorder='big') + salt)
        # Receive encryption object from client
        encryption_object_bytes = client_socket.recv(4096)
        encryption_object = pickle.loads(encryption_object_bytes)
        message_count = 0
        while True:
            try:
                message_length_bytes = client_socket.recv(4)
                if not message_length_bytes:
                    break

                message_length = int.from_bytes(message_length_bytes, byteorder='big')
                encrypted_message = client_socket.recv(message_length)
                decrypted_message = encryption_object.decrypt(encrypted_message)
                message_count += 1
                if message_count >= 5:
                    # Key update logic
                    message_count = 0
                    password = ''.join(random.choice(self.characters) for _ in range(16))
                    salt = os.urandom(16)
                    encryption_object = AESEncryption(password, salt)  # Create a new encryption object
                    # Send the key update signal and new encryption object
                    client_socket.sendall(b'U')
                    encrypted_object_bytes = pickle.dumps(encryption_object)
                    client_socket.sendall(
                        len(encrypted_object_bytes).to_bytes(4, byteorder='big') + encrypted_object_bytes)
                else:
                    client_socket.sendall(b'M')  # 'U' for update
                parts = decrypted_message.split(' - ', 1)
                print(parts)
                if len(parts) == 2:
                    print(f"Message from {address}: {parts[0]}")
                if len(decrypted_message.strip()) > 0:  # Ignore empty messages
                    encrypted_message_for_broadcast = encryption_object.encrypt(decrypted_message)
                    client_socket.sendall(
                        len(encrypted_message_for_broadcast).to_bytes(4,
                                                                      byteorder='big') + encrypted_message_for_broadcast)
            except Exception as e:
                print(f"Error handling client {address}: {e}")
                break

        client_socket.close()
        self.clients.remove(client_socket)
        print(f"Client {address} disconnected")

    def start(self):
        print("Server started. Waiting for connections...")
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()
            except Exception as e:
                print(f"Error accepting connections: {e}")

if __name__ == "__main__":
    server = Server()
    server.start()
