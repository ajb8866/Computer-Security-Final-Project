import datetime
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from AES import AESEncryption  # Ensure this class is defined in a separate file
import pickle
import time


class ChatClient:
    def __init__(self, master):
        self.password_entry = None
        self.password_label = None
        self.encryption = None
        self.master = master
        self.master.title("Chat Client")
        self.socket = None
        self.server_host = '127.0.0.1'
        self.server_port = 8080
        self.setup_ui_components()

    def setup_ui_components(self):
        self.password_label = tk.Label(self.master, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.pack()

        self.connect_button = tk.Button(self.master, text="Connect", command=self.connect)
        self.connect_button.pack()

        self.messages = scrolledtext.ScrolledText(self.master, state='disabled')
        self.messages.pack()

        self.message_entry = tk.Entry(self.master)
        self.message_entry.pack()
        self.send_button = tk.Button(self.master, text="Send", command=self.send_message)
        self.send_button.pack()

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))

            # Send 'P' to indicate password setup
            self.socket.sendall(b'P')

            # Receive and process the salt
            salt_length = int.from_bytes(self.socket.recv(4), byteorder='big')
            salt = self.socket.recv(salt_length)
            password = self.password_entry.get()
            self.encryption = AESEncryption(password, salt)
            encrypted_object = pickle.dumps(self.encryption)
            self.socket.sendall(encrypted_object)
            threading.Thread(target=self.handle_server_response, daemon=True).start()
        except Exception as e:
            self.display_message(f"Connection error: {e}")

    def send_message(self):
        try:
            timestamp = time.time()
            message = self.message_entry.get()
            message = message + " - " + str(timestamp)
            encrypted_message = self.encryption.encrypt(message)
            message_byte = len(encrypted_message).to_bytes(4, byteorder='big')
            self.socket.sendall(message_byte + encrypted_message)
            self.display_message(f'Sent (encrypted): {encrypted_message}')
            self.message_entry.delete(0, 'end')
        except Exception as e:
            self.display_message(f"Error sending message: {e}")

    def handle_server_response(self):
        while True:
            try:
                message_type_bytes = self.socket.recv(1)
                if not message_type_bytes:
                    self.display_message("Server connection closed.")
                    break

                message_type = message_type_bytes.decode()

                if message_type == 'U':  # Update key signal
                    encryption_object_bytes_length = int.from_bytes(self.socket.recv(4), byteorder='big')
                    encryption_object_bytes = b''
                    while len(encryption_object_bytes) < encryption_object_bytes_length:
                        part = self.socket.recv(encryption_object_bytes_length - len(encryption_object_bytes))
                        if not part:
                            raise ConnectionError("Incomplete encryption object received.")
                        encryption_object_bytes += part
                    self.encryption = pickle.loads(encryption_object_bytes)
                    self.display_message("Encryption key updated.")
                    message_length_bytes = self.socket.recv(4)
                    message_length = int.from_bytes(message_length_bytes, byteorder='big')
                    encrypted_message = b''
                    while len(encrypted_message) < message_length:
                        part = self.socket.recv(message_length - len(encrypted_message))
                        if not part:
                            raise ConnectionError("Incomplete message received.")
                        encrypted_message += part

                    decrypted_message = self.encryption.decrypt(encrypted_message)
                    parts = decrypted_message.split(' - ', 1)
                    if len(parts) == 2:
                        self.master.after(0, lambda: self.display_message(f'Received: {parts[0]}'))

                    # Continue to the next iteration of the loop to handle further messages


                if message_type == 'M':  # Update key signal
                    message_length_bytes = self.socket.recv(4)
                    message_length = int.from_bytes(message_length_bytes, byteorder='big')
                    encrypted_message = b''
                    while len(encrypted_message) < message_length:
                        part = self.socket.recv(message_length - len(encrypted_message))
                        if not part:
                            raise ConnectionError("Incomplete message received.")
                        encrypted_message += part

                    decrypted_message = self.encryption.decrypt(encrypted_message)
                    parts = decrypted_message.split(' - ', 1)
                    if len(parts) == 2:
                        self.master.after(0, lambda: self.display_message(f'Received: {parts[0]}'))

            except ConnectionError as ce:
                self.master.after(0, lambda: self.display_message(f"Connection error: {ce}"))
                break
            except Exception as e:
                self.master.after(0, lambda: self.display_message(f"Error receiving message: {e}"))
                break

    def display_message(self, message):
        self.messages.configure(state='normal')
        self.messages.insert('end', f'{message}\n')
        self.messages.configure(state='disabled')


if __name__ == "__main__":
    root = tk.Tk()
    chat_client = ChatClient(root)
    root.mainloop()
