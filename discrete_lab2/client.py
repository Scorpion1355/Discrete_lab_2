""" Client """

import socket
import threading
from rsa import generate_keys, encrypt, decrypt, hash_message, verify_integrity

class Client:
    """
    Handles client-side operations for connecting to the server, sending and receiving messages.
    """
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        """
        Initializes the client with server connection parameters and generates key pairs.
        """
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.public_key, self.private_key = generate_keys()
        self.server_public_key = None

    def init_connection(self):
        """
        Initializes the connection with the server and exchanges public keys.
        Starts threads for reading and writing messages.
        """
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: Could not connect to server:", e)
            return

        self.s.send(self.username.encode())
        server_key_data = self.s.recv(1024).decode().split(',')
        self.server_public_key = (int(server_key_data[0]), int(server_key_data[1]))
        self.s.send(f"{self.public_key[0]},{self.public_key[1]}".encode())
        threading.Thread(target=self.read_handler).start()
        threading.Thread(target=self.write_handler).start()

    def read_handler(self):
        """
        Reads and decrypts messages from the server, verifying their integrity.
        """
        while True:
            try:
                encrypted_data = b''
                while True:
                    byte = self.s.recv(1)
                    if byte == b'\n' or not byte:
                        break
                    encrypted_data += byte
                if not encrypted_data:
                    break
                encrypted_msg = [int(x) for x in encrypted_data.decode().split(',') if x]
                decrypted_msg = decrypt(encrypted_msg, self.private_key)
                received_hash = self.s.recv(64).decode()
                if not verify_integrity(decrypted_msg, received_hash):
                    print("Message integrity could be compromised!")
                print(decrypted_msg)
            except ConnectionResetError:
                print("Server closed the connection")
                break
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def write_handler(self):
        """
        Reads user input, encrypts the message, and sends it to the server along with its hash.
        """
        while True:
            try:
                message = input()
                if message.lower() == 'exit':
                    self.s.close()
                    break
                encrypted_msg = encrypt(message, self.server_public_key)
                encrypted_str = ','.join(map(str, encrypted_msg))
                self.s.send(encrypted_str.encode())
                self.s.send(hash_message(message).encode())
            except Exception:
                print("Connection to server lost")
                self.s.close()
                break

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, 'User')
    cl.init_connection()
