""" Server """

import socket
import threading

from rsa import generate_keys, encrypt, decrypt, hash_message, verify_integrity


class Server:
    """ Class for Server object """

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        self.client_keys = {}
        self.public_key, self.private_key = generate_keys()

    def start(self):
        """
        Main starting server code
        """
        print("Server started")

        self.s.bind((self.host, self.port))
        self.s.listen(100)

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} connected")
            self.username_lookup[c] = username
            self.clients.append(c)

            # send public key to the client
            c.send(f"{self.public_key[0]},{self.public_key[1]}".encode())

            # encrypt the secret with the clients public key
            client_key_data = c.recv(1024).decode().split(',')
            client_public_key = (int(client_key_data[0]), int(client_key_data[1]))
            self.client_keys[c] = client_public_key

            # send the encrypted secret to a client
            welcome_message = f"Welcome to the server, {username}!"
            encrypted_welcome = encrypt(welcome_message, client_public_key)
            encrypted_str = ','.join(map(str, encrypted_welcome))
            c.send(encrypted_str.encode() + b'\n')
            c.send(hash_message(welcome_message).encode())

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        """
        Send a message to all clients
        """

        for client in self.clients:

            # encrypt the message
            try:
                encrypted_msg = encrypt(msg, self.client_keys[client])
                encrypted_str = ','.join(map(str, encrypted_msg))

                client.send(encrypted_str.encode() + b'\n')
                client.send(hash_message(msg).encode())

            except Exception as e:
                print(f"Error broadcasting to a client: {e}")

    def handle_client(self, c: socket, addr): 
        """
        Handles receiving messages from a client and broadcasting them to others
        """
        try:
            while True:

                encrypted_data = b''
                while True:
                    byte = c.recv(1)
                    if byte == b'\n' or not byte:
                        break
                    encrypted_data += byte

                if not encrypted_data:
                    break

                encrypted_msg = [int(x) for x in encrypted_data.decode().split(',') if x]

                received_hash = c.recv(128).decode()

                decrypted_msg = decrypt(encrypted_msg, self.private_key)

                if not verify_integrity(decrypted_msg, received_hash):
                    print("Message integrity failed")
                    continue

                username = self.username_lookup[c]
                formatted_msg = f"{username}: {decrypted_msg}"
                print(formatted_msg)

                self.broadcast(formatted_msg)

        except ConnectionResetError:
            print(f"Connectionm failed")

        except Exception as e:
            print(f"Error receiving message: {e}")

if __name__ == "__main__":
    s = Server(9001)
    s.start()
