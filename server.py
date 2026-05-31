import hashlib
import logging
import socket
import json
from cProfile import label

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

TTP_HOST = "127.0.0.1"
TTP_PORT = 9000

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000

actual_server_id = "server1"

server_id = hashlib.sha256(actual_server_id.encode()).hexdigest()

# logs

logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s: %(message)s"
)


private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

public_key = private_key.public_key()

public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

certificate = None
session_key = None


def register():

    global certificate

    msg = {
        "type": "register_server",
        "id": server_id,
        "public_key": public_pem.decode()
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((TTP_HOST, TTP_PORT))
        s.send(json.dumps(msg).encode())

        response =json.loads(s.recv(16384).decode())
        certificate = response["certificate"]

        print("Registered in TTP:", s.recv(1024))

        logging.info("Server registered...")


def start_server():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()

        print("Server running...")

        while True:
            conn, addr = s.accept()

            data = conn.recv(4096)

            print("Received:", data.decode())

            conn.send(b"Hello world!")

            conn.close()


register()
start_server()