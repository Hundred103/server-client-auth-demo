import hashlib
import logging
import socket
import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TTP_HOST = "ttp"
TTP_PORT = 9000

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000

server_id = "server1"

hash_server_id = hashlib.sha256(server_id.encode()).hexdigest()

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
        "id": hash_server_id,
        "public_key": public_pem.decode()
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((TTP_HOST, TTP_PORT))
        s.send(json.dumps(msg).encode())

        response =json.loads(s.recv(16384).decode())
        certificate = response["certificate"]

        print("Registered in TTP:", s.recv(1024))

        logging.info("Server registered...")

def request_session_key():
    global session_key

    msg={
        "type": "request_session_key",
        "user_id": hashlib.sha256("user1".encode()).hexdigest(),
        "server_id": hash_server_id
        }

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.connect((TTP_HOST,TTP_PORT))
        s.send((json.dumps(msg).encode()))

        response = json.loads(s.recv(16384).decode())
        encrypted_key = bytes.fromhex(response["server_key"])
        session_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    logging.info("Session key received")


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()

        print("Server running...")

        while True:
            conn, addr = s.accept()
            print(f"Client {addr}")

            try:
                request_session_key()

                nonce = conn.recv(12)

                cipher = conn.recv(4096)

                aesgcm = AESGCM(session_key)

                plain = aesgcm.decrypt(nonce,cipher,None)

                print("Received:", plain.decode())
                logging.info(f"Message recieved: {plain.decode()}")

                conn.send(b"OK")

            except Exception as e:
                print(f"Error processing request: {e}")
                conn.send(b"ERROR")

            finally:
                conn.close()


register()
start_server()