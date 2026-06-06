import hashlib
import socket
import json
from cProfile import label

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

TTP_HOST = "127.0.0.1"
TTP_PORT = 9000

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000

user_id = "user1"

hash_user_id = hashlib.sha256(user_id.encode()).hexdigest()

private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

public_key = private_key.public_key()

public_pem = public_key.public_bytes( encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)



certificate = None
session_key = None

def register():

    global certificate

    msg = {
        "type": "register_user",
        "id": hash_user_id,
        "public_key": public_pem.decode()
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((TTP_HOST, TTP_PORT))
        s.send(json.dumps(msg).encode())

        response = json.loads(s.recv(16384).decode())
        certificate = response["certificate"]

        print("Registered in TTP:", s.recv(1024))

def request_session_key():
    global session_key

    msg = {
        "type": "request_session_key",
        "user_id": hash_user_id,
        "server_id": hashlib.sha256("server1".encode()).hexdigest()
    }

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:

        s.connect((TTP_HOST,TTP_PORT))
        s.send(json.dumps(msg).encode())

        response = json.loads(s.recv(16384).decode())

        encrypted_key = bytes.fromhex(response["user_key"])

        session_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


def connect_server():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.connect((SERVER_HOST, SERVER_PORT))

        s.send(b"Hello server!")

        print("Server response:", s.recv(4096).decode())


register()
connect_server()