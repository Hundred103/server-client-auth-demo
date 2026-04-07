import json
import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

HOST = "0.0.0.0"
PORT = 9000

users = {}
servers = {}

private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

public_key = private_key.public_key()

# konwersja do formatu PEM aby móc przesłać przez sieć

public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def handlde_client(conn):
    data = conn.recv(4096)
    msg = json.loads(data.decode())

    if msg["type"] == "register_user":
        users[msg["id"]] = msg["public_key"]
        print("User registered:", msg["id"])
        conn.send(b"OK")

    elif msg["type"] == "register_server":
        servers[msg["id"]] = msg["public_key"]
        print("Server registered:", msg["id"])
        conn.send(b"OK")
    conn.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    print("TTP running...")

    while True:
        conn, addr = s.accept()
        handlde_client(conn)
