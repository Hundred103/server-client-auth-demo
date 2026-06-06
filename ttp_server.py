import json
import logging
import os
import socket
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = "0.0.0.0"
PORT = 9000

users = {}
servers = {}
session_keys = {}

# logging

logging.basicConfig(
    filename="ttp.log",
    level=logging.INFO,
    format="%(asctime)s: %(message)s"
)

# klucz

private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

public_key = private_key.public_key()

# konwersja do formatu PEM aby móc przesłać przez sieć

public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

# certyfikat

def generate_certificate(entity_id, public_key):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, entity_id)])

    cert = (x509.CertificateBuilder().
            subject_name(subject).
            issuer_name(issuer).
            public_key(public_key).
            serial_number(x509.random_serial_number()).
            not_valid_before(datetime.now(timezone.utc)).
            not_valid_after(datetime.now(timezone.utc)+timedelta(days=365)).
            sign(private_key, hashes.SHA256())
            )

    return  cert.public_bytes(serialization.Encoding.PEM)

# client handler

def handle_client(conn):

    data = conn.recv(16384)
    msg = json.loads(data.decode())

    msg_type = msg["type"]

    # user register

    if msg_type == "register_user":

        user_id = msg["id"]

        public_key_obj = serialization.load_pem_public_key(
            msg["public_key"].encode()
        )

        cert = generate_certificate(user_id, public_key_obj)

        users[user_id] = {
            "public_key": msg["public_key"],
            "certificate": cert.decode()
        }

        logging.info(f"User registered: {user_id}")

        response = {
            "status": "OK",
            "certificate": cert.decode(),
            "ttp_public_key": public_pem.decode()
        }

        conn.send(json.dumps(response).encode())

    # server register

    elif msg_type == "register_server":

        server_id = msg["id"]

        public_key_obj = serialization.load_pem_public_key(
            msg["public_key"].encode()
        )

        cert = generate_certificate(server_id, public_key_obj)

        servers[server_id] = {
            "public_key": msg["public_key"],
            "certificate": cert.decode()
        }

        logging.info(f"Server registered: {server_id}")

        response = {
            "status": "OK",
            "certificate": cert.decode(),
            "ttp_public_key": public_pem.decode()
        }

        conn.send(json.dumps(response).encode())

    # session key request

    elif msg_type == "request_session_key":

        user_id = msg["user_id"]
        server_id = msg["server_id"]

        if user_id not in users or server_id not in servers:
            logging.warning(f"Session key denied: User {user_id} or Server {server_id} not registered yet.")
            conn.send(json.dumps({"error": "Not registered"}).encode())
            return

        session_lookup = f"{user_id}_{server_id}"
        if session_lookup in session_keys:
            session_key = session_keys[session_lookup]
        else:
            session_key = os.urandom(32)
            session_keys[session_lookup] = session_key

        user_public_key = serialization.load_pem_public_key(
            users[user_id]["public_key"].encode()
        )

        server_public_key = serialization.load_pem_public_key(
            servers[server_id]["public_key"].encode()
        )

        encrypted_for_user = user_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_for_server = server_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        response = {
            "user_key": encrypted_for_user.hex(),
            "server_key": encrypted_for_server.hex()
        }

        logging.info("Session key generated")

        conn.send(json.dumps(response).encode())

    conn.close()

# ===== MAIN =====

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    s.bind((HOST, PORT))
    s.listen()

    print("TTP running...")

    while True:

        conn, addr = s.accept()

        handle_client(conn)