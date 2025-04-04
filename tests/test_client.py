import socket
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import struct

with open("keys/client_01_key.pem", "rb") as f:
    client_priv = x25519.X25519PrivateKey.from_private_bytes(
        serialization.load_pem_private_key(f.read(), password=None).private_bytes_raw()
    )
client_pub = client_priv.public_key().public_bytes_raw()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
sock.connect(("localhost", 12345))

sock.sendall(client_pub)
server_pub = sock.recv(32)

shared_secret = client_priv.exchange(x25519.X25519PublicKey.from_public_bytes(server_pub))
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=server_pub,
    info=b"test_server"
)
session_key = hkdf.derive(shared_secret)
print(f"Client session key: {session_key[:8].hex()}...")

message = b"Hello from client"
nonce = os.urandom(12)
cipher = ChaCha20Poly1305(session_key)
ciphertext = cipher.encrypt(nonce, message, None)
msg = struct.pack(">I", 4 + len(nonce) + len(ciphertext)) + nonce + ciphertext
print(f"Preparing message, length: {len(msg)}, raw: {msg.hex()}")
sock.sendall(msg)
print(f"Sent message: {len(msg)} bytes")

length_data = b""
while len(length_data) < 4:
    chunk = sock.recv(4 - len(length_data))
    if not chunk:
        print("Server closed connection early")
        break
    length_data += chunk
    print(f"Received length chunk: {len(chunk)} bytes, raw: {chunk.hex()}")
print(f"Received length data: {len(length_data)} bytes, raw: {length_data.hex()}")
total_len = struct.unpack(">I", length_data)[0]
payload_len = total_len - 4  # Expect payload after length prefix
print(f"Expected payload length: {payload_len}")

resp_data = b""
while len(resp_data) < payload_len:
    chunk = sock.recv(payload_len - len(resp_data))
    if not chunk:
        print("Server closed connection early during response")
        break
    resp_data += chunk
    print(f"Received response chunk: {len(chunk)} bytes, raw: {chunk.hex()}")
print(f"Received response data: {len(resp_data)} bytes")
nonce = resp_data[:12]
ciphertext = resp_data[12:]
plaintext = cipher.decrypt(nonce, ciphertext, None)
print(f"Client received: {plaintext.decode()}")

sock.close()