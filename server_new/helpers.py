import hashlib
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import io

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def stop_server(err):
    """ Print err and stop script execution """
    print(f"Fatal Error due to: {err}")
    exit(1)


def parse_port(file_path):
    """ Parse port.info for port number. On any failure, None will be returned. """
    port = None
    try:
        with open(file_path, "r") as info:
            port = info.readline().strip()
            port = int(port)
    except (ValueError, FileNotFoundError):
        port = None
    return port


def generate_aes_key():
    """ Generating AES key. """
    key = secrets.token_bytes(16)
    return key


def encrypt_aes_key(aes_key, public_key_str):
    # Load the public key from a string
    public_key = serialization.load_pem_public_key(
        public_key_str.encode(),
        backend=default_backend()
    )

    # Encrypt the AES key with the public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_aes_key


def decrypt_file_content(encrypted_content, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()
    return decrypted_content


def save_to_ram(file_content, file_name):
    in_memory_file = io.BytesIO(file_content)
    file_path = f'/tmp/{file_name}'
    with open(file_path, 'wb') as f:
        f.write(in_memory_file.read())
    return file_path
