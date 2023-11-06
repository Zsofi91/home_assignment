import hashlib
import string
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


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
    key = ''.join(secrets.choice(string.hexdigits) for i in range(32))
    return bytes.fromhex(key)


def encrypt_aes_key(aes_key, public_key):
    encrypted_aes_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    return encrypted_aes_key


# def cksum(filename):
#     crc32 = 0
#     byte_count = 0
#
#     with open(filename, 'rb') as file:
#         while True:
#             chunk = file.read(1024)
#             if not chunk:
#                 break
#             crc32 = hashlib.crc32(chunk, crc32)
#             byte_count += len(chunk)
#
#     crc32 = crc32 & 0xFFFFFFFF  # Ensure the result is a 32-bit unsigned integer
#     return f'{crc32:08X} {byte_count} {filename}'


