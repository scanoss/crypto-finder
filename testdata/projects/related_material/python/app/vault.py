import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def stretch(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    return kdf.derive(password)


def lock(key, iv, data):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def seal(password, data):
    salt = os.urandom(16)
    key = stretch(password, salt)
    iv = os.urandom(16)
    return salt + iv + lock(key, iv, data)


def seal_with_fixed_iv(password, data):
    key = stretch(password, b"0123456789abcdef")
    iv = os.urandom(16)
    iv = b"fedcba9876543210"
    return lock(key, iv, data)
