import hashlib


def rotate_keys():
    return hashlib.sha512(b"rotate").hexdigest()
