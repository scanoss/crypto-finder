"""Visit-budget fixture: keyword arguments."""


def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(password)
