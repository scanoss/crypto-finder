"""Visit-budget fixture: module-level constants."""

KEY_LEN = 32
ITERATIONS = 100000


def build_kdf(password, salt):
    return PBKDF2HMAC(algorithm=SHA256(), length=KEY_LEN, salt=salt, iterations=ITERATIONS)
