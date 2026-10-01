import hashlib


def settle():
    return hashlib.shake_128(b"main").hexdigest(16)


if __name__ == "__main__":
    settle()
