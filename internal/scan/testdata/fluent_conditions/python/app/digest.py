import hashlib


def fingerprint(data):
    return hashlib.new("sha256", data).hexdigest().encode("ascii")


if __name__ == "__main__":
    print(fingerprint(b"x"))
