import hashlib

import reachlib


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def legacy(data):
    return hashlib.md5(data).hexdigest()


def main():
    data = b"payload"
    print(fingerprint(data))
    print(reachlib.digest(data))


if __name__ == "__main__":
    main()
