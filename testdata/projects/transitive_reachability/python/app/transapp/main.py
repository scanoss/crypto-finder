import hashlib

import transliba


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def legacy(data):
    return hashlib.md5(data).hexdigest()


def main():
    data = b"payload"
    print(fingerprint(data))
    print(transliba.used(data))


if __name__ == "__main__":
    main()
