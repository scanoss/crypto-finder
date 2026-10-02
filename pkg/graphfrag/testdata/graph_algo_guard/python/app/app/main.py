from signer import Signer
from signer.core import digest


class Service:
    def __init__(self, key):
        self.signer = Signer(key)

    def handle(self, payload):
        tag = self.signer.sign(payload)
        return digest(payload + tag)


def main():
    svc = Service(b"key")
    print(svc.handle(b"data"))


if __name__ == "__main__":
    main()
