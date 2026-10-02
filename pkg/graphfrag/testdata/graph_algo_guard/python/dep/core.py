import hashlib
import hmac


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Signer:
    def __init__(self, key):
        self.key = key

    def sign(self, data):
        mac = hmac.new(self.key, data, hashlib.sha256)
        return mac.digest()

    def verify(self, data, tag):
        return hmac.compare_digest(self.sign(data), tag)
