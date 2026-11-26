import hashlib

try:
    import hmac

    HAS_HMAC = True
except ImportError:
    HAS_HMAC = False


class Base:
    def __init__(self):
        self.seed = hashlib.sha256()

    def run(self, data):
        return self.step(data)

    def step(self, data):
        return hashlib.sha1(data).digest()

    def __eq__(self, other):
        return self.run(b"") == other.run(b"")

    @classmethod
    def create(cls):
        return cls()

    class Options:
        def digest(self, data):
            return hashlib.md5(data).hexdigest()


class Fast(Base):
    def __init__(self):
        super().__init__()

    def step(self, data):
        return hashlib.blake2b(data).digest()


if HAS_HMAC:

    class Keyed(Base):
        def __init__(self):
            super().__init__()

        def step(self, data):
            return hmac.new(
                b"k",  # key, "fixed"
                data,
                hashlib.sha256,
            ).digest()
