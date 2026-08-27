"""Visit-budget fixture: decorators (staticmethod/classmethod/property/custom)."""


class KeyStore:
    @staticmethod
    def generate(size):
        return os.urandom(size)

    @classmethod
    def from_env(cls, name):
        return cls(os.environ[name])

    @property
    def fingerprint(self):
        return hashlib.sha256(self._key).hexdigest()

    @app.route("/keys")
    def list_keys(self):
        return self._keys
