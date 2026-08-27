"""Visit-budget fixture: super()."""


class BaseCipher:
    def __init__(self, key):
        self.key = key


class AesCipher(BaseCipher):
    def __init__(self, key, mode):
        super().__init__(key)
        self.mode = mode

    def encrypt(self, data):
        return super().transform(data)
