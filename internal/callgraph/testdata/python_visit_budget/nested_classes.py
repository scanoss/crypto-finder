"""Visit-budget fixture: nested classes."""


class Vault:
    class Entry:
        def __init__(self, name, value):
            self.name = name
            self.value = value

        def seal(self):
            return hashlib.sha256(self.value).digest()

    def add(self, name, value):
        entry = Vault.Entry(name, value)
        return entry.seal()
