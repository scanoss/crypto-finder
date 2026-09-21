import hashlib
def compute(value):
    h=hashlib.sha256()
    h.update(value)
    return h.digest()
