import hashlib
def compute(value):
    return hashlib.sha256(value).hexdigest()
