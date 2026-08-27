"""Visit-budget fixture: comprehensions (list/set/dict/generator)."""


def hash_all(items):
    digests = [hashlib.sha256(item).hexdigest() for item in items]
    unique = {hashlib.md5(item).digest() for item in items}
    mapping = {item: hashlib.sha1(item).digest() for item in items}
    lazy = (hashlib.sha256(item).digest() for item in items)
    return digests, unique, mapping, list(lazy)
