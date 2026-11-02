"""A transitive dependency that does the hashing."""

import hashlib


def used_hash(data):
    return hashlib.sha256(data).hexdigest()


def unused_hash(data):
    return hashlib.sha512(data).hexdigest()
