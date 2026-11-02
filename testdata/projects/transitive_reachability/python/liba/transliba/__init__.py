"""A direct dependency with no hashing of its own."""

import translibb


def used(data):
    return translibb.used_hash(data)


def unused(data):
    return translibb.unused_hash(data)
