"""Visit-budget fixture: parameter/return type annotations."""

from typing import Optional


def encrypt(data: bytes, cipher: Optional["Cipher"] = None) -> bytes:
    active: Cipher = cipher or default_cipher()
    return active.encrypt(data)
