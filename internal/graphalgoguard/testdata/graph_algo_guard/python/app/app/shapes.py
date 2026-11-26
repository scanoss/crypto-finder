import typing
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from signer.shapes import Base, Fast


def tracked_dependency(data):
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def tracked_keywords(key, nonce, data):
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data, associated_data=b"aad")


def tracked_own(data):
    fast = Fast()
    return fast.run(data)


def duck(sink, data):
    sink.write(data)
    sink.writelines(line for line, _ in data)
    return sink.flush()


def callback(fn, data):
    return fn(data)


def class_object(data):
    return Base.create().run(data)


def build():
    return Base()


def token(user):
    return base64.b64encode(user.encode()).decode("utf-8").replace("\n", "")


class Holder:
    def __init__(self, base: Base):
        self.base = base
        self.fast = Fast()

    def go(self, data):
        self.fast.run(data)
        return self.base.step(data)


class Local:
    def ping(self):
        return 1


def make_local() -> Local:
    return Local()


def annotated(local: Local, data: bytes):
    local.ping()
    made = make_local()
    made.ping()
    return data.hex()


class Quiet(Local):
    pass


def methodless():
    quiet = Quiet()
    return quiet.ping()


class Wiring:
    local: Local

    def __init__(self, holder: Holder, thing):
        self.inner = holder.fast
        self.casted = typing.cast(Local, thing)

    def go(self, data):
        self.local.ping()
        self.casted.ping()
        return self.inner.run(data)


def rebinding(data, flag):
    h = hashes.Hash(hashes.SHA256())
    if flag:
        h = hashes.Hash(hashes.SHA512())
    h.update(data)
    h = None
    return h


def displays(data):
    algs = ["HS256", "HS384"]
    pair = ("RSA-OAEP", "A256GCM")
    return hashes.Hash(algs, pair, data)


def unpacked(data):
    private, public = ec.generate_private_key(ec.SECP256R1()), None
    first, second = build()
    return second.sign(data)


def rebound_parameter(key, flag):
    if flag:
        key = None
    return key
