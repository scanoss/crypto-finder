import abc
import hashlib
import ssl
from typing import Optional, Protocol, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ssl import CERT_NONE

TLS11 = ssl.PROTOCOL_TLSv1_1
DIGESTS = {"sha256": hashes.SHA256, "sha1": hashes.SHA1}


class Policy:
    MINIMUM = ssl.TLSVersion.TLSv1_2

    def accepts(self, version, mode):
        if version in (ssl.PROTOCOL_TLSv1, TLS11) or mode == CERT_NONE:
            return False
        match mode:
            case ssl.CERT_REQUIRED:
                return True
        return [hashes.SHA512]

    def modern(self):
        return self.MINIMUM == ssl.TLSVersion.TLSv1_2


def harden(ctx, strict):
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.options |= ssl.OP_NO_TLSv1
    name = "TLSv1_2"
    if strict:
        name = "TLSv1_3"
    ctx.minimum_version = name
    ctx.check_hostname = True
    return ctx.wrap(name)


class Store(Protocol):
    def load(self, raw):
        ...


class KeyStore(abc.ABC):
    default: Optional[rsa.RSAPrivateKey] = None

    @abc.abstractmethod
    def raw(self):
        """Bytes."""

    def key(self):
        k: rsa.RSAPrivateKey = cast(rsa.RSAPrivateKey, serialization.load_pem_private_key(self.raw(), None))
        return k


def digest(name, data):
    level = ssl.CERT_REQUIRED
    hashlib.new(level, TLS11)
    if name == "sha1":
        return hashlib.new(name, data)
    match name:
        case "sha256" | "sha512":
            return hashlib.new(name, data)
    local = {"a": "sha256", "b": "sha512"}
    picked = local[name]
    hashlib.new(picked, data)
    shared = {"a": "sha256"}
    register(shared)
    hashlib.new(shared["a"], data)
    return hashlib.new(name, DIGESTS["sha1"])


def supported(algorithm):
    return isinstance(
        algorithm,
        (
            hashes.SHA256,
            hashes.SHA512,
        ),
    )
