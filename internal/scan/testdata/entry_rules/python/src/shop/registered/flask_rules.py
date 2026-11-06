import hashlib

from flask import Blueprint, Flask

app = Flask(__name__)
admin = Blueprint("admin", __name__)


class Registry:
    """An application object with a method named like Flask's."""

    def add_url_rule(self, rule, endpoint=None, view_func=None):
        pass


registry = Registry()


def fingerprint():
    return hashlib.sha1(b"view_func").hexdigest()


def rotate():
    return hashlib.sha256(b"positional").hexdigest()


def audit():
    return hashlib.md5(b"not flask").hexdigest()


def unused():
    return hashlib.sha512(b"helper").hexdigest()


app.add_url_rule("/fingerprint", view_func=fingerprint)
admin.add_url_rule("/rotate", "rotate", rotate, methods=["POST"])
registry.add_url_rule("/audit", view_func=audit)
