import hashlib

from flask import Flask

app = Flask(__name__)


@app.route("/digest")
def digest():
    return hashlib.sha1(b"flask").hexdigest()
