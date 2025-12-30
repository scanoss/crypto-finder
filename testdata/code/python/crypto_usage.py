import secrets
import hmac
import hashlib

# Should trigger python.crypto.secrets.token-bytes
token = secrets.token_bytes(32)

# Should trigger python.crypto.hmac.new
h = hmac.new(b"secret_key", b"message", digestmod=hashlib.sha256)
