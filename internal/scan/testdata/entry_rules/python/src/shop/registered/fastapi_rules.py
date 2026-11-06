import hashlib

from fastapi import APIRouter, FastAPI

api = FastAPI()
router = APIRouter()


def fingerprint():
    return hashlib.sha1(b"add_api_route").hexdigest()


async def sign():
    return hashlib.sha256(b"endpoint").hexdigest()


async def stream(websocket):
    return hashlib.sha384(b"websocket").hexdigest()


api.add_api_route("/fingerprint", fingerprint, methods=["GET"])
router.add_api_route("/sign", endpoint=sign, methods=["POST"])
api.add_api_websocket_route("/stream", stream)
