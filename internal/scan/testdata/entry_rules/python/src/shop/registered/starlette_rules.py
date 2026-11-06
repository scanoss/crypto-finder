import hashlib

from starlette.applications import Starlette
from starlette.routing import Router

app = Starlette()
router = Router()


async def homepage(request):
    return hashlib.sha1(b"add_route").hexdigest()


async def feed(websocket):
    return hashlib.sha256(b"add_websocket_route").hexdigest()


app.add_route("/", homepage)
router.add_websocket_route("/feed", endpoint=feed)
