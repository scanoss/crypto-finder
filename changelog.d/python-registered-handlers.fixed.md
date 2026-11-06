- Python handlers registered by a call are framework entry points
  (`root_kind: framework_entry`), like their decorated counterparts: Flask and
  Blueprint `add_url_rule`, FastAPI and `APIRouter` `add_api_route`,
  `add_api_websocket_route`, `add_route` and `add_websocket_route`, and
  Starlette `add_route` and `add_websocket_route`. The handler may be passed
  positionally after the path or as the `view_func=` or `endpoint=` keyword
  argument. The receiver must come from the framework (`app = Flask(__name__)`,
  `router = APIRouter()`); the same method on another object is not an entry
  point. Crypto written directly in such a handler now reads `reachable`, and a
  chain through it starts at the handler with `entry_rule`
  `python/flask:registration_call:add_url_rule`,
  `python/fastapi:registration_call:add_api_route` or
  `python/starlette:registration_call:add_route`, instead of `no_callers`.
