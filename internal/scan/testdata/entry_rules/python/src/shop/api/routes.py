import hashlib

from fastapi import APIRouter, FastAPI

api = FastAPI()
router = APIRouter()


@api.get("/health")
async def health():
    return hashlib.md5(b"fastapi").hexdigest()


@router.post("/orders")
def create_order():
    return hashlib.sha224(b"router").hexdigest()
