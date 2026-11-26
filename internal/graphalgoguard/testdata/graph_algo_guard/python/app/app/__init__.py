from .main import Service
from .shapes import *

__all__ = ["Service", "tracked_dependency", "_handle"]
_handle = Service.handle
