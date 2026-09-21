"""
TEST-ONLY SHIM — not the real fastapi. Same reason as pydantic.py in this
directory: no network access to install the real, pinned fastapi==0.141.1.
Implements just enough (APIRouter/FastAPI as no-op decorators, HTTPException,
Query, WebSocket/WebSocketDisconnect placeholders) to import and call the
route FUNCTIONS directly in tests — this does NOT stand up a real ASGI
server or test the actual HTTP layer. Re-test with the real package and a
real TestClient/uvicorn before trusting the HTTP layer itself.
"""


class HTTPException(Exception):
    def __init__(self, status_code=500, detail=None):
        self.status_code = status_code
        self.detail = detail
        super().__init__(str(detail))


def Query(default=None, **kwargs):
    return default


def _decorator_factory():
    def register(*a, **k):
        def deco(fn):
            return fn
        return deco
    return register


class APIRouter:
    def __init__(self, *a, **k):
        self.get = _decorator_factory()
        self.post = _decorator_factory()
        self.websocket = _decorator_factory()


class WebSocket:
    pass


class WebSocketDisconnect(Exception):
    pass


class FastAPI:
    def __init__(self, *a, **k):
        self.get = _decorator_factory()
        self.post = _decorator_factory()
        self.on_event = _decorator_factory()

    def include_router(self, *a, **k):
        pass
