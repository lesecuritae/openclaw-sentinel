from core.api.v1.routes import router as api_router
from core.api.v1.ws.events import router as ws_router

__all__ = ["api_router", "ws_router"]
