import asyncio
from urllib.parse import urlsplit

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.auth import resolve_principal

router = APIRouter()
MAX_QUEUE_SIZE = 50


class EventConnectionManager:
    def __init__(self, queue_size: int = MAX_QUEUE_SIZE):
        self.queue_size = queue_size
        self.queues: dict[int, asyncio.Queue[dict]] = {}

    def register(self, client_id: int) -> asyncio.Queue[dict]:
        queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=self.queue_size)
        self.queues[client_id] = queue
        return queue

    def disconnect(self, client_id: int) -> None:
        self.queues.pop(client_id, None)

    def publish(self, message: dict) -> None:
        for queue in tuple(self.queues.values()):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(message)


manager = EventConnectionManager()


def origin_allowed(websocket: WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    if not origin:
        return True
    settings = websocket.app.state.settings
    normalized = origin.rstrip("/")
    if normalized in settings.allowed_origins:
        return True
    return urlsplit(origin).netloc == websocket.headers.get("host")


@router.websocket("/ws/events")
async def events_websocket(websocket: WebSocket):
    if not origin_allowed(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        frame = await asyncio.wait_for(websocket.receive_json(), timeout=5)
    except (TimeoutError, ValueError, WebSocketDisconnect):
        await websocket.close(code=1008)
        return
    supplied = frame.get("token", "") if isinstance(frame, dict) else ""
    principal = resolve_principal(websocket.app.state, str(supplied))
    authenticated = principal is not None
    if not authenticated:
        await websocket.close(code=1008)
        return

    client_id = id(websocket)
    queue = manager.register(client_id)
    try:
        await websocket.send_json({"type": "authenticated"})
        while True:
            if resolve_principal(websocket.app.state, str(supplied)) is None:
                await websocket.close(code=1008)
                break
            incoming = asyncio.create_task(websocket.receive())
            outgoing = asyncio.create_task(queue.get())
            try:
                done, _ = await asyncio.wait(
                    {incoming, outgoing}, timeout=5, return_when=asyncio.FIRST_COMPLETED
                )
                if incoming in done:
                    # No client frames are accepted after authentication.
                    break
                if outgoing in done:
                    await websocket.send_json(outgoing.result())
            finally:
                incoming.cancel()
                outgoing.cancel()
                await asyncio.gather(incoming, outgoing, return_exceptions=True)
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(client_id)
