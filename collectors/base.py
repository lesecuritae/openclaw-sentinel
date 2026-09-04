from collections.abc import Awaitable, Callable
from typing import Protocol

from core.models import SecurityEvent

EventSink = Callable[[SecurityEvent], Awaitable[None]]


class Collector(Protocol):
    """Unified collector contract. All sources (HAProxy, Docker, auth, service logs)
    implement this interface and emit normalized SecurityEvent objects."""

    async def run(self, emit: EventSink) -> None: ...

    async def collect(self) -> list[SecurityEvent]: ...
