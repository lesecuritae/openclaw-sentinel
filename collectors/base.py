from collections.abc import Awaitable, Callable
from typing import Protocol

from core.models import SecurityEvent

EventSink = Callable[[SecurityEvent], Awaitable[None]]


class Collector(Protocol):
    """Contract implemented by HAProxy and future event sources."""

    async def run(self, emit: EventSink) -> None: ...
