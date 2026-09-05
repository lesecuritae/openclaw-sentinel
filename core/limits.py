"""Bounded process-wide budgets; deploy a single API worker per database."""

import time
from threading import Lock

from starlette.responses import JSONResponse


class RateBudget:
    def __init__(self):
        self.windows = {}
        self.lock = Lock()

    def allow(self, category: str, limit: int) -> bool:
        with self.lock:
            now = time.monotonic()
            start, count = self.windows.get(category, (now, 0))
            if now - start >= 60:
                start, count = now, 0
            self.windows[category] = (start, count + 1)
            return count < limit


class RequestLimits:
    def __init__(self, app, settings):
        self.app, self.settings = app, settings
        self.budget = RateBudget()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        if path == "/health":
            return await self.app(scope, receive, send)
        category = "api"
        maximum = self.settings.api_rate_limit
        if path == "/events" and scope["method"] == "POST":
            category, maximum = "ingest", self.settings.event_rate_limit
        elif path == "/mcp":
            category, maximum = "mcp", self.settings.mcp_rate_limit
        elif "/reports/" in path:
            category, maximum = "reports", self.settings.report_rate_limit
        elif "/ai/" in path:
            category, maximum = "llm", self.settings.llm_rate_limit
        elif "/auth/session" in path or "/setup/initialize" in path:
            category, maximum = "login", 20
        if not self.budget.allow(category, maximum):
            return await JSONResponse(
                {"detail": "rate limit exceeded"}, 429, headers={"Retry-After": "60"}
            )(scope, receive, send)
        # Count actual ASGI bytes, including chunked requests, before JSON parsing.
        limit = (
            self.settings.max_event_bytes
            if category == "ingest"
            else self.settings.max_request_bytes
        )
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > limit:
                return await JSONResponse({"detail": "request too large"}, 413)(
                    scope, receive, send
                )
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        delivered = False

        async def buffered():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, buffered, send)
