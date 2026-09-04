import httpx


class HTTPProvider:
    def __init__(self, client: httpx.AsyncClient | None = None, timeout: float = 5.0):
        self._client, self.timeout = client, timeout

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        if self._client:
            response = await self._client.request(method, url, **kwargs)
        else:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                response = await client.request(method, url, **kwargs)
        response.raise_for_status()
        return response
