import asyncio
from pathlib import Path


class HAProxyRuntimeClient:
    def __init__(self, socket_path: Path | str, timeout: float = 3.0):
        self.socket_path = str(socket_path)
        self.timeout = timeout

    async def command(self, command: str) -> str:
        if "\n" in command or "\r" in command:
            raise ValueError("HAProxy command must be a single line")
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(self.socket_path), self.timeout
        )
        try:
            writer.write((command + "\n").encode())
            await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()
            return (await asyncio.wait_for(reader.read(4 * 1024 * 1024), self.timeout)).decode()
        finally:
            writer.close()
            await writer.wait_closed()
