import ipaddress
import re

from collectors.haproxy.runtime import HAProxyRuntimeClient
from core.models import Action, ActionResult


class HAProxyActionAdapter:
    def __init__(self, runtime: HAProxyRuntimeClient, blocklist_path: str, enabled: bool = False):
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", blocklist_path):
            raise ValueError("invalid ACL path")
        self.runtime, self.blocklist_path, self.enabled = runtime, blocklist_path, enabled

    async def _contains(self, address: str) -> bool:
        response = await self.runtime.command(f"show acl {self.blocklist_path}")
        entries = []
        for line in response.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2 or not parts[0].startswith("0x"):
                raise RuntimeError("invalid HAProxy ACL response")
            entries.append(str(ipaddress.ip_address(parts[1])))
        return address in entries

    async def block(self, ip: str, expires_at: str | None = None) -> ActionResult:
        address = str(ipaddress.ip_address(ip))
        if not self.enabled:
            return ActionResult(
                action=Action.BLOCK,
                ip=address,
                provider="haproxy",
                applied=False,
                detail=f"actions disabled; expires_at={expires_at or 'none'}",
            )
        response = ""
        if not await self._contains(address):
            response = await self.runtime.command(f"add acl {self.blocklist_path} {address}")
        if response.strip() or not await self._contains(address):
            raise RuntimeError("HAProxy block not confirmed")
        return ActionResult(
            action=Action.BLOCK,
            ip=address,
            provider="haproxy",
            applied=True,
            detail=f"{response.strip()}; expires_at={expires_at or 'none'}",
        )

    async def unblock(self, ip: str) -> ActionResult:
        address = str(ipaddress.ip_address(ip))
        if not self.enabled:
            return ActionResult(
                action=Action.ALLOW,
                ip=address,
                provider="haproxy",
                applied=False,
                detail="actions disabled",
            )
        response = await self.runtime.command(f"del acl {self.blocklist_path} {address}")
        if response.strip() or await self._contains(address):
            raise RuntimeError("HAProxy rollback not confirmed")
        return ActionResult(
            action=Action.ALLOW,
            ip=address,
            provider="haproxy",
            applied=True,
            detail=response.strip(),
        )

    async def rate_limit(
        self, ip: str, requests_per_minute: int = 60, expires_at: str | None = None
    ) -> ActionResult:
        address = str(ipaddress.ip_address(ip))
        if not self.enabled:
            return ActionResult(
                action=Action.RATE_LIMIT,
                ip=address,
                provider="haproxy",
                applied=False,
                detail="actions disabled",
            )
        return ActionResult(
            action=Action.RATE_LIMIT,
            ip=address,
            provider="haproxy",
            applied=False,
            detail="per-IP rate limiting has no verified provider lifecycle; disabled",
        )
