import ipaddress

from collectors.haproxy.runtime import HAProxyRuntimeClient
from core.models import Action, ActionResult


class HAProxyActionAdapter:
    def __init__(self, runtime: HAProxyRuntimeClient, blocklist_path: str, enabled: bool = False):
        self.runtime, self.blocklist_path, self.enabled = runtime, blocklist_path, enabled

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
        response = await self.runtime.command(f"add acl {self.blocklist_path} {address}")
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
        return ActionResult(
            action=Action.ALLOW,
            ip=address,
            provider="haproxy",
            applied=True,
            detail=response.strip(),
        )
