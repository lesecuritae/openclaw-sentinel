import asyncio
import logging
import sqlite3
from datetime import UTC, datetime

log = logging.getLogger(__name__)


class ActionLifecycle:
    def __init__(self, store, haproxy):
        self.store, self.haproxy = store, haproxy
        self.lock = asyncio.Lock()

    async def unblock(self, ip):
        async with self.lock:
            result = await self.haproxy.unblock(ip)
            if not result.applied:
                raise RuntimeError("rollback not confirmed")
            for row in self.store.pending_actions():
                if (
                    row["ip"] == result.ip
                    and row["provider"] == "haproxy"
                    and row["action"] == "block"
                ):
                    self.store.finish_action(row["id"], "revoked")
            return result

    async def revoke(self, action_id):
        async with self.lock:
            row = self.store.action_by_id(action_id)
            if row is None:
                return None
            if row["applied"] or row["result"] == "applying":
                if row["provider"] != "haproxy" or row["action"] != "block":
                    raise RuntimeError("provider has no verified rollback")
                result = await self.haproxy.unblock(row["ip"])
                if not result.applied:
                    raise RuntimeError("rollback not confirmed")
                for related in self.store.pending_actions():
                    if (
                        related["ip"] == row["ip"]
                        and related["provider"] == "haproxy"
                        and related["action"] == "block"
                    ):
                        self.store.finish_action(related["id"], "revoked")
            else:
                self.store.finish_action(action_id, "revoked")
            return self.store.action_by_id(action_id)

    async def reconcile(self):
        async with self.lock:
            now = datetime.now(UTC).isoformat()
            rows = self.store.pending_actions()
            for row in rows:
                if row["provider"] != "haproxy" or row["action"] != "block":
                    continue
                if row["expires_at"] and row["expires_at"] > now:
                    continue
                # Multiple records may share one ACL entry. Keep the longest lease.
                if any(
                    other["ip"] == row["ip"]
                    and other["provider"] == "haproxy"
                    and other["action"] == "block"
                    and other["expires_at"]
                    and other["expires_at"] > now
                    for other in rows
                ):
                    continue
                try:
                    result = await self.haproxy.unblock(row["ip"])
                    if not result.applied:
                        raise RuntimeError("rollback not confirmed")
                    self.store.finish_action(row["id"], "expired")
                    self.store.add_audit("system:expiry", "action.expire", after={"id": row["id"]})
                except (OSError, ValueError, RuntimeError):
                    log.warning("Rollback pending for action %s; will retry", row["id"])

    async def run(self, interval=5):
        while True:
            await asyncio.sleep(interval)
            try:
                await self.reconcile()
            except sqlite3.Error:
                log.warning("Expiry database unavailable; will retry")
