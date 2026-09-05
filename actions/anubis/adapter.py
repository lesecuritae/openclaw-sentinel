import httpx

from core.models import Action, ActionResult


class AnubisChallengeAdapter:
    """Phase-1 boundary for an external Anubis deployment; no CAPTCHA lives here."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url

    async def challenge(self, ip: str) -> ActionResult:
        if self.base_url:
            try:
                async with httpx.AsyncClient(
                    base_url=self.base_url, timeout=5, follow_redirects=False
                ) as client:
                    response = await client.post("/challenge", json={"ip": ip})
                    response.raise_for_status()
                    payload = response.json()
                return ActionResult(
                    action=Action.CHALLENGE,
                    ip=ip,
                    provider="anubis",
                    applied=True,
                    detail=(
                        f"challenge_id={payload.get('id', '')}; "
                        f"status={payload.get('status', 'issued')}"
                    ),
                )
            except (httpx.HTTPError, ValueError) as exc:
                return ActionResult(
                    action=Action.CHALLENGE,
                    ip=ip,
                    provider="anubis",
                    applied=False,
                    detail=f"challenge failed: {exc}",
                )
        return ActionResult(
            action=Action.CHALLENGE,
            ip=ip,
            provider="anubis",
            applied=False,
            detail="provider prepared; routing integration is a later phase",
        )

    async def status(self, challenge_id: str) -> dict:
        if not self.base_url:
            return {"id": challenge_id, "status": "unconfigured"}
        async with httpx.AsyncClient(
            base_url=self.base_url, timeout=5, follow_redirects=False
        ) as client:
            response = await client.get(f"/challenge/{challenge_id}")
            response.raise_for_status()
            return response.json()
