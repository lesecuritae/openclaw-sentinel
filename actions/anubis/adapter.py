from core.models import Action, ActionResult


class AnubisChallengeAdapter:
    """Phase-1 boundary for an external Anubis deployment; no CAPTCHA lives here."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url

    async def challenge(self, ip: str) -> ActionResult:
        return ActionResult(
            action=Action.CHALLENGE,
            ip=ip,
            provider="anubis",
            applied=False,
            detail="provider prepared; routing integration is a later phase",
        )
