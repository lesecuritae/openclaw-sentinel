import json

from actions.anubis import AnubisChallengeAdapter
from actions.haproxy import HAProxyActionAdapter
from core.models import Action, ActionResult, RiskAssessment, SecurityEvent
from database.store import SecurityStore
from engine.detection import DetectionEngine
from engine.policy import PolicyEngine
from engine.risk import RiskEngine


class SentinelService:
    def __init__(
        self,
        store: SecurityStore,
        detection: DetectionEngine,
        risk: RiskEngine,
        policy: PolicyEngine,
        haproxy: HAProxyActionAdapter,
        anubis: AnubisChallengeAdapter,
    ):
        self.store, self.detection, self.risk, self.policy = store, detection, risk, policy
        self.haproxy, self.anubis = haproxy, anubis

    async def process(self, event: SecurityEvent) -> RiskAssessment:
        self.store.add_event(event)
        detections = self.detection.evaluate(
            event, lambda seconds: self.store.recent_events(event.ip, seconds)
        )
        assessment = self.risk.assess(event.ip, detections)
        assessment.action = self.policy.decide(assessment)
        self.store.update_profile(assessment)
        if event.ip != "unknown":
            result = await self._act(assessment)
            self.store.add_action(
                event.ip,
                assessment.action,
                ",".join(assessment.reasons),
                result.provider,
                result.applied,
            )
        return assessment

    async def _act(self, assessment: RiskAssessment) -> ActionResult:
        if assessment.action == Action.BLOCK:
            return await self.haproxy.block(assessment.ip)
        if assessment.action == Action.CHALLENGE:
            return await self.anubis.challenge(assessment.ip)
        return ActionResult(action=Action.ALLOW, ip=assessment.ip, provider="policy", applied=True)

    async def explain_event(self, event: SecurityEvent, llm) -> str:
        return await llm.explain(json.dumps(event.model_dump(mode="json")))
