import json

from actions.anubis import AnubisChallengeAdapter
from actions.haproxy import HAProxyActionAdapter
from core.models import Action, ActionResult, RiskAssessment, RiskFactor, SecurityEvent
from database.store import SecurityStore
from engine.behavior.analyzer import BehaviorAnalyzer
from engine.client.analyzer import ClientMismatchAnalyzer
from engine.detection import DetectionEngine
from engine.geo_time.analyzer import GeoTimeAnalyzer
from engine.policy import PolicyEngine
from engine.risk import RiskEngine
from engine.trust.engine import TrustEngine


class SentinelService:
    def __init__(
        self,
        store: SecurityStore,
        detection: DetectionEngine,
        risk: RiskEngine,
        policy: PolicyEngine,
        haproxy: HAProxyActionAdapter,
        anubis: AnubisChallengeAdapter,
        intelligence=None,
        event_publisher=None,
    ):
        self.store, self.detection, self.risk, self.policy = store, detection, risk, policy
        self.haproxy, self.anubis = haproxy, anubis
        self.intelligence = intelligence
        self.event_publisher = event_publisher
        self.behavior = BehaviorAnalyzer()
        self.geo_time = GeoTimeAnalyzer()
        self.client = ClientMismatchAnalyzer()
        self.trust = TrustEngine()

    async def process(self, event: SecurityEvent) -> RiskAssessment:
        self.store.add_event(event)
        device_profile = self.store.get_device_profile(event.device_id)
        recent_events = self.store.recent_events(event.ip, 300)
        adaptive_factors = self.behavior.analyze_request_patterns(recent_events)
        adaptive_factors.extend(self.behavior.analyze_access_patterns(recent_events))
        if event.device_id and not device_profile:
            adaptive_factors.append(
                RiskFactor(
                    source="device:unknown",
                    score=10,
                    reason="device identifier has no trusted history",
                    kind="device",
                )
            )
        if device_profile:
            adaptive_factors.extend(
                self.geo_time.explain_geo_time_mismatch(event, device_profile)
            )
            adaptive_factors.extend(self.client.analyze_client(event, device_profile))
            trust_factor = self.trust.get_trust_factor(device_profile)
            if trust_factor.score:
                adaptive_factors.append(trust_factor)

        reputation = []
        if self.intelligence and event.ip != "unknown":
            reputation = await self.intelligence.check(event.ip)
        detections = self.detection.evaluate(
            event, lambda seconds: self.store.recent_events(event.ip, seconds)
        )
        assessment = self.risk.assess(event.ip, detections, reputation, adaptive_factors)
        assessment.action = self.policy.decide(assessment)
        self.store.update_event_score(event.event_id, assessment.risk_score)
        self.store.add_anomalies(event, adaptive_factors)

        if event.ip and event.ip != "unknown":
            self.store.update_profile(assessment)
            safe = assessment.action == Action.ALLOW and assessment.risk_score < 30
            if event.device_id:
                self.store.update_device_profile(
                    event.device_id,
                    event,
                    safe=safe,
                    blocked=assessment.action == Action.BLOCK,
                )
            if safe:
                self.store.observe_baseline(event.service, f"event:{event.event_type}")
                if event.method:
                    self.store.observe_baseline(event.service, f"method:{event.method.upper()}")
            result = await self._act(assessment)
            self.store.add_action(
                event.ip,
                assessment.action,
                ",".join(assessment.reasons),
                result.provider,
                result.applied,
            )
        if self.event_publisher:
            self.event_publisher(
                {
                    "event": event.model_dump(mode="json"),
                    "risk_score": assessment.risk_score,
                    "action": assessment.action.value,
                    "factors": [factor.model_dump() for factor in assessment.factors],
                }
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
