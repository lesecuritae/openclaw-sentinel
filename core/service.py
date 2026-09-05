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
        infrastructure_event = event.source == "docker" or event.ip == "unknown"

        def history(seconds: int) -> list[SecurityEvent]:
            candidates = self.store.recent_events(event.ip, seconds)
            if not infrastructure_event:
                return [item for item in candidates if item.source != "docker"]
            actor = event.metadata.get("actor_id") if event.source == "docker" else None
            return [
                item
                for item in candidates
                if item.source == event.source
                and item.service == event.service
                and (not actor or item.metadata.get("actor_id") == actor)
            ]

        device_profile = self.store.get_device_profile(event.device_id)
        recent_events = history(300)
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
            adaptive_factors.extend(self.geo_time.explain_geo_time_mismatch(event, device_profile))
            adaptive_factors.extend(self.client.analyze_client(event, device_profile))
            trust_factor = self.trust.get_trust_factor(device_profile)
            if trust_factor.score:
                adaptive_factors.append(trust_factor)

        reputation = []
        if self.intelligence and not infrastructure_event:
            reputation = await self.intelligence.check(event.ip)
        detections = self.detection.evaluate(event, history)
        assessment = self.risk.assess(event.ip, detections, reputation, adaptive_factors)
        assessment.action = self.policy.decide(assessment)
        self.store.update_event_score(event.event_id, assessment.risk_score)
        self.store.add_anomalies(event, adaptive_factors)
        if assessment.risk_score >= 70 or event.severity.value in {"high", "critical"}:
            factors = [factor.model_dump(mode="json") for factor in assessment.factors]
            existing = self.store.open_incident(event.source, event.service)
            if existing:
                self.store.record_incident_risk(existing["id"], assessment.risk_score, factors)
            else:
                self.store.create_incident(
                    source=event.source,
                    component=event.service,
                    risk_score=assessment.risk_score,
                    factors=factors,
                    event_id=event.event_id,
                )

        if event.ip and not infrastructure_event:
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

    async def process_integrity(self, finding) -> RiskAssessment:
        """Submit a read-only integrity finding through the event pipeline.

        Integrity events use an infrastructure identity, so the normal action path
        cannot create profiles, blocks, challenges, or other enforcement actions.
        The finding remains separately queryable from the integrity store.
        """
        event = SecurityEvent(
            source="integrity",
            ip="unknown",
            service=finding.subject,
            event_type=finding.kind,
            severity=finding.severity,
            metadata={"status": finding.status, "score": finding.score, **finding.details},
        )
        assessment = await self.process(event)
        # Keep the public assessment explicitly non-enforcing as a second guard.
        assessment.action = Action.ALLOW
        self.store.add_integrity_finding(finding, event.event_id)
        return assessment

    async def _act(self, assessment: RiskAssessment) -> ActionResult:
        if assessment.action == Action.BLOCK:
            return await self.haproxy.block(assessment.ip)
        if assessment.action == Action.CHALLENGE:
            return await self.anubis.challenge(assessment.ip)
        return ActionResult(action=Action.ALLOW, ip=assessment.ip, provider="policy", applied=True)

    async def explain_event(self, event: SecurityEvent, llm) -> str:
        return await llm.explain(json.dumps(event.model_dump(mode="json")))
