from collections.abc import Callable

from core.config import DetectionRule, RulesConfig
from core.models import Detection, SecurityEvent


class DetectionEngine:
    def __init__(self, config: RulesConfig):
        self.config = config

    def evaluate(
        self,
        event: SecurityEvent,
        history: Callable[[int], list[SecurityEvent]],
    ) -> list[Detection]:
        detections: list[Detection] = []
        for name, rule in self.config.rules.items():
            if not rule.enabled:
                continue
            matching = [item for item in history(rule.window) if self._matches(item, rule)]
            unseen = all(item.event_id != event.event_id for item in matching)
            if self._matches(event, rule) and unseen:
                matching.append(event)
            count = self._count(matching, rule.distinct_by)
            if count >= rule.threshold:
                detections.append(Detection(rule=name, score=rule.score, reason=name))
        return detections

    @staticmethod
    def _matches(event: SecurityEvent, rule: DetectionRule) -> bool:
        if rule.event_types and event.event_type not in rule.event_types:
            return False
        status = event.metadata.get("status")
        if rule.statuses and status not in rule.statuses:
            return False
        if rule.paths:
            path = event.path or ""
            matches_path = any(
                path == candidate or path.startswith(candidate + "/") for candidate in rule.paths
            )
            if not matches_path:
                return False
        return not rule.methods or (event.method or "").upper() in rule.methods

    @staticmethod
    def _count(events: list[SecurityEvent], distinct_by: str | None) -> int:
        if not distinct_by:
            return len(events)
        if distinct_by not in SecurityEvent.model_fields:
            raise ValueError(f"unsupported distinct_by field: {distinct_by}")
        return len({getattr(event, distinct_by) for event in events if getattr(event, distinct_by)})
