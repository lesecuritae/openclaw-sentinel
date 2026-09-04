from __future__ import annotations

from core.models import RiskFactor


class BehaviorAnalyzer:
    """Analyze request/access patterns without autonomous rule changes."""

    def __init__(self, repeated_path_threshold: int = 4, distinct_path_threshold: int = 8):
        self.repeated_path_threshold = repeated_path_threshold
        self.distinct_path_threshold = distinct_path_threshold

    def analyze_request_patterns(self, events: list) -> list[RiskFactor]:
        factors = []
        from collections import Counter

        paths = [getattr(event, "path", None) for event in events]
        paths = [path for path in paths if path]
        counts = Counter(paths)
        top = counts.most_common(1)
        if top and top[0][1] >= self.repeated_path_threshold:
            factors.append(
                RiskFactor(
                    source="behavior:repeated_path",
                    score=15,
                    reason=f"repeated path {top[0][0]} ({top[0][1]} requests/5m)",
                    kind="behavior",
                )
            )
        if len(set(paths)) >= self.distinct_path_threshold:
            factors.append(
                RiskFactor(
                    source="behavior:path_spread",
                    score=20,
                    reason=f"{len(set(paths))} distinct paths requested within 5m",
                    kind="behavior",
                )
            )
        return factors

    def analyze_access_patterns(self, events: list) -> list[RiskFactor]:
        services = {getattr(event, "service", "") for event in events}
        if len(services) >= 5:
            return [
                RiskFactor(
                    source="behavior:service_spread",
                    score=15,
                    reason=f"{len(services)} services accessed within 5m",
                    kind="behavior",
                )
            ]
        return []
