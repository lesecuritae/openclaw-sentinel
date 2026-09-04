from __future__ import annotations

from core.models import RiskFactor


class TrustEngine:
    """Deterministic trust on 0..100. Neutral start 50. No self-rewriting rules."""

    NEUTRAL = 50
    MIN = 0
    MAX = 100

    def __init__(self, min_samples_for_trust: int = 10, confidence_threshold: float = 0.5):
        self.min_samples = min_samples_for_trust
        self.confidence_threshold = confidence_threshold

    def calculate_trust(self, device_profile: dict) -> int:
        score = self.NEUTRAL
        excluded = device_profile.get("blocked_event_count", 0) + device_profile.get(
            "challenged_event_count", 0
        )
        positive_events = max(0, device_profile.get("positive_event_count", 0) - excluded)
        confidence = device_profile.get("positive_confidence", 0.0)
        if positive_events >= self.min_samples and confidence >= self.confidence_threshold:
            score += min(20, positive_events)
        negative_events = max(0, device_profile.get("negative_event_count", 0))
        if negative_events > 0:
            score -= min(30, negative_events * 5)
        return max(self.MIN, min(self.MAX, score))

    def explain_trust(self, device_profile: dict) -> str:
        score = self.calculate_trust(device_profile)
        parts = [f"trust_score={score}"]
        if device_profile.get("positive_event_count", 0) > 0:
            parts.append(f"positive_events={device_profile['positive_event_count']}")
        if device_profile.get("negative_event_count", 0) > 0:
            parts.append(f"negative_events={device_profile['negative_event_count']}")
        if device_profile.get("blocked_event_count", 0) > 0:
            parts.append(f"blocked_events={device_profile['blocked_event_count']} (not trusted)")
        return "; ".join(parts)

    def get_trust_factor(self, device_profile: dict) -> RiskFactor:
        score = self.calculate_trust(device_profile)
        # Trust factor mapped to risk contribution: high trust = lower risk, but
        # negative trust factors never blind neutralize hard threat signals.
        # We return a factor where score reflects deviation from neutral.
        deviation = score - self.NEUTRAL  # positive = more trust, negative = less
        # For risk engine: lower deviation = lower risk contribution
        # We cap contribution so trust never fully neutralizes hard threats.
        factor_score = max(-30, min(30, -deviation // 3))
        return RiskFactor(
            source="trust:adaptive",
            score=factor_score,
            reason=self.explain_trust(device_profile),
            kind="trust",
        )
