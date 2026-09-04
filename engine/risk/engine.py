from core.models import Detection, RiskAssessment, RiskFactor
from intelligence.base import IntelligenceResult


class RiskEngine:
    """Combine explainable factors; intelligence providers never select actions."""

    def __init__(self, single_source_ceiling: int = 89):
        self.single_source_ceiling = single_source_ceiling

    def assess(
        self,
        ip: str,
        detections: list[Detection],
        intelligence: list[IntelligenceResult] | None = None,
        additional_factors: list[RiskFactor] | None = None,
    ) -> RiskAssessment:
        unique = {item.rule: item for item in detections}
        factors = [
            RiskFactor(source=item.rule, score=item.score, reason=item.reason, kind="behavior")
            for item in unique.values()
        ]
        by_source = {
            item.source: item for item in (intelligence or []) if item.listed and item.score
        }
        listed = list(by_source.values())
        factors.extend(
            RiskFactor(
                source=item.source, score=item.score, reason=item.reason, kind="intelligence"
            )
            for item in listed
        )
        factors.extend(additional_factors or [])
        score = min(100, max(0, sum(item.score for item in factors)))
        corroborating = any(
            item.kind not in {"intelligence", "trust"} and item.score > 0 for item in factors
        )
        if len(listed) == 1 and not corroborating:
            score = min(score, self.single_source_ceiling)
        return RiskAssessment(
            ip=ip, risk_score=score, reasons=[item.reason for item in factors], factors=factors
        )
