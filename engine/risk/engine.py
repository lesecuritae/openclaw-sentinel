from core.models import Detection, RiskAssessment


class RiskEngine:
    """Additive and capped today; future intelligence factors use this boundary."""

    def assess(self, ip: str, detections: list[Detection], prior_score: int = 0) -> RiskAssessment:
        unique = {item.rule: item for item in detections}
        score = min(100, max(0, prior_score) + sum(item.score for item in unique.values()))
        return RiskAssessment(ip=ip, risk_score=score, reasons=sorted(unique))
