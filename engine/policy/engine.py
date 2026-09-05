from core.config import PolicyConfig
from core.models import Action, RiskAssessment


class PolicyEngine:
    """Deterministic policy evaluation; no model or LLM participates."""

    def __init__(self, config: PolicyConfig):
        self.config = config

    @staticmethod
    def _action(value: object) -> Action:
        aliases = {"anubis_challenge": "challenge", "haproxy_block": "block"}
        return Action(aliases.get(str(value), str(value)))

    def decide(self, assessment: RiskAssessment, context: dict | None = None) -> Action:
        for rule in sorted(self.config.rules, key=lambda item: int(item.get("priority", 100))):
            condition = rule.get("condition", {})
            if all(
                (
                    assessment.risk_score >= int(condition.get("min_risk", 0)),
                    not condition.get("event_type")
                    or context
                    and context.get("event_type") == condition.get("event_type"),
                    not condition.get("source")
                    or context
                    and context.get("source") == condition.get("source"),
                )
            ):
                return self._action(rule.get("action", "allow"))
        if assessment.risk_score < self.config.allow_below:
            return Action.ALLOW
        if assessment.risk_score < self.config.challenge_below:
            return Action.CHALLENGE if self.config.challenge_enabled else Action.ALLOW
        if self.config.require_explicit_block_rule:
            return Action.ALLOW
        return Action.BLOCK if self.config.block_enabled else Action.ALLOW

    def explain(self, assessment: RiskAssessment, context: dict | None = None) -> dict:
        action = self.decide(assessment, context)
        return {
            "action": action.value,
            "risk_score": assessment.risk_score,
            "deterministic": True,
            "rules": self.config.rules,
        }

    def test(self, risk_score: int, context: dict | None = None) -> dict:
        assessment = RiskAssessment(ip="test", risk_score=max(0, min(100, risk_score)), reasons=[])
        return self.explain(assessment, context)
