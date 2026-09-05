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
        return self.evaluate(assessment, context)["action"]

    def evaluate(self, assessment: RiskAssessment, context: dict | None = None) -> dict:
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
                action = self._action(rule.get("action", "allow"))
                return {
                    "action": action,
                    "rule": rule,
                    "reason": "explicit deterministic rule matched",
                }
        if assessment.risk_score < self.config.allow_below:
            return {"action": Action.ALLOW, "rule": None, "reason": "risk below allow threshold"}
        if assessment.risk_score < self.config.challenge_below:
            action = Action.CHALLENGE if self.config.challenge_enabled else Action.ALLOW
            return {"action": action, "rule": None, "reason": "risk in challenge band"}
        if self.config.require_explicit_block_rule:
            return {"action": Action.ALLOW, "rule": None, "reason": "explicit block rule required"}
        return {
            "action": Action.BLOCK if self.config.block_enabled else Action.ALLOW,
            "rule": None,
            "reason": "risk threshold policy",
        }

    def explain(self, assessment: RiskAssessment, context: dict | None = None) -> dict:
        result = self.evaluate(assessment, context)
        return {
            "action": result["action"].value,
            "risk_score": assessment.risk_score,
            "deterministic": True,
            "rule": result["rule"],
            "reason": result["reason"],
            "context": context or {},
            "rules": self.config.rules,
        }

    def test(self, risk_score: int, context: dict | None = None) -> dict:
        assessment = RiskAssessment(ip="test", risk_score=max(0, min(100, risk_score)), reasons=[])
        return self.explain(assessment, context)
