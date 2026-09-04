from core.config import PolicyConfig
from core.models import Action, RiskAssessment


class PolicyEngine:
    def __init__(self, config: PolicyConfig):
        self.config = config

    def decide(self, assessment: RiskAssessment) -> Action:
        if assessment.risk_score < self.config.allow_below:
            return Action.ALLOW
        if assessment.risk_score < self.config.challenge_below:
            return Action.CHALLENGE if self.config.challenge_enabled else Action.ALLOW
        return Action.BLOCK if self.config.block_enabled else Action.ALLOW
