from core.config import PolicyConfig
from core.models import Action, RiskAssessment
from engine.policy import PolicyEngine


def test_prioritized_deterministic_policy_rules():
    engine = PolicyEngine(
        PolicyConfig(
            rules=[
                {
                    "priority": 20,
                    "condition": {"min_risk": 80, "event_type": "ssh_bruteforce"},
                    "action": "anubis_challenge",
                },
                {"priority": 30, "condition": {"min_risk": 90}, "action": "haproxy_block"},
            ]
        )
    )
    assessment = RiskAssessment(ip="203.0.113.10", risk_score=85, reasons=[])
    assert engine.decide(assessment, {"event_type": "ssh_bruteforce"}) == Action.CHALLENGE
    assert engine.decide(assessment, {"event_type": "normal_request"}) == Action.ALLOW


def test_policy_test_never_uses_llm():
    result = PolicyEngine(PolicyConfig()).test(95)
    assert result["deterministic"] is True


def test_production_config_requires_explicit_block_rule():
    from pathlib import Path

    import yaml

    config = PolicyConfig.model_validate(yaml.safe_load(Path("config/policy.yaml").read_text()))
    assert config.require_explicit_block_rule is True
    assert PolicyEngine(config).test(100)["action"] == "allow"
