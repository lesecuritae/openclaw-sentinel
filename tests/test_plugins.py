import pytest

from core.plugins import PluginRegistry
from intelligence import IntelligenceResult


def test_plugin_registry_is_explicit_and_rejects_duplicates():
    registry = PluginRegistry()
    plugin = object()
    registry.register("collectors", "example", plugin)
    assert registry.collectors["example"] is plugin
    with pytest.raises(ValueError, match="duplicate"):
        registry.register("collectors", "example", object())
    with pytest.raises(ValueError, match="unsupported"):
        registry.register("unknown", "example", object())


def test_intelligence_scores_are_bounded():
    assert IntelligenceResult(source="example", ip="192.0.2.10", score=20).score == 20
    with pytest.raises(ValueError):
        IntelligenceResult(source="example", ip="192.0.2.10", score=101)
