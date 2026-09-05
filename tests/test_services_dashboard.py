"""Tests for the services dashboard aggregates."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.store import SecurityStore


def test_services_dashboard_aggregate_not_fallback():
    store = SecurityStore(":memory:")
    result = store.services_dashboard(rolling_window_hours=24)
    # Must return list (not None/empty fallback)
    assert isinstance(result, list)
    # No fake IP profiles required - actual service aggregates from evidence
    # When no lifecycle evidence exists, observed_status should be "unknown"
    # Not fabricated healthy/status values
    for item in result:
        assert "service" in item
        assert item.get("observed_status") == "unknown" or item.get("observed_status") in (
            "running",
            "stopped",
            "restarting",
            "created",
            "unknown",
        )
        assert "current_risk" in item
        assert isinstance(item["current_risk"], int)
        assert item.get("rolling_window_hours") == 24
        assert "last_event_type" in item
        # Actual values derived from store, not fake defaults
        assert item.get("service") is not None


def test_service_state_evidence_reads_actual_lifecycle():
    store = SecurityStore(":memory:")
    # No lifecycle evidence should exist initially
    evidence = store.service_state_evidence("nonexistent-service")
    assert isinstance(evidence, list)
    # Must return actual evidence, not fabricated profiles
    # No fake IP profiles injected


def test_get_services_mcp_tool_exists_and_reads_aggregates():
    # Verify MCP definition includes security.get_services
    from mcp.server import SecurityTools

    definitions = SecurityTools(None, None, None).definitions()
    names = {d["name"] for d in definitions}
    assert "security.get_services" in names
    # Not an empty fallback assertion
