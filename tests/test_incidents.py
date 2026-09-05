import pytest

from database.store import SecurityStore


def test_incident_creation_status_history_and_risk(tmp_path):
    store = SecurityStore(tmp_path / "incident.db")
    incident = store.create_incident(
        source="docker",
        component="vaultwarden",
        risk_score=82,
        factors=[{"source": "integrity", "score": 80}],
    )
    assert incident["status"] == "neu"
    assert incident["priority"] == "hoch"
    updated = store.update_incident_status(incident["id"], "analysiert", "Snapshot geprüft")
    assert updated["status"] == "analysiert"
    store.record_incident_risk(incident["id"], 94)
    assert store.incident(incident["id"])["risk_score"] == 94
    assert len(store.incident_history(incident["id"])) == 3


def test_invalid_incident_status_is_rejected(tmp_path):
    store = SecurityStore(tmp_path / "incident.db")
    incident = store.create_incident(source="auth", component="ssh", risk_score=70)
    with pytest.raises(ValueError):
        store.update_incident_status(incident["id"], "blocked")
