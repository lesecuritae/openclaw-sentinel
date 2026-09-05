from core.permissions import Role


def test_roles_are_ordered():
    from core.permissions import _levels

    assert _levels[Role.VIEWER] < _levels[Role.ANALYST] < _levels[Role.ADMINISTRATOR]


def test_audit_before_after_round_trip(tmp_path):
    from database.store import SecurityStore

    store = SecurityStore(tmp_path / "ops.db")
    store.add_audit("alice", "config.update", {"x": 1}, {"x": 2})
    entry = store.audit_log()[0]
    assert entry["username"] == "alice"
    assert entry["before_state"] == {"x": 1}
    assert entry["after_state"] == {"x": 2}


def test_config_export_backup_import():
    from core.config import Settings
    from core.config_manager import ConfigManager

    manager = ConfigManager(Settings())
    exported = manager.export()
    backup = manager.backup()
    assert backup.exists()
    assert set(exported) == {"rules", "policy", "intelligence"}
    assert manager.import_config(exported)["imported"] is True
