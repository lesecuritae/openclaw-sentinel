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


def test_fresh_setup_is_single_use(tmp_path):
    from database.store import SecurityStore

    store = SecurityStore(tmp_path / "fresh.db")
    assert not store.setup_initialized()
    assert store.initialize_setup("admin", "administrator", "hash", "0.5.0")
    assert store.setup_initialized()
    assert not store.initialize_setup("other", "administrator", "hash2", "0.5.0")
    assert store.users()[0]["username"] == "admin"


def test_config_export_backup_import(tmp_path):
    import shutil
    from pathlib import Path

    from core.config import Settings
    from core.config_manager import ConfigManager

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("rules.yaml", "policy.yaml", "intelligence.yaml"):
        shutil.copy(Path("config") / name, config_dir / name)
    manager = ConfigManager(
        Settings(
            rules_path=config_dir / "rules.yaml",
            policy_path=config_dir / "policy.yaml",
            intelligence_path=config_dir / "intelligence.yaml",
        )
    )
    exported = manager.export()
    backup = manager.backup(tmp_path)
    assert backup.exists()
    assert set(exported) == {"rules", "policy", "intelligence"}
    assert manager.import_config(exported)["imported"] is True
