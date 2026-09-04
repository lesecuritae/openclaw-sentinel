import asyncio
import shutil
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.websockets import WebSocketDisconnect

from core.api.v1 import api_router, ws_router
from core.api.v1.ws.events import EventConnectionManager
from core.config import Settings
from core.config_manager import ConfigManager
from database.store import SecurityStore


class ToolsStub:
    def definitions(self):
        return [{"name": "security.check_ip"}]


@pytest.fixture
def web_app(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("rules", "policy", "intelligence"):
        shutil.copy(f"config/{name}.yaml", config_dir / f"{name}.yaml")
    settings = Settings(
        database_path=tmp_path / "sentinel.db",
        rules_path=config_dir / "rules.yaml",
        policy_path=config_dir / "policy.yaml",
        intelligence_path=config_dir / "intelligence.yaml",
        sentinel_api_key="test-secret",
    )
    app = FastAPI()
    app.state.settings = settings
    app.state.store = SecurityStore(settings.database_path)
    app.state.config_manager = ConfigManager(settings)
    app.state.tools = ToolsStub()
    app.state.runtime = SimpleNamespace(command=lambda _command: asyncio.sleep(0, result=""))
    app.state.service = SimpleNamespace(haproxy=None)
    app.include_router(api_router)
    app.include_router(ws_router, prefix="/api/v1")
    return app


def test_rest_auth_dashboard_and_limits(web_app):
    with TestClient(web_app) as client:
        assert client.get("/api/v1/dashboard").status_code == 401
        headers = {"Authorization": "Bearer test-secret"}
        response = client.get("/api/v1/dashboard", headers=headers)
        assert response.status_code == 200
        assert response.json()["events_24h"] == 0
        assert client.get("/api/v1/events?limit=501", headers=headers).status_code == 422


def test_config_update_is_validated_and_atomic(web_app):
    manager = web_app.state.config_manager
    original = manager.targets["policy"][0].read_text()
    with pytest.raises(ValidationError):
        manager.update("policy", {"unknown": True})
    assert manager.targets["policy"][0].read_text() == original
    result = manager.update(
        "policy",
        {
            "allow_below": 60,
            "challenge_below": 90,
            "challenge_enabled": False,
            "block_enabled": True,
            "challenge_provider": "anubis",
            "block_provider": "haproxy",
        },
    )
    assert result == {"updated": True, "restart_required": True}
    assert manager.targets["policy"][0].stat().st_mode & 0o777 == 0o600


def test_websocket_requires_token_and_rejects_cross_origin(web_app):
    with TestClient(web_app) as client:
        with client.websocket_connect("/api/v1/ws/events") as websocket:
            websocket.send_json({"token": "wrong"})
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_json()
        with pytest.raises(WebSocketDisconnect), client.websocket_connect(
            "/api/v1/ws/events", headers={"origin": "https://evil.example"}
        ):
            pass
        with client.websocket_connect("/api/v1/ws/events") as websocket:
            websocket.send_json({"token": "test-secret"})
            assert websocket.receive_json() == {"type": "authenticated"}


def test_broadcast_queue_is_bounded_and_keeps_latest():
    manager = EventConnectionManager(queue_size=2)
    queue = manager.register(1)
    manager.publish({"id": 1})
    manager.publish({"id": 2})
    manager.publish({"id": 3})
    assert queue.qsize() == 2
    assert queue.get_nowait() == {"id": 2}
    assert queue.get_nowait() == {"id": 3}
