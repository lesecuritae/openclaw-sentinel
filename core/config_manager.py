import os
import tempfile
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from core.config import IntelligenceConfig, PolicyConfig, RulesConfig, Settings


class ConfigManager:
    """Validate and atomically persist only Sentinel's configured YAML files."""

    def __init__(self, settings: Settings):
        self.targets: dict[str, tuple[Path, type[BaseModel]]] = {
            "rules": (settings.rules_path.resolve(), RulesConfig),
            "policy": (settings.policy_path.resolve(), PolicyConfig),
            "intelligence": (settings.intelligence_path.resolve(), IntelligenceConfig),
        }

    def read(self, name: str) -> dict[str, Any]:
        path, schema = self._target(name)
        return schema.model_validate(yaml.safe_load(path.read_text())).model_dump(mode="json")

    def update(self, name: str, data: dict[str, Any]) -> dict[str, bool]:
        path, schema = self._target(name)
        validated = schema.model_validate(data)
        payload = yaml.safe_dump(validated.model_dump(mode="python"), sort_keys=False)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise
        return {"updated": True, "restart_required": True}

    def _target(self, name: str) -> tuple[Path, type[BaseModel]]:
        try:
            return self.targets[name]
        except KeyError:
            raise UnknownConfigurationError("unknown configuration") from None


class UnknownConfigurationError(ValueError):
    pass
