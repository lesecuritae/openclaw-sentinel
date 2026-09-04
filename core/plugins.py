from dataclasses import dataclass, field
from typing import Any


@dataclass
class PluginRegistry:
    """Explicit registry for configured collectors, intelligence and action providers."""

    collectors: dict[str, Any] = field(default_factory=dict)
    intelligence: dict[str, Any] = field(default_factory=dict)
    actions: dict[str, Any] = field(default_factory=dict)

    def register(self, kind: str, name: str, plugin: Any) -> None:
        collection = getattr(self, kind, None)
        if not isinstance(collection, dict):
            raise ValueError(f"unsupported plugin kind: {kind}")
        if name in collection:
            raise ValueError(f"duplicate {kind} plugin: {name}")
        collection[name] = plugin
