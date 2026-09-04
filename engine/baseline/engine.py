from pathlib import Path

from database.store import SecurityStore


class BaselineEngine:
    """Observation-only facade over Sentinel's shared persistent store."""

    def __init__(self, store: SecurityStore | Path | str):
        self.store = store if isinstance(store, SecurityStore) else SecurityStore(store)

    def observe(self, service: str, pattern: str) -> None:
        self.store.observe_baseline(service, pattern)

    def get_recommendation(self, service: str, pattern: str) -> dict | None:
        return next(
            (
                baseline
                for baseline in self.store.baselines(service)
                if baseline["pattern"] == pattern
            ),
            None,
        )
