from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.models import Action, RiskAssessment, SecurityEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL,
  ip TEXT NOT NULL, service TEXT NOT NULL, event_type TEXT NOT NULL,
  severity TEXT NOT NULL, score INTEGER NOT NULL DEFAULT 0, metadata TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ip_time ON events(ip, timestamp);
CREATE TABLE IF NOT EXISTS ip_profile (
  ip TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  risk_score INTEGER NOT NULL, action TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ip TEXT NOT NULL,
  action TEXT NOT NULL, reason TEXT NOT NULL, provider TEXT NOT NULL, applied INTEGER NOT NULL
);
"""


class SecurityStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def add_event(self, event: SecurityEvent, score: int = 0) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.source,
                    event.ip,
                    event.service,
                    event.event_type,
                    event.severity.value,
                    score,
                    json.dumps(event.metadata, separators=(",", ":")),
                ),
            )

    def recent_events(self, ip: str, window_seconds: int) -> list[SecurityEvent]:
        since = (datetime.now(UTC) - timedelta(seconds=window_seconds)).isoformat()
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM events WHERE ip=? AND timestamp>=? ORDER BY timestamp DESC",
                (ip, since),
            ).fetchall()
        return [self._event(row) for row in rows]

    def events(self, *, ip: str | None = None, limit: int = 100) -> list[SecurityEvent]:
        sql = "SELECT * FROM events"
        args: list[object] = []
        if ip:
            sql += " WHERE ip=?"
            args.append(ip)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        args.append(min(max(limit, 1), 1000))
        with self.connect() as db:
            return [self._event(row) for row in db.execute(sql, args).fetchall()]

    @staticmethod
    def _event(row: sqlite3.Row) -> SecurityEvent:
        return SecurityEvent(
            event_id=row["id"],
            timestamp=row["timestamp"],
            source=row["source"],
            ip=row["ip"],
            service=row["service"],
            event_type=row["event_type"],
            severity=row["severity"],
            metadata=json.loads(row["metadata"]),
        )

    def update_profile(self, assessment: RiskAssessment) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            db.execute(
                """INSERT INTO ip_profile VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen,
                risk_score=excluded.risk_score, action=excluded.action""",
                (assessment.ip, now, now, assessment.risk_score, assessment.action.value),
            )

    def profile(self, ip: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM ip_profile WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

    def add_action(
        self, ip: str, action: Action, reason: str, provider: str, applied: bool
    ) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO actions(timestamp,ip,action,reason,provider,applied)
                VALUES(?,?,?,?,?,?)""",
                (datetime.now(UTC).isoformat(), ip, action.value, reason, provider, int(applied)),
            )

    def incidents(self, limit: int = 100) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM actions WHERE action!='allow' ORDER BY timestamp DESC LIMIT ?",
                (min(max(limit, 1), 1000),),
            ).fetchall()
        return [dict(row) for row in rows]
