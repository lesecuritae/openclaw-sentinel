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
  severity TEXT NOT NULL, score INTEGER NOT NULL DEFAULT 0, metadata TEXT NOT NULL,
  path TEXT, method TEXT, user_agent TEXT, hostname TEXT, country TEXT, asn TEXT
);
CREATE INDEX IF NOT EXISTS events_ip_time ON events(ip, timestamp);
CREATE TABLE IF NOT EXISTS ip_profile (
  ip TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  risk_score INTEGER NOT NULL, action TEXT NOT NULL, reasons TEXT NOT NULL DEFAULT '[]',
  factors TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ip TEXT NOT NULL,
  action TEXT NOT NULL, reason TEXT NOT NULL, provider TEXT NOT NULL, applied INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_intelligence (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, source TEXT NOT NULL,
  result INTEGER NOT NULL, score INTEGER NOT NULL, reason TEXT NOT NULL,
  attributes TEXT NOT NULL DEFAULT '{}', checked_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS threat_intelligence_expiry
  ON threat_intelligence(ip, source, expires_at);
"""


class SecurityStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)
            self._migrate(db)

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        event_columns = {row["name"] for row in db.execute("PRAGMA table_info(events)")}
        for name in ("path", "method", "user_agent", "hostname", "country", "asn"):
            if name not in event_columns:
                db.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
        profile_columns = {row["name"] for row in db.execute("PRAGMA table_info(ip_profile)")}
        if "reasons" not in profile_columns:
            db.execute("ALTER TABLE ip_profile ADD COLUMN reasons TEXT NOT NULL DEFAULT '[]'")
        if "factors" not in profile_columns:
            db.execute("ALTER TABLE ip_profile ADD COLUMN factors TEXT NOT NULL DEFAULT '[]'")
        db.execute("CREATE INDEX IF NOT EXISTS events_ip_path_time ON events(ip,path,timestamp)")

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def add_event(self, event: SecurityEvent, score: int = 0) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT OR IGNORE INTO events
                (id,timestamp,source,ip,service,event_type,severity,score,metadata,
                 path,method,user_agent,hostname,country,asn)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                    event.path,
                    event.method,
                    event.user_agent,
                    event.hostname,
                    event.country,
                    event.asn,
                ),
            )

    def update_event_score(self, event_id: str, score: int) -> None:
        with self.connect() as db:
            db.execute("UPDATE events SET score=? WHERE id=?", (score, event_id))

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
            path=row["path"],
            method=row["method"],
            user_agent=row["user_agent"],
            hostname=row["hostname"],
            country=row["country"],
            asn=row["asn"],
            metadata=json.loads(row["metadata"]),
        )

    def update_profile(self, assessment: RiskAssessment) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            db.execute(
                """INSERT INTO ip_profile(ip,first_seen,last_seen,risk_score,action,reasons,factors)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen,
                risk_score=excluded.risk_score, action=excluded.action,
                reasons=excluded.reasons, factors=excluded.factors""",
                (
                    assessment.ip,
                    now,
                    now,
                    assessment.risk_score,
                    assessment.action.value,
                    json.dumps(assessment.reasons),
                    json.dumps([factor.model_dump(mode="json") for factor in assessment.factors]),
                ),
            )

    def profile(self, ip: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM ip_profile WHERE ip=?", (ip,)).fetchone()
        if not row:
            return None
        profile = dict(row)
        profile["reasons"] = json.loads(profile["reasons"])
        profile["factors"] = json.loads(profile["factors"])
        return profile

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

    def action_history(self, ip: str, limit: int = 100) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM actions WHERE ip=? ORDER BY timestamp DESC LIMIT ?",
                (ip, min(max(limit, 1), 1000)),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_intelligence(self, ip: str, source: str) -> dict | None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM threat_intelligence
                WHERE ip=? AND source=? AND expires_at>?
                ORDER BY checked_at DESC LIMIT 1""",
                (ip, source, now),
            ).fetchone()
        return self._intelligence(row) if row else None

    def put_intelligence(self, result, checked_at: datetime, expires_at: datetime) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO threat_intelligence
                (ip,source,result,score,reason,attributes,checked_at,expires_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (
                    result.ip,
                    result.source,
                    int(result.listed),
                    result.score,
                    result.reason,
                    json.dumps(result.attributes, separators=(",", ":")),
                    checked_at.isoformat(),
                    expires_at.isoformat(),
                ),
            )

    def intelligence_history(self, ip: str, limit: int = 100) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM threat_intelligence WHERE ip=?
                ORDER BY checked_at DESC LIMIT ?""",
                (ip, min(max(limit, 1), 1000)),
            ).fetchall()
        return [self._intelligence(row) for row in rows]

    def threat_sources(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT source, COUNT(*) AS cached_results, MAX(checked_at) AS last_checked
                FROM threat_intelligence GROUP BY source ORDER BY source"""
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _intelligence(row: sqlite3.Row) -> dict:
        return {
            "source": row["source"],
            "ip": row["ip"],
            "listed": bool(row["result"]),
            "score": row["score"],
            "reason": row["reason"],
            "attributes": json.loads(row["attributes"]),
            "checked_at": row["checked_at"],
            "expires_at": row["expires_at"],
        }
