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
CREATE TABLE IF NOT EXISTS device_profiles (
  device_id TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  known_regions TEXT DEFAULT '[]',
  typical_hours TEXT DEFAULT '[]',
  services TEXT DEFAULT '[]',
  user_agents TEXT DEFAULT '[]',
  languages TEXT DEFAULT '[]',
  timezones TEXT DEFAULT '[]',
  tls_fingerprints TEXT DEFAULT '[]',
  ip_history TEXT DEFAULT '[]',
  trust_score INTEGER DEFAULT 50,
  positive_event_count INTEGER DEFAULT 0,
  negative_event_count INTEGER DEFAULT 0,
  blocked_event_count INTEGER DEFAULT 0,
  positive_confidence REAL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS device_first_seen ON device_profiles(first_seen);
CREATE TABLE IF NOT EXISTS behavior_baselines (
  service TEXT NOT NULL,
  pattern TEXT NOT NULL,
  confidence REAL DEFAULT 0.0,
  sample_count INTEGER DEFAULT 0,
  first_seen TEXT,
  last_seen TEXT,
  recommendation TEXT DEFAULT '',
  PRIMARY KEY(service, pattern)
);
CREATE INDEX IF NOT EXISTS behavior_service ON behavior_baselines(service);
CREATE TABLE IF NOT EXISTS behavior_anomalies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL, event_id TEXT NOT NULL, ip TEXT NOT NULL,
  device_id TEXT, service TEXT NOT NULL, source TEXT NOT NULL,
  score INTEGER NOT NULL, reason TEXT NOT NULL, kind TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS behavior_anomalies_lookup
  ON behavior_anomalies(ip, device_id, service, timestamp);

"""


class SecurityStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._memory_db: sqlite3.Connection | None = None
        if str(path) == ":memory:":
            self._memory_db = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_db.row_factory = sqlite3.Row
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)
            self._migrate(db)

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        event_columns = {row["name"] for row in db.execute("PRAGMA table_info(events)")}
        for name in (
            "path",
            "method",
            "user_agent",
            "hostname",
            "country",
            "asn",
            "accept_language",
            "client_timezone",
            "device_id",
            "tls_fingerprint",
        ):
            if name not in event_columns:
                db.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
        profile_columns = {row["name"] for row in db.execute("PRAGMA table_info(ip_profile)")}
        if "reasons" not in profile_columns:
            db.execute("ALTER TABLE ip_profile ADD COLUMN reasons TEXT NOT NULL DEFAULT '[]'")
        if "factors" not in profile_columns:
            db.execute("ALTER TABLE ip_profile ADD COLUMN factors TEXT NOT NULL DEFAULT '[]'")
        device_columns = {row["name"] for row in db.execute("PRAGMA table_info(device_profiles)")}
        for name in (
            "user_agents",
            "languages",
            "timezones",
            "tls_fingerprints",
            "ip_history",
        ):
            if name not in device_columns:
                db.execute(f"ALTER TABLE device_profiles ADD COLUMN {name} TEXT DEFAULT '[]'")
        baseline_pk = [
            row["name"] for row in db.execute("PRAGMA table_info(behavior_baselines)") if row["pk"]
        ]
        if baseline_pk == ["pattern"]:
            db.executescript(
                """
                ALTER TABLE behavior_baselines RENAME TO behavior_baselines_legacy;
                CREATE TABLE behavior_baselines (
                  service TEXT NOT NULL, pattern TEXT NOT NULL,
                  confidence REAL DEFAULT 0.0, sample_count INTEGER DEFAULT 0,
                  first_seen TEXT, last_seen TEXT, recommendation TEXT DEFAULT '',
                  PRIMARY KEY(service, pattern)
                );
                INSERT OR IGNORE INTO behavior_baselines
                  SELECT service,pattern,confidence,sample_count,first_seen,last_seen,recommendation
                  FROM behavior_baselines_legacy;
                DROP TABLE behavior_baselines_legacy;
                CREATE INDEX IF NOT EXISTS behavior_service ON behavior_baselines(service);
                """
            )
        db.execute("CREATE INDEX IF NOT EXISTS events_ip_path_time ON events(ip,path,timestamp)")

    def connect(self) -> sqlite3.Connection:
        if self._memory_db is not None:
            return self._memory_db
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def add_event(self, event: SecurityEvent, score: int = 0) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT OR IGNORE INTO events
                (id,timestamp,source,ip,service,event_type,severity,score,metadata,
                 path,method,user_agent,hostname,country,asn,accept_language,client_timezone,device_id,tls_fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                    event.accept_language,
                    event.client_timezone,
                    event.device_id,
                    event.tls_fingerprint,
                ),
            )

    def update_event_score(self, event_id: str, score: int) -> None:
        with self.connect() as db:
            db.execute("UPDATE events SET score=? WHERE id=?", (score, event_id))

    def recent_events(self, ip: str, window_seconds: int) -> list[SecurityEvent]:
        since = (datetime.now(UTC) - timedelta(seconds=window_seconds)).isoformat()
        with self.connect() as db:
            try:
                db.execute("SELECT 1 FROM events LIMIT 1")
            except Exception:
                return []
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
            accept_language=row["accept_language"],
            client_timezone=row["client_timezone"],
            device_id=row["device_id"],
            tls_fingerprint=row["tls_fingerprint"],
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

    def get_device_profile(self, device_id: str | None) -> dict | None:
        if not device_id:
            return None
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM device_profiles WHERE device_id=?", (device_id,)
            ).fetchone()
        if not row:
            return None
        profile = dict(row)
        for key in self._device_list_fields():
            try:
                value = json.loads(profile.get(key) or "[]")
                profile[key] = value if isinstance(value, list) else []
            except (TypeError, json.JSONDecodeError):
                profile[key] = []
        return profile

    @staticmethod
    def _device_list_fields() -> tuple[str, ...]:
        return (
            "known_regions",
            "typical_hours",
            "services",
            "user_agents",
            "languages",
            "timezones",
            "tls_fingerprints",
            "ip_history",
        )

    @staticmethod
    def _bounded(values: list, limit: int = 32) -> list[str]:
        return list(dict.fromkeys(str(value) for value in values if value not in (None, "")))[
            -limit:
        ]

    def update_device_profile(
        self,
        device_id: str,
        event: SecurityEvent,
        *,
        safe: bool,
        blocked: bool = False,
    ) -> None:
        if not device_id:
            return
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM device_profiles WHERE device_id=?", (device_id,)
            ).fetchone()
            current = dict(row) if row else {}
            values: dict[str, list[str]] = {}
            for field in self._device_list_fields():
                try:
                    decoded = json.loads(current.get(field) or "[]")
                    values[field] = decoded if isinstance(decoded, list) else []
                except (TypeError, json.JSONDecodeError):
                    values[field] = []
            if safe:
                additions = {
                    "known_regions": event.country,
                    "typical_hours": event.timestamp.hour,
                    "services": event.service,
                    "user_agents": event.user_agent,
                    "languages": event.accept_language,
                    "timezones": event.client_timezone,
                    "tls_fingerprints": event.tls_fingerprint,
                    "ip_history": event.ip,
                }
                for field, value in additions.items():
                    values[field] = self._bounded([*values[field], value])
            positive = int(current.get("positive_event_count", 0)) + int(safe)
            negative = int(current.get("negative_event_count", 0)) + int(not safe)
            blocked_count = int(current.get("blocked_event_count", 0)) + int(blocked)
            confidence = min(0.99, positive / max(3, positive + negative))
            trusted_positive = max(0, positive - blocked_count)
            increase = (
                min(20, trusted_positive) if trusted_positive >= 10 and confidence >= 0.5 else 0
            )
            trust_score = max(0, min(100, 50 + increase - min(30, negative * 5)))
            serialized = [
                json.dumps(values[field], separators=(",", ":"))
                for field in self._device_list_fields()
            ]
            db.execute(
                """INSERT INTO device_profiles
                (device_id,first_seen,last_seen,known_regions,typical_hours,services,user_agents,
                 languages,timezones,tls_fingerprints,ip_history,trust_score,positive_event_count,
                 negative_event_count,blocked_event_count,positive_confidence)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen,
                known_regions=excluded.known_regions,typical_hours=excluded.typical_hours,
                services=excluded.services,user_agents=excluded.user_agents,
                languages=excluded.languages,timezones=excluded.timezones,
                tls_fingerprints=excluded.tls_fingerprints,ip_history=excluded.ip_history,
                trust_score=excluded.trust_score,
                positive_event_count=excluded.positive_event_count,
                negative_event_count=excluded.negative_event_count,
                blocked_event_count=excluded.blocked_event_count,
                positive_confidence=excluded.positive_confidence""",
                (
                    device_id,
                    current.get("first_seen", now),
                    now,
                    *serialized,
                    trust_score,
                    positive,
                    negative,
                    blocked_count,
                    confidence,
                ),
            )

    def observe_baseline(self, service: str, pattern: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            db.execute(
                """INSERT INTO behavior_baselines
                (service,pattern,confidence,sample_count,first_seen,last_seen,recommendation)
                VALUES(?,?,0.05,1,?,?,'observe')
                ON CONFLICT(service,pattern) DO UPDATE SET
                sample_count=MIN(10000,behavior_baselines.sample_count+1),
                confidence=MIN(0.99,behavior_baselines.confidence+0.01),
                last_seen=excluded.last_seen""",
                (service, pattern, now, now),
            )

    def baselines(self, service: str) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM behavior_baselines WHERE service=? ORDER BY confidence DESC",
                (service,),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_anomalies(self, event: SecurityEvent, factors: list) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            db.executemany(
                """INSERT INTO behavior_anomalies
                (timestamp,event_id,ip,device_id,service,source,score,reason,kind)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        now,
                        event.event_id,
                        event.ip,
                        event.device_id,
                        event.service,
                        factor.source,
                        factor.score,
                        factor.reason,
                        factor.kind,
                    )
                    for factor in factors
                    if factor.score > 0
                ],
            )

    def behavior_anomalies(
        self, *, ip: str | None = None, service: str | None = None, limit: int = 100
    ) -> list[dict]:
        clauses, args = [], []
        if ip:
            clauses.append("ip=?")
            args.append(ip)
        if service:
            clauses.append("service=?")
            args.append(service)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        args.append(min(max(limit, 1), 1000))
        with self.connect() as db:
            rows = db.execute(
                f"SELECT * FROM behavior_anomalies{where} ORDER BY timestamp DESC LIMIT ?",
                args,
            ).fetchall()
        return [dict(row) for row in rows]

    def anomaly(self, anomaly_id: int) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM behavior_anomalies WHERE id=?", (anomaly_id,)
            ).fetchone()
        return dict(row) if row else None

    # Phase-4 bounded/paginated queries
    def profile_summary(self, limit: int = 100) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM ip_profile ORDER BY last_seen DESC LIMIT ?",
                (min(max(limit, 1), 500),),
            ).fetchall()
        return [dict(row) for row in rows]

    def event_count_24h(self) -> int:
        since = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        with self.connect() as db:
            row = db.execute(
                "SELECT COUNT(*) AS c FROM events WHERE timestamp >= ?",
                (since,),
            ).fetchone()
        return row["c"] if row else 0

    def action_count_24h(self, action: str) -> int:
        since = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        with self.connect() as db:
            row = db.execute(
                "SELECT COUNT(*) AS c FROM actions WHERE action = ? AND timestamp >= ?",
                (action, since),
            ).fetchone()
        return row["c"] if row else 0

    def events_paged(self, ip: str | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        sql = "SELECT * FROM events"
        args: list = []
        if ip:
            sql += " WHERE ip = ?"
            args.append(ip)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        args.append(min(max(limit, 1), 1000))
        args.append(max(offset, 0))
        with self.connect() as db:
            rows = db.execute(sql, args).fetchall()
        return [self._event_dict(row) for row in rows]

    def incidents_paged(self, limit: int = 100, offset: int = 0) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT * FROM actions WHERE action != 'allow'
                ORDER BY timestamp DESC LIMIT ? OFFSET ?""",
                (min(max(limit, 1), 1000), max(offset, 0)),
            ).fetchall()
        return [dict(row) for row in rows]

    def services_list(self, limit: int = 50) -> list[str]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT DISTINCT service FROM events ORDER BY service DESC LIMIT ?",
                (min(max(limit, 1), 200),),
            ).fetchall()
        return [row[0] for row in rows if row[0]]

    def top_ips(self, limit: int = 10) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT ip, COUNT(*) AS count FROM events GROUP BY ip ORDER BY count DESC LIMIT ?",
                (min(max(limit, 1), 50),),
            ).fetchall()
        return [{"ip": row["ip"], "count": row["count"]} for row in rows]

    def source_service_count(self, source: str) -> int:
        with self.connect() as db:
            row = db.execute(
                "SELECT COUNT(DISTINCT service) AS count FROM events WHERE source = ?",
                (source,),
            ).fetchone()
        return int(row["count"]) if row else 0

    def severity_count_24h(self, severities: tuple[str, ...]) -> int:
        if not severities:
            return 0
        since = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        placeholders = ",".join("?" for _ in severities)
        with self.connect() as db:
            row = db.execute(
                f"SELECT COUNT(*) AS count FROM events WHERE timestamp >= ? "
                f"AND severity IN ({placeholders})",
                (since, *severities),
            ).fetchone()
        return int(row["count"]) if row else 0

    def service_health_summary(self, limit: int = 50) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT service, MAX(timestamp) AS last_event,
                   MAX(score) AS risk_score,
                   SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END) AS warnings
                   FROM events WHERE service IS NOT NULL AND service != ''
                   GROUP BY service ORDER BY last_event DESC LIMIT ?""",
                (min(max(limit, 1), 200),),
            ).fetchall()
        return [dict(row) for row in rows]

    def devices_for_ip(self, ip: str, limit: int = 20) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM device_profiles WHERE ip_history LIKE ? LIMIT ?",
                (f'%"{ip}"%', min(max(limit, 1), 100)),
            ).fetchall()
        profiles = []
        for row in rows:
            profile = self.get_device_profile(row["device_id"])
            if profile and ip in profile["ip_history"]:
                profiles.append(profile)
        return profiles

    def services_dashboard(self, rolling_window_hours: int = 24) -> list[dict]:
        since = (datetime.now(UTC) - timedelta(hours=rolling_window_hours)).isoformat()
        with self.connect() as db:
            # Ensure events table exists (graceful for fresh/empty DB)
            try:
                db.execute("SELECT COUNT(*) FROM events LIMIT 1")
            except sqlite3.OperationalError:
                return []

            rows = db.execute(
                """SELECT service,
                   MAX(timestamp) AS last_event,
                   MAX(score) AS current_risk,
                   COUNT(*) AS event_count,
                   SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END) AS warnings,
                   MAX(timestamp) AS latest_timestamp
                   FROM events
                   WHERE service IS NOT NULL AND service != ''
                   AND timestamp >= ?
                   GROUP BY service
                   ORDER BY last_event DESC""",
                (since,),
            ).fetchall()
        results = []
        for row in rows:
            service = row["service"]
            # Derive observed status from latest lifecycle/backend evidence
            latest_row = db.execute(
                "SELECT event_type FROM events WHERE service = ? "
                "ORDER BY timestamp DESC LIMIT 1",
                (service,),
            ).fetchone()
            latest_event_type = latest_row["event_type"] if latest_row else "unknown"
            observed_status = "unknown"
            # Actual container/service lifecycle evidence from events
            lifecycle_rows = db.execute(
                "SELECT event_type FROM events WHERE service = ? ORDER BY timestamp DESC LIMIT 5",
                (service,),
            ).fetchall()
            lifecycle_evidence = [r[0] for r in lifecycle_rows]
            # Derive status from latest lifecycle evidence
            if lifecycle_evidence:
                last_type = lifecycle_evidence[0]
                if last_type in (
                    "service_start",
                    "start",
                    "start_service",
                    "container_start",
                    "docker_start",
                ):
                    observed_status = "running"
                elif last_type in (
                    "service_stop",
                    "stop",
                    "service_stop_service",
                    "container_stop",
                    "docker_stop",
                ):
                    observed_status = "stopped"
                elif last_type in (
                    "service_restart",
                    "restart",
                    "service_restart_service",
                    "container_restart",
                    "docker_restart",
                ):
                    observed_status = "restarting"
                elif last_type in (
                    "service_create",
                    "create",
                    "service_create_service",
                    "container_create",
                    "docker_create",
                ):
                    observed_status = "created"
            else:
                # No lifecycle evidence in rolling window; check broader events
                broader = db.execute(
                    "SELECT event_type FROM events WHERE service = ? "
                    "ORDER BY timestamp DESC LIMIT 20",
                    (service,),
                ).fetchall()
                broader_evidence = [r[0] for r in broader]
                if broader_evidence:
                    first = broader_evidence[0]
                    if "start" in first or first.startswith("start"):
                        observed_status = "running"
                    elif "stop" in first or first.startswith("stop"):
                        observed_status = "stopped"
                    elif "restart" in first or first.startswith("restart"):
                        observed_status = "restarting"
                    else:
                        observed_status = "unknown"
                else:
                    observed_status = "unknown"
            results.append(
                {
                    "service": service,
                    "observed_status": observed_status,
                    "current_risk": row["current_risk"] or 0,
                    "last_activity": row["last_event"],
                    "last_event_type": latest_event_type or "unknown",
                    "rolling_window_hours": rolling_window_hours,
                    "event_count": row["event_count"] or 0,
                    "warnings_24h": row["warnings"] or 0,
                }
            )
        return results

    def service_state_evidence(self, service: str, limit: int = 20) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT event_type, timestamp FROM events WHERE service = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (service, min(max(limit, 1), 200)),
            ).fetchall()
        return [{"event_type": r[0], "timestamp": r[1]} for r in rows]

    @staticmethod
    def _event_dict(row) -> dict:
        return {
            "event_id": row["id"],
            "timestamp": row["timestamp"],
            "source": row["source"],
            "ip": row["ip"],
            "service": row["service"],
            "event_type": row["event_type"],
            "severity": row["severity"],
            "score": row["score"],
        }
