from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class IntegrityFinding:
    kind: str
    subject: str
    status: str
    severity: str
    score: int
    details: dict[str, Any] = field(default_factory=dict)


class IntegrityEngine:
    """Read-only integrity analysis. It never authorizes enforcement actions."""

    @staticmethod
    def docker_changes(
        previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
    ) -> list[IntegrityFinding]:
        findings: list[IntegrityFinding] = []
        for name, item in current.items():
            old = previous.get(name)
            if old is None:
                findings.append(
                    IntegrityFinding(
                        "unknown_container",
                        name,
                        "new",
                        "medium",
                        55,
                        {"image": item.get("image"), "digest": item.get("digest")},
                    )
                )
                continue
            changed = {
                key: (old.get(key), item.get(key))
                for key in ("image", "digest", "ports", "privileged", "mounts")
                if old.get(key) != item.get(key)
            }
            if changed:
                kind = (
                    "docker_image_digest_changed"
                    if set(changed) <= {"image", "digest"}
                    else "docker_container_changed"
                )
                findings.append(
                    IntegrityFinding(
                        kind,
                        name,
                        "changed",
                        "high" if "privileged" in changed else "medium",
                        75 if "privileged" in changed else 50,
                        {"changes": changed},
                    )
                )
        for name in previous.keys() - current.keys():
            findings.append(
                IntegrityFinding("container_missing", name, "missing", "medium", 50, {})
            )
        return findings

    @staticmethod
    def hash_file(path: str | Path, max_bytes: int = 32 * 1024 * 1024) -> str | None:
        target = Path(path)
        if not target.is_file() or target.is_symlink() or target.stat().st_size > max_bytes:
            return None
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @classmethod
    def file_changes(
        cls, previous: dict[str, str], paths: list[str | Path]
    ) -> list[IntegrityFinding]:
        current = {str(path): cls.hash_file(path) for path in paths}
        findings: list[IntegrityFinding] = []
        for path, digest in current.items():
            if digest is None:
                if path in previous:
                    findings.append(
                        IntegrityFinding(
                            "integrity_file_hash_changed", path, "unreadable", "high", 70, {}
                        )
                    )
            elif path not in previous:
                findings.append(
                    IntegrityFinding(
                        "integrity_file_hash_baseline", path, "new", "info", 0, {"sha256": digest}
                    )
                )
            elif previous[path] != digest:
                findings.append(
                    IntegrityFinding(
                        "integrity_file_hash_changed",
                        path,
                        "changed",
                        "high",
                        80,
                        {"previous": previous[path], "sha256": digest},
                    )
                )
        return findings

    @staticmethod
    def package_findings(
        report: str | dict[str, Any] | list[dict[str, Any]],
    ) -> list[IntegrityFinding]:
        payload = json.loads(report) if isinstance(report, str) else report
        entries = payload.get("vulnerabilities", payload) if isinstance(payload, dict) else payload
        findings = []
        for item in entries or []:
            if not isinstance(item, dict):
                continue
            ids = item.get("ids") or item.get("cve") or item.get("aliases") or []
            if isinstance(ids, str):
                ids = [ids]
            package = item.get("name") or item.get("package") or "unknown"
            severity = str(item.get("severity", "high")).lower()
            score = 90 if severity in {"critical", "high"} else 60
            findings.append(
                IntegrityFinding(
                    "package_vulnerability",
                    package,
                    "vulnerable",
                    severity,
                    score,
                    {
                        "ids": ids,
                        "version": item.get("version"),
                        "fix_versions": item.get("fix_versions") or item.get("fix_version"),
                    },
                )
            )
        return findings
