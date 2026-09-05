import json

from engine.integrity import IntegrityEngine


def test_docker_digest_and_privilege_changes_are_findings():
    findings = IntegrityEngine.docker_changes(
        {"vaultwarden": {"image": "vw:1", "digest": "sha256:a", "privileged": False}},
        {"vaultwarden": {"image": "vw:1", "digest": "sha256:b", "privileged": True}},
    )
    assert {item.kind for item in findings} == {"docker_container_changed"}
    assert findings[0].score == 75


def test_file_hash_change(tmp_path):
    target = tmp_path / "sentinel.conf"
    target.write_text("safe")
    baseline = {str(target): IntegrityEngine.hash_file(target)}
    target.write_text("changed")
    findings = IntegrityEngine.file_changes(baseline, [target])
    assert findings[0].kind == "integrity_file_hash_changed"
    assert findings[0].details["previous"] != findings[0].details["sha256"]


def test_pip_audit_cve_report():
    report = {
        "vulnerabilities": [
            {"name": "urllib3", "version": "1", "ids": ["CVE-2025-1"], "fix_versions": ["2"]}
        ]
    }
    findings = IntegrityEngine.package_findings(json.dumps(report))
    assert findings[0].kind == "package_vulnerability"
    assert "CVE-2025-1" in findings[0].details["ids"]
