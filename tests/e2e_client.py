"""Deterministic black-box client for the isolated HAProxy/Sentinel stack."""
import json
import os
import time
import urllib.error
import urllib.request

TARGET = os.environ["TARGET_URL"]
SENTINEL = os.environ["SENTINEL_URL"]
HEADERS = {"Authorization": f"Bearer {os.environ['SENTINEL_KEY']}"}


def request(path: str, method: str = "GET") -> int:
    req = urllib.request.Request(TARGET + path, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def api(path: str):
    req = urllib.request.Request(SENTINEL + path, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def wait_for_events(count: int):
    for _ in range(30):
        events = api("/api/v1/events?limit=500")["items"]
        if len(events) >= count:
            return events
        time.sleep(1)
    raise AssertionError(f"expected at least {count} events")


def inject_docker_fixture():
    """Use ingestion without granting this isolated stack a Docker socket."""
    payload = {
        "source": "docker",
        "ip": "unknown",
        "service": "e2e-testservice",
        "event_type": "docker_restart",
        "severity": "medium",
        "metadata": {"actor_id": "e2e-testservice", "action": "restart"},
    }
    req = urllib.request.Request(
        SENTINEL + "/events",
        data=json.dumps(payload).encode(),
        headers={**HEADERS, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5):
        pass


def main():
    assert request("/") in (200, 503)
    baseline = len(wait_for_events(1))
    for _ in range(22):
        request("/login", "POST")
    assert request("/backend-error") in (404, 502, 503)
    for path in ("/.env", "/.git/config", "/wp-admin", "/admin", "/phpmyadmin"):
        request(path)
    events = wait_for_events(baseline + 27)
    assert any(event["event_type"] == "request" for event in events)
    dashboard = api("/api/v1/dashboard")
    assert dashboard["events_24h"] >= baseline + 27
    assert dashboard["current_risk"] > 0
    assert api("/api/v1/incidents?limit=100")["items"]
    mcp_payload = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "security.get_services", "arguments": {}},
    }
    req = urllib.request.Request(
        SENTINEL + "/mcp",
        data=json.dumps(mcp_payload).encode(),
        headers={**HEADERS, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        assert json.load(response)["result"]["content"]
    inject_docker_fixture()
    assert api("/api/v1/dashboard")["container_count"] >= 1
    print(json.dumps({"pipeline": "ok", "mcp": "ok", "docker_fixture": "ok"}))


if __name__ == "__main__":
    main()
