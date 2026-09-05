import ipaddress
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import ValidationError

from core.api.v1.schemas import (
    ConfigUpdate,
    DashboardSummary,
    Page,
    ServiceItem,
    ServicesResponse,
    WebLogin,
)
from core.config_manager import UnknownConfigurationError

router = APIRouter(prefix="/api/v1")


def authenticate(request: Request) -> None:
    expected = request.app.state.settings.sentinel_api_key
    authorization = request.headers.get("authorization", "")
    supplied = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
    if request.app.state.web_sessions.enabled:
        if not request.app.state.web_sessions.validate(supplied):
            raise HTTPException(status_code=401, detail="invalid or expired web session")
        return
    if not expected:
        return
    if not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="invalid API key")


secured = [Depends(authenticate)]


@router.get("/auth/status")
def auth_status(request: Request):
    return {"two_factor_enabled": request.app.state.web_sessions.enabled}


@router.post("/auth/session")
def create_session(request: Request, login: WebLogin):
    manager = request.app.state.web_sessions
    if not manager.enabled:
        raise HTTPException(status_code=404, detail="web 2FA is disabled")
    client = request.client.host if request.client else "unknown"
    token = manager.login(client, login.api_key, login.totp_code)
    if not token:
        raise HTTPException(status_code=401, detail="invalid credentials or rate limited")
    return {"token": token, "expires_in": manager.ttl_seconds}


@router.post("/auth/logout", dependencies=secured, status_code=204)
def logout(request: Request):
    authorization = request.headers.get("authorization", "")
    request.app.state.web_sessions.logout(authorization.removeprefix("Bearer "))


def valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address") from None


@router.get("/dashboard", response_model=DashboardSummary, dependencies=secured)
def dashboard(request: Request):
    store = request.app.state.store
    profiles = store.profile_summary(500)
    return DashboardSummary(
        current_risk=max((row["risk_score"] for row in profiles), default=0),
        events_24h=store.event_count_24h(),
        blocks_24h=store.action_count_24h("block"),
        challenges_24h=store.action_count_24h("challenge"),
        top_attackers=store.top_ips(10),
        affected_services=store.services_list(50),
        container_count=store.source_service_count("docker"),
        service_health=store.service_health_summary(50),
        warnings_24h=store.severity_count_24h(("high", "critical")),
        last_events=store.events_paged(None, 10, 0),
    )


@router.get("/events", response_model=Page, dependencies=secured)
def events(
    request: Request,
    ip: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    address = valid_ip(ip) if ip else None
    return Page(
        items=request.app.state.store.events_paged(address, limit, offset),
        limit=limit,
        offset=offset,
    )


@router.get("/incidents", response_model=Page, dependencies=secured)
def incidents(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    return Page(
        items=request.app.state.store.incidents_paged(limit, offset),
        limit=limit,
        offset=offset,
    )


@router.get("/incidents/{incident_id}", dependencies=secured)
def incident_detail(request: Request, incident_id: str):
    incident = request.app.state.store.incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@router.get("/incidents/{incident_id}/history", dependencies=secured)
def incident_history(request: Request, incident_id: str):
    if not request.app.state.store.incident(incident_id):
        raise HTTPException(status_code=404, detail="incident not found")
    return {
        "incident_id": incident_id,
        "timeline": request.app.state.store.incident_history(incident_id),
    }


@router.patch("/incidents/{incident_id}", dependencies=secured)
def update_incident(request: Request, incident_id: str, update: dict):
    try:
        result = request.app.state.store.update_incident_status(
            incident_id, str(update.get("status", "")), str(update.get("note", ""))
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if not result:
        raise HTTPException(status_code=404, detail="incident not found")
    return result


@router.get("/ip/{ip}", dependencies=secured)
def ip_detail(request: Request, ip: str):
    address = valid_ip(ip)
    store = request.app.state.store
    return {
        "ip": address,
        "profile": store.profile(address),
        "events": store.events_paged(address, 100, 0),
        "actions": store.action_history(address),
        "threat_intelligence": store.intelligence_history(address),
        "devices": store.devices_for_ip(address),
    }


@router.get("/config/{name}", dependencies=secured)
def get_config(request: Request, name: str):
    try:
        return {"name": name, "value": request.app.state.config_manager.read(name)}
    except UnknownConfigurationError:
        raise HTTPException(status_code=404, detail="unknown configuration") from None
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_input=False)) from None


@router.put("/config/{name}", dependencies=secured)
def update_config(request: Request, name: str, update: ConfigUpdate):
    try:
        return request.app.state.config_manager.update(name, update.value)
    except UnknownConfigurationError:
        raise HTTPException(status_code=404, detail="unknown configuration") from None
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_input=False)) from None


@router.get("/threat-intelligence", dependencies=secured)
def threat_intelligence(request: Request):
    return {
        "configuration": request.app.state.config_manager.read("intelligence"),
        "cache": request.app.state.store.threat_sources(),
    }


@router.get("/risk-policy", dependencies=secured)
def risk_policy(request: Request):
    return {
        "rules": request.app.state.config_manager.read("rules"),
        "policy": request.app.state.config_manager.read("policy"),
    }


@router.get("/policies", dependencies=secured)
def policies(request: Request):
    config = request.app.state.settings.load_policy()
    return {
        "rules": config.rules,
        "thresholds": {
            "allow_below": config.allow_below,
            "challenge_below": config.challenge_below,
        },
        "require_explicit_block_rule": config.require_explicit_block_rule,
        "actions": ["log_only", "alert", "anubis_challenge", "haproxy_block", "rate_limit"],
    }


@router.post("/policies/test", dependencies=secured)
def test_policy(request: Request, payload: dict):
    score = int(payload.get("risk_score", 0))
    return request.app.state.service.policy.test(score, payload.get("context"))


@router.get("/haproxy", dependencies=secured)
async def haproxy(request: Request):
    runtime = request.app.state.runtime
    settings = request.app.state.settings
    response = {"connected": False, "actions_enabled": settings.actions_enabled, "backends": []}
    try:
        statistics = await runtime.command("show stat")
        response["connected"] = True
        response["backends"] = sorted(
            {
                columns[0]
                for line in statistics.splitlines()
                if line and not line.startswith("#") and len(columns := line.split(",")) > 1
            }
        )[:100]
    except (FileNotFoundError, ConnectionError, OSError):
        pass
    return response


@router.get("/challenge", dependencies=secured)
def challenge(request: Request):
    settings = request.app.state.settings
    policy = settings.load_policy()
    return {
        "enabled": policy.challenge_enabled,
        "provider": policy.challenge_provider,
        "configured": bool(settings.anubis_url),
        "challenge_below": policy.challenge_below,
    }


@router.get("/llm", dependencies=secured)
def llm_status(request: Request):
    settings = request.app.state.settings
    return {
        "provider": settings.llm_provider,
        "model": settings.model,
        "endpoint": settings.local_llm_url if settings.llm_provider == "local" else None,
        "credential_configured": bool(settings.openrouter_api_key),
        "action_control": False,
    }


@router.get("/services", response_model=ServicesResponse, dependencies=secured)
def services_dashboard(
    request: Request,
    rolling_window_hours: int = Query(24, ge=1, le=168),
):
    store = request.app.state.store
    services_agg = store.services_dashboard(rolling_window_hours=rolling_window_hours)
    # Preserve existing summary keys for compatibility
    container_services = store.services_list(50)
    services_items = [
        ServiceItem(
            service=item["service"],
            observed_status=item["observed_status"],
            current_risk=item["current_risk"],
            rolling_window_hours=item.get("rolling_window_hours", rolling_window_hours),
            last_activity=item.get("last_activity"),
            last_event_type=item.get("last_event_type", "unknown"),
            event_count=item.get("event_count", 0),
            warnings_24h=item.get("warnings_24h", 0),
        )
        for item in services_agg
    ]
    # Derive actual container/service status from relevant lifecycle evidence
    # Generic requests cannot fake healthy container; unknown when no lifecycle evidence
    return ServicesResponse(
        services=services_items,
        rolling_window_hours=rolling_window_hours,
        container_services=container_services,
        warnings_summary=sum(s.get("warnings_24h", 0) for s in services_items),
        incidents_summary=store.action_count_24h("block") + store.action_count_24h("challenge"),
    )


@router.get("/integrity", dependencies=secured)
def integrity(request: Request, limit: int = Query(100, ge=1, le=500), status: str | None = None):
    store = request.app.state.store
    return {
        "summary": store.integrity_summary(),
        "findings": store.integrity_findings(limit, status),
    }


@router.get("/mcp", dependencies=secured)
def mcp_status(request: Request):
    return {
        "status": "available",
        "tools": [definition["name"] for definition in request.app.state.tools.definitions()],
    }


@router.post("/haproxy/unblock/{ip}", dependencies=secured)
async def unblock(request: Request, ip: str):
    return await request.app.state.service.haproxy.unblock(valid_ip(ip))
