import hashlib
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
from core.auth import audit, authenticate, credential_principal, scoped
from core.config_manager import UnknownConfigurationError
from core.permissions import Role, current_role

router = APIRouter(prefix="/api/v1")


secured = [Depends(authenticate)]


@router.get("/auth/status")
def auth_status(request: Request):
    return {"two_factor_enabled": request.app.state.web_sessions.enabled}


@router.get("/setup/status")
def setup_status(request: Request):
    return {"initialized": request.app.state.store.setup_initialized(), "version": "0.5.0"}


@router.post("/setup/initialize")
def setup_initialize(request: Request, payload: dict):
    if request.app.state.store.setup_initialized():
        raise HTTPException(status_code=409, detail="setup already initialized")
    bootstrap = request.headers.get("x-bootstrap-token", "")
    configured = request.app.state.settings.setup_bootstrap_token
    if not configured or not secrets.compare_digest(bootstrap.encode(), configured.encode()):
        raise HTTPException(status_code=401, detail="valid bootstrap token required")
    username = str(payload.get("username", "")).strip()
    api_key = str(payload.get("api_key", ""))
    if not username or len(username) > 128 or len(api_key) < 32 or len(api_key) > 4096:
        raise HTTPException(status_code=422, detail="username and a strong api_key are required")
    reserved = list(request.app.state.settings.role_credentials.values())
    reserved += [item.token for item in request.app.state.settings.collector_credentials.values()]
    reserved.append(configured)
    if api_key in reserved:
        raise HTTPException(422, "setup requires an independent new credential")
    created = request.app.state.store.initialize_setup(
        username, "administrator", hashlib.sha256(api_key.encode()).hexdigest(), "0.5.0"
    )
    if not created:
        raise HTTPException(status_code=409, detail="setup already initialized")
    request.app.state.store.add_audit(
        str(
            request.app.state.store.user_by_credential(
                hashlib.sha256(api_key.encode()).hexdigest()
            )["id"]
        ),
        "setup.initialize",
        {},
        {"role": "administrator"},
        session_id="bootstrap",
    )
    return {
        "initialized": True,
        "role": "administrator",
        "message": "Credentials are active. Bootstrap is now disabled.",
    }


@router.post("/auth/session")
def create_session(request: Request, login: WebLogin):
    manager = request.app.state.web_sessions
    if not manager.enabled:
        raise HTTPException(status_code=404, detail="web 2FA is disabled")
    client = request.client.host if request.client else "unknown"
    principal = credential_principal(request.app.state, login.api_key)
    token = (
        manager.login(
            client, login.api_key, login.totp_code, credential_verified=principal is not None
        )
        if principal
        else None
    )
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


@router.get(
    "/dashboard", response_model=DashboardSummary, dependencies=[Depends(scoped("incident.read"))]
)
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


@router.get("/events", response_model=Page, dependencies=[Depends(scoped("incident.read"))])
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


@router.get("/incidents", response_model=Page, dependencies=[Depends(scoped("incident.read"))])
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


@router.get("/incidents/{incident_id}", dependencies=[Depends(scoped("incident.read"))])
def incident_detail(request: Request, incident_id: str):
    incident = request.app.state.store.incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@router.get("/ai/incident/{incident_id}", dependencies=[Depends(scoped("llm.analyze"))])
async def ai_incident(request: Request, incident_id: str):
    incident = request.app.state.store.incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        analysis = await request.app.state.tools._analyze_incident(incident)
    except Exception as exc:
        analysis = {"status": "unavailable", "reason": type(exc).__name__}
    return {"incident": incident, "analysis": analysis, "analysis_only": True}


@router.get("/incidents/{incident_id}/history", dependencies=[Depends(scoped("incident.read"))])
def incident_history(request: Request, incident_id: str):
    if not request.app.state.store.incident(incident_id):
        raise HTTPException(status_code=404, detail="incident not found")
    return {
        "incident_id": incident_id,
        "timeline": request.app.state.store.incident_history(incident_id),
    }


@router.patch("/incidents/{incident_id}", dependencies=[Depends(scoped("incident.write"))])
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


@router.get("/ip/{ip}", dependencies=[Depends(scoped("incident.read"))])
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


@router.get("/config/export", dependencies=[Depends(scoped("config.export"))])
def export_config(request: Request):
    return request.app.state.config_manager.export()


@router.get("/config/{name}", dependencies=[Depends(scoped("config.export"))])
def get_config(request: Request, name: str):
    try:
        return {"name": name, "value": request.app.state.config_manager.read(name)}
    except UnknownConfigurationError:
        raise HTTPException(status_code=404, detail="unknown configuration") from None
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_input=False)) from None


@router.put("/config/{name}", dependencies=[Depends(scoped("config.write"))])
def update_config(request: Request, name: str, update: ConfigUpdate):
    before = request.app.state.config_manager.read(name)
    try:
        result = request.app.state.config_manager.update(name, update.value)
        audit(
            request,
            f"config.update:{name}",
            before,
            update.value,
        )
        return result
    except UnknownConfigurationError:
        raise HTTPException(status_code=404, detail="unknown configuration") from None
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_input=False)) from None


@router.get("/threat-intelligence", dependencies=[Depends(scoped("policy.read"))])
def threat_intelligence(request: Request):
    return {
        "configuration": request.app.state.config_manager.read("intelligence"),
        "cache": request.app.state.store.threat_sources(),
    }


@router.get("/risk-policy", dependencies=[Depends(scoped("policy.read"))])
def risk_policy(request: Request):
    return {
        "rules": request.app.state.config_manager.read("rules"),
        "policy": request.app.state.config_manager.read("policy"),
    }


@router.get("/policies", dependencies=[Depends(scoped("policy.read"))])
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


@router.get("/actions", dependencies=[Depends(scoped("action.read"))])
def actions(request: Request, limit: int = Query(100, ge=1, le=500)):
    return {"actions": request.app.state.store.actions(limit)}


@router.post("/actions/{action_id}/revoke", dependencies=[Depends(scoped("action.execute"))])
async def revoke_action(request: Request, action_id: int):
    try:
        result = await request.app.state.service.lifecycle.revoke(action_id)
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(502, "rollback not confirmed") from exc
    if result is None:
        raise HTTPException(404, "action not found")
    audit(request, "action.revoke", after={"action_id": action_id})
    return result


@router.get("/audit-log", dependencies=[Depends(scoped("audit.read"))])
def audit_log(request: Request, limit: int = Query(100, ge=1, le=500)):
    return {"entries": request.app.state.store.audit_log(limit)}


@router.get("/reports/daily", dependencies=[Depends(scoped("report.create"))])
def daily_report(request: Request):
    return request.app.state.store.daily_report()


@router.get("/users", dependencies=[Depends(scoped("user.read"))])
def users(request: Request):
    return {
        "roles": [role.value for role in Role],
        "users": request.app.state.store.users(),
        "current_role": current_role(request).value,
    }


@router.post("/config/backup", dependencies=[Depends(scoped("config.export"))])
def backup_config(request: Request):
    path = request.app.state.config_manager.backup()
    audit(request, "config.backup", {}, {"path": str(path)})
    return {"backed_up": True, "path": str(path)}


@router.post("/config/import", dependencies=[Depends(scoped("config.write"))])
def import_config(request: Request, payload: dict):
    before = request.app.state.config_manager.export()
    try:
        result = request.app.state.config_manager.import_config(payload)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    audit(request, "config.import", before, payload)
    return result


@router.post("/policies/test", dependencies=[Depends(scoped("policy.read"))])
def test_policy(request: Request, payload: dict):
    score = int(payload.get("risk_score", 0))
    context = dict(payload.get("context") or {})
    context.update(
        {key: payload[key] for key in ("ip", "event_type", "source", "factors") if key in payload}
    )
    result = request.app.state.service.policy.test(score, context)
    result["dry_run"] = True
    result["preview"] = f"{result['action']} would be prepared; no action executed"
    return result


@router.get("/trusted-entities", dependencies=[Depends(scoped("policy.read"))])
def trusted_entities(request: Request):
    return {"entities": request.app.state.store.trusted_entities()}


@router.post("/trusted-entities", dependencies=[Depends(scoped("policy.write"))])
def add_trusted_entity(request: Request, payload: dict):
    entity_type = str(payload.get("entity_type", ""))
    if (
        entity_type not in {"ip", "network", "device"}
        or not payload.get("value")
        or not payload.get("reason")
    ):
        raise HTTPException(status_code=422, detail="entity_type, value and reason are required")
    audit(request, "trusted_entity.add", after=payload)
    return request.app.state.store.add_trusted_entity(
        entity_type, str(payload["value"]), str(payload["reason"]), payload.get("expires_at")
    )


@router.delete("/trusted-entities/{entity_id}", dependencies=[Depends(scoped("policy.write"))])
def disable_trusted_entity(request: Request, entity_id: int):
    audit(request, "trusted_entity.disable", after={"id": entity_id})
    if not request.app.state.store.disable_trusted_entity(entity_id):
        raise HTTPException(status_code=404, detail="trusted entity not found")
    return {"disabled": True, "id": entity_id}


@router.get("/haproxy", dependencies=[Depends(scoped("action.read"))])
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


@router.get("/challenge", dependencies=[Depends(scoped("policy.read"))])
def challenge(request: Request):
    settings = request.app.state.settings
    policy = settings.load_policy()
    return {
        "enabled": policy.challenge_enabled,
        "provider": policy.challenge_provider,
        "configured": bool(settings.anubis_url),
        "challenge_below": policy.challenge_below,
    }


@router.get("/llm", dependencies=[Depends(scoped("policy.read"))])
def llm_status(request: Request):
    settings = request.app.state.settings
    return {
        "provider": settings.llm_provider,
        "model": settings.model,
        "endpoint": settings.local_llm_url if settings.llm_provider == "local" else None,
        "credential_configured": bool(settings.openrouter_api_key),
        "action_control": False,
    }


@router.get(
    "/services", response_model=ServicesResponse, dependencies=[Depends(scoped("incident.read"))]
)
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


@router.get("/integrity", dependencies=[Depends(scoped("incident.read"))])
def integrity(request: Request, limit: int = Query(100, ge=1, le=500), status: str | None = None):
    store = request.app.state.store
    return {
        "summary": store.integrity_summary(),
        "findings": store.integrity_findings(limit, status),
    }


@router.get("/mcp", dependencies=[Depends(scoped("incident.read"))])
def mcp_status(request: Request):
    return {
        "status": "available",
        "tools": [definition["name"] for definition in request.app.state.tools.definitions()],
    }


@router.post("/haproxy/unblock/{ip}", dependencies=[Depends(scoped("action.execute"))])
async def unblock(request: Request, ip: str):
    result = await request.app.state.service.lifecycle.unblock(valid_ip(ip))
    audit(request, "action.unblock", after={"ip": valid_ip(ip)})
    return result
