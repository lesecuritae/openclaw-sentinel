import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from actions.anubis import AnubisChallengeAdapter
from actions.haproxy import HAProxyActionAdapter
from collectors.auth import LinuxAuthCollector
from collectors.docker import DockerEventCollector
from collectors.haproxy import HAProxyCollector, HAProxyRequestCollector, HAProxyRuntimeClient
from collectors.integrity import IntegrityCollector
from collectors.service import ServiceLogCollector
from core.api.v1 import api_router, ws_router
from core.api.v1.ws.events import manager as event_manager
from core.auth import audit, authenticate, scoped
from core.config import Settings
from core.config_manager import ConfigManager
from core.event_security import IngestEvent, collector_identity, validate_event
from core.limits import RequestLimits
from core.service import SentinelService
from core.web_auth import WebSessionManager
from database.store import SecurityStore
from engine.detection import DetectionEngine
from engine.policy import PolicyEngine
from engine.risk import RiskEngine
from intelligence.factory import build_intelligence
from llm.gateway import LLMGateway
from mcp.server import SecurityTools

logging.basicConfig(level=logging.INFO)
settings = Settings()
store = SecurityStore(settings.database_path)
intelligence = build_intelligence(settings, store)
runtime = HAProxyRuntimeClient(settings.haproxy_socket)
service = SentinelService(
    store,
    DetectionEngine(settings.load_rules()),
    RiskEngine(settings.load_intelligence().single_source_ceiling),
    PolicyEngine(settings.load_policy()),
    HAProxyActionAdapter(runtime, settings.haproxy_blocklist_path, settings.actions_enabled),
    AnubisChallengeAdapter(settings.anubis_url),
    intelligence,
    event_manager.publish,
    settings.response_dry_run,
)
llm = LLMGateway.from_settings(settings)
tools = SecurityTools(service, store, llm, intelligence)
web_sessions = WebSessionManager(
    enabled=settings.web_2fa_enabled,
    api_key=settings.sentinel_api_key,
    secret=settings.web_2fa_secret,
    secret_file=Path(settings.web_2fa_secret_file) if settings.web_2fa_secret_file else None,
    ttl_seconds=settings.web_session_ttl_seconds,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await service.lifecycle.reconcile()
    tasks = [asyncio.create_task(service.lifecycle.run(settings.action_expiry_interval_seconds))]
    if settings.haproxy_collector_enabled:
        tasks.append(
            asyncio.create_task(
                HAProxyCollector(runtime, settings.collector_interval_seconds).run(service.process)
            )
        )
    if settings.haproxy_request_collector_enabled:
        tasks.append(
            asyncio.create_task(
                HAProxyRequestCollector(
                    settings.haproxy_request_host, settings.haproxy_request_port
                ).run(service.process)
            )
        )
    if settings.docker_collector_enabled:
        tasks.append(
            asyncio.create_task(
                DockerEventCollector(
                    enabled=True,
                    api_url=settings.docker_api_url,
                    allowed_containers=settings.allowed_containers,
                    allowed_images=settings.allowed_images,
                    settings=settings,
                ).run(service.process)
            )
        )
    if settings.auth_collector_enabled:
        tasks.append(
            asyncio.create_task(
                LinuxAuthCollector(
                    enabled=True,
                    log_paths=[path for path in settings.auth_log_paths.split(":") if path],
                ).run(service.process)
            )
        )
    if settings.service_log_collector_enabled:
        tasks.append(
            asyncio.create_task(
                ServiceLogCollector(enabled=True, log_path=settings.service_log_path or None).run(
                    service.process
                )
            )
        )
    if settings.integrity_collector_enabled:
        collector = IntegrityCollector(
            api_url=settings.docker_api_url,
            file_paths=settings.important_file_paths,
            package_report=settings.integrity_package_report,
            interval=max(settings.collector_interval_seconds, 30),
        )
        tasks.append(asyncio.create_task(collector.run(service.process_integrity)))
    yield
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(
    title="OpenClaw Sentinel",
    version="0.5.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(RequestLimits, settings=settings)
app.state.settings = settings
app.state.store = store
app.state.service = service
app.state.tools = tools
app.state.runtime = runtime
app.state.config_manager = ConfigManager(settings)
service.config_manager = app.state.config_manager
app.state.web_sessions = web_sessions
if settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "PUT", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/events")
async def ingest(event: IngestEvent, identity: Annotated[dict, Depends(collector_identity)]):
    return await service.process(validate_event(event, identity))


@app.get("/events", dependencies=[Depends(scoped("incident.read"))])
async def events(ip: str | None = None, limit: int = Query(100, ge=1, le=500)):
    return store.events(ip=ip, limit=limit)


@app.get("/risk/{ip}", dependencies=[Depends(scoped("incident.read"))])
async def risk(ip: str):
    return store.profile(ip) or {"ip": ip, "risk_score": 0, "action": "allow"}


@app.get("/incidents", dependencies=[Depends(scoped("incident.read"))])
async def incidents(limit: int = Query(100, ge=1, le=500)):
    return store.incidents(limit)


@app.post("/actions/unblock/{ip}", dependencies=[Depends(scoped("action.execute"))])
async def unblock(request: Request, ip: str):
    result = await service.lifecycle.unblock(ip)
    audit(request, "action.unblock", after={"ip": ip})
    return result


@app.post("/mcp", dependencies=[Depends(authenticate)])
async def mcp(request: Request, payload: dict):
    return await tools.jsonrpc(payload, request.state.principal)


app.include_router(api_router)
app.include_router(ws_router, prefix="/api/v1")

frontend = Path("/app/frontend")
if frontend.exists():
    app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
