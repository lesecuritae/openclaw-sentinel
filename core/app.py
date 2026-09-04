import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from actions.anubis import AnubisChallengeAdapter
from actions.haproxy import HAProxyActionAdapter
from collectors.auth import LinuxAuthCollector
from collectors.docker import DockerEventCollector
from collectors.haproxy import HAProxyCollector, HAProxyRequestCollector, HAProxyRuntimeClient
from collectors.service import ServiceLogCollector
from core.api.v1 import api_router, ws_router
from core.api.v1.ws.events import manager as event_manager
from core.config import Settings
from core.config_manager import ConfigManager
from core.models import SecurityEvent
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


def authenticate(authorization: str | None = Header(default=None)) -> None:
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if settings.sentinel_api_key and not secrets.compare_digest(
        supplied, settings.sentinel_api_key
    ):
        raise HTTPException(status_code=401, detail="invalid API key")


@asynccontextmanager
async def lifespan(_: FastAPI):
    tasks = []
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
                    enabled=True, api_url=settings.docker_api_url
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
                ServiceLogCollector(
                    enabled=True, log_path=settings.service_log_path or None
                ).run(service.process)
            )
        )
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="OpenClaw Sentinel", version="0.4.5", lifespan=lifespan)
app.state.settings = settings
app.state.store = store
app.state.service = service
app.state.tools = tools
app.state.runtime = runtime
app.state.config_manager = ConfigManager(settings)
app.state.web_sessions = web_sessions
if settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "PUT", "POST"],
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


@app.post("/events", dependencies=[Depends(authenticate)])
async def ingest(event: SecurityEvent):
    return await service.process(event)


@app.get("/events", dependencies=[Depends(authenticate)])
async def events(ip: str | None = None, limit: int = 100):
    return store.events(ip=ip, limit=limit)


@app.get("/risk/{ip}", dependencies=[Depends(authenticate)])
async def risk(ip: str):
    return store.profile(ip) or {"ip": ip, "risk_score": 0, "action": "allow"}


@app.get("/incidents", dependencies=[Depends(authenticate)])
async def incidents(limit: int = 100):
    return store.incidents(limit)


@app.post("/actions/unblock/{ip}", dependencies=[Depends(authenticate)])
async def unblock(ip: str):
    return await service.haproxy.unblock(ip)


@app.post("/mcp", dependencies=[Depends(authenticate)])
async def mcp(request: dict):
    return await tools.jsonrpc(request)


app.include_router(api_router)
app.include_router(ws_router, prefix="/api/v1")

frontend = Path("/app/frontend")
if frontend.exists():
    app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
