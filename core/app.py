import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException

from actions.anubis import AnubisChallengeAdapter
from actions.haproxy import HAProxyActionAdapter
from collectors.haproxy import HAProxyCollector, HAProxyRequestCollector, HAProxyRuntimeClient
from core.config import Settings
from core.models import SecurityEvent
from core.service import SentinelService
from database.store import SecurityStore
from engine.detection import DetectionEngine
from engine.policy import PolicyEngine
from engine.risk import RiskEngine
from llm.gateway import LLMGateway
from mcp.server import SecurityTools

logging.basicConfig(level=logging.INFO)
settings = Settings()
store = SecurityStore(settings.database_path)
runtime = HAProxyRuntimeClient(settings.haproxy_socket)
service = SentinelService(
    store,
    DetectionEngine(settings.load_rules()),
    RiskEngine(),
    PolicyEngine(settings.load_policy()),
    HAProxyActionAdapter(runtime, settings.haproxy_blocklist_path, settings.actions_enabled),
    AnubisChallengeAdapter(settings.anubis_url),
)
llm = LLMGateway.from_settings(settings)
tools = SecurityTools(service, store, llm)


def authenticate(authorization: str | None = Header(default=None)) -> None:
    if settings.sentinel_api_key and authorization != f"Bearer {settings.sentinel_api_key}":
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
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="OpenClaw Sentinel", version="0.1.5", lifespan=lifespan)


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
