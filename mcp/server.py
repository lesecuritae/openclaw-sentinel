import json
from typing import Any


class SecurityTools:
    def __init__(self, service, store, llm, intelligence=None):
        self.service, self.store, self.llm, self.intelligence = (service, store, llm, intelligence)

    def definitions(self) -> list[dict[str, Any]]:
        names = {
            "security.check_ip": {"ip": "string"},
            "security.get_events": {"ip": "string"},
            "security.get_incidents": {},
            "security.get_risk_score": {"ip": "string"},
            "security.explain_event": {"event_id": "string"},
            "security.generate_report": {},
            "security.check_ip_reputation": {"ip": "string"},
            "security.get_threat_sources": {},
            "security.get_ip_history": {"ip": "string"},
            "security.explain_risk_score": {"ip": "string"},
        }
        return [
            {
                "name": name,
                "description": name.replace("security.", "").replace("_", " "),
                "inputSchema": {
                    "type": "object",
                    "properties": {key: {"type": kind} for key, kind in fields.items()},
                },
            }
            for name, fields in names.items()
        ]

    async def call(self, name: str, args: dict) -> Any:
        if name in {"security.check_ip", "security.get_risk_score"}:
            return self.store.profile(args["ip"]) or {
                "ip": args["ip"],
                "risk_score": 0,
                "action": "allow",
            }
        if name == "security.get_events":
            return [e.model_dump(mode="json") for e in self.store.events(ip=args.get("ip"))]
        if name == "security.get_incidents":
            return self.store.incidents()
        if name == "security.check_ip_reputation":
            if not self.intelligence:
                return []
            return [
                result.model_dump(mode="json")
                for result in await self.intelligence.check(args["ip"])
            ]
        if name == "security.get_threat_sources":
            configured = self.intelligence.sources() if self.intelligence else []
            return {"configured": configured, "cache": self.store.threat_sources()}
        if name == "security.get_ip_history":
            ip = args["ip"]
            return {
                "profile": self.store.profile(ip),
                "events": [event.model_dump(mode="json") for event in self.store.events(ip=ip)],
                "intelligence": self.store.intelligence_history(ip),
                "actions": self.store.action_history(ip),
            }
        if name == "security.explain_risk_score":
            profile = self.store.profile(args["ip"])
            if not profile:
                return {"ip": args["ip"], "risk_score": 0, "factors": [], "reasons": []}
            return {
                key: profile[key] for key in ("ip", "risk_score", "action", "factors", "reasons")
            }
        if name == "security.explain_event":
            matches = [e for e in self.store.events(limit=1000) if e.event_id == args["event_id"]]
            if not matches:
                raise KeyError("event not found")
            return {"explanation": await self.service.explain_event(matches[0], self.llm)}
        if name == "security.generate_report":
            return {"incidents": self.store.incidents(), "profiles": "available per IP"}
        raise KeyError(f"unknown tool: {name}")

    async def jsonrpc(self, request: dict) -> dict:
        method, request_id = request.get("method"), request.get("id")
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "openclaw-sentinel", "version": "0.2.0"},
                }
            elif method == "tools/list":
                result = {"tools": self.definitions()}
            elif method == "tools/call":
                params = request.get("params", {})
                value = await self.call(params["name"], params.get("arguments", {}))
                result = {"content": [{"type": "text", "text": json.dumps(value, default=str)}]}
            else:
                raise KeyError("method not found")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (KeyError, ValueError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": str(exc)},
            }
