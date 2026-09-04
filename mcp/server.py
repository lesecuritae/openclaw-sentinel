import json
from typing import Any


class SecurityTools:
    def __init__(self, service, store, llm):
        self.service, self.store, self.llm = service, store, llm

    def definitions(self) -> list[dict[str, Any]]:
        names = {
            "security.check_ip": {"ip": "string"},
            "security.get_events": {"ip": "string"},
            "security.get_incidents": {},
            "security.get_risk_score": {"ip": "string"},
            "security.explain_event": {"event_id": "string"},
            "security.generate_report": {},
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
                    "serverInfo": {"name": "openclaw-sentinel", "version": "0.1.0"},
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
