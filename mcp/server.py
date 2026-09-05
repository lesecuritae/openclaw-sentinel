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
            "security.get_services": {},
            "security.get_integrity": {"status": "string", "limit": "integer"},
            "security.get_integrity_summary": {},
            "security.generate_report": {},
            "security.check_ip_reputation": {"ip": "string"},
            "security.get_threat_sources": {},
            "security.get_ip_history": {"ip": "string"},
            "security.get_device_profile": {"device_id": "string"},
            "security.get_behavior_anomalies": {"service": "string", "ip": "string"},
            "security.get_trust_score": {"device_id": "string"},
            "security.explain_anomaly": {"anomaly_id": "integer"},
            "security.explain_risk_score": {"ip": "string"},
        }
        required = {
            "security.check_ip": ["ip"],
            "security.get_risk_score": ["ip"],
            "security.explain_event": ["event_id"],
            "security.check_ip_reputation": ["ip"],
            "security.get_ip_history": ["ip"],
            "security.get_device_profile": ["device_id"],
            "security.get_trust_score": ["device_id"],
            "security.explain_anomaly": ["anomaly_id"],
            "security.explain_risk_score": ["ip"],
        }
        definitions = []
        for name, fields in names.items():
            schema = {
                "type": "object",
                "properties": {key: {"type": kind} for key, kind in fields.items()},
                "additionalProperties": False,
            }
            if name in required:
                schema["required"] = required[name]
            definitions.append(
                {
                    "name": name,
                    "description": name.replace("security.", "").replace("_", " "),
                    "inputSchema": schema,
                }
            )
        return definitions

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
        if name == "security.get_device_profile":
            return self.store.get_device_profile(args["device_id"]) or {
                "device_id": args["device_id"],
                "trust_score": 50,
                "known": False,
            }
        if name == "security.get_behavior_anomalies":
            return self.store.behavior_anomalies(service=args.get("service"), ip=args.get("ip"))
        if name == "security.get_trust_score":
            from engine.trust.engine import TrustEngine

            profile = self.store.get_device_profile(args["device_id"]) or {}
            engine = TrustEngine()
            return {
                "device_id": args["device_id"],
                "trust_score": engine.calculate_trust(profile),
                "explanation": engine.explain_trust(profile),
            }
        if name == "security.explain_anomaly":
            anomaly = self.store.anomaly(args["anomaly_id"])
            if not anomaly:
                raise KeyError("anomaly not found")
            return anomaly
        if name == "security.get_services":
            rolling_window_hours = args.get("rolling_window_hours", 24)
            return {
                "services": self.store.services_dashboard(
                    rolling_window_hours=rolling_window_hours
                ),
                "rolling_window_hours": rolling_window_hours,
            }
        if name == "security.get_integrity":
            return {
                "summary": self.store.integrity_summary(),
                "findings": self.store.integrity_findings(
                    args.get("limit", 100), args.get("status")
                ),
            }
        if name == "security.get_integrity_summary":
            return self.store.integrity_summary()
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
                    "serverInfo": {"name": "openclaw-sentinel", "version": "0.4.5"},
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
