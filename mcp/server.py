import json
from typing import Any

from fastapi import HTTPException

from core.auth import Principal
from core.limits import RateBudget


class SecurityTools:
    def __init__(self, service, store, llm, intelligence=None):
        self.budget = RateBudget()
        self.service, self.store, self.llm, self.intelligence = (service, store, llm, intelligence)

    def definitions(self) -> list[dict[str, Any]]:
        names = {
            "security.check_ip": {"ip": "string"},
            "security.get_events": {"ip": "string"},
            "security.get_incidents": {},
            "security.explain_incident": {"incident_id": "string"},
            "security.get_incident_history": {"incident_id": "string"},
            "security.get_risk_score": {"ip": "string"},
            "security.explain_event": {"event_id": "string"},
            "security.get_services": {},
            "security.get_integrity": {"status": "string", "limit": "integer"},
            "security.get_integrity_summary": {},
            "security.get_policies": {},
            "security.explain_action": {
                "risk_score": "integer",
                "event_type": "string",
                "source": "string",
            },
            "security.test_policy": {
                "risk_score": "integer",
                "event_type": "string",
                "source": "string",
            },
            "security.get_trusted_entities": {},
            "security.add_trusted_entity": {
                "entity_type": "string",
                "value": "string",
                "reason": "string",
            },
            "security.preview_action": {
                "risk_score": "integer",
                "event_type": "string",
                "source": "string",
            },
            "security.get_actions": {"limit": "integer"},
            "security.revoke_action": {"action_id": "integer"},
            "security.analyze_ip": {"ip": "string"},
            "security.summarize_events": {"ip": "string"},
            "security.get_audit_log": {"limit": "integer"},
            "security.export_config": {},
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
            "security.explain_incident": ["incident_id"],
            "security.get_incident_history": ["incident_id"],
            "security.explain_action": ["risk_score"],
            "security.test_policy": ["risk_score"],
            "security.add_trusted_entity": ["entity_type", "value", "reason"],
            "security.revoke_action": ["action_id"],
            "security.analyze_ip": ["ip"],
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

    @staticmethod
    def scope_for(name: str) -> str:
        return {
            "security.add_trusted_entity": "policy.write",
            "security.revoke_action": "action.execute",
            "security.export_config": "config.export",
            "security.get_audit_log": "audit.read",
            "security.generate_report": "report.create",
            "security.explain_incident": "llm.analyze",
            "security.explain_event": "llm.analyze",
            "security.analyze_ip": "llm.analyze",
            "security.summarize_events": "llm.analyze",
            "security.get_policies": "policy.read",
            "security.test_policy": "policy.read",
            "security.preview_action": "policy.read",
            "security.get_actions": "action.read",
            **dict.fromkeys(
                {
                    "security.check_ip",
                    "security.get_events",
                    "security.get_incidents",
                    "security.get_incident_history",
                    "security.get_risk_score",
                    "security.get_services",
                    "security.get_integrity",
                    "security.get_integrity_summary",
                    "security.check_ip_reputation",
                    "security.get_threat_sources",
                    "security.get_ip_history",
                    "security.get_device_profile",
                    "security.get_behavior_anomalies",
                    "security.get_trust_score",
                    "security.explain_anomaly",
                    "security.explain_risk_score",
                },
                "incident.read",
            ),
            "security.get_trusted_entities": "policy.read",
            "security.explain_action": "policy.read",
        }[name]

    async def call(self, name: str, args: dict, principal: Principal | None = None) -> Any:
        if principal is None:
            raise HTTPException(401, "authenticated user required")
        principal.require(self.scope_for(name))
        definitions = {item["name"]: item for item in self.definitions()}
        if name not in definitions:
            raise KeyError("unknown tool")
        schema = definitions[name]["inputSchema"]
        if not isinstance(args, dict) or set(args) - set(schema["properties"]):
            raise ValueError("invalid arguments")
        if set(schema.get("required", [])) - set(args):
            raise ValueError("missing arguments")
        for key, value in args.items():
            kind = schema["properties"][key]["type"]
            if (kind == "string" and (not isinstance(value, str) or len(value) > 2048)) or (
                kind == "integer" and (type(value) is not int or not 0 <= value <= 1000)
            ):
                raise ValueError("invalid argument type or size")
        if self.scope_for(name) == "report.create" and not self.budget.allow("reports", 10):
            raise HTTPException(429, "report rate limit exceeded")
        if self.scope_for(name) in {"action.execute", "policy.write", "config.export"}:
            self.store.add_audit(
                principal.user_id, name, after=args, session_id=principal.session_id
            )
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
        if name == "security.explain_incident":
            incident = self.store.incident(args["incident_id"])
            if not incident:
                raise KeyError("incident not found")
            return {"incident": incident, "analysis": await self._analyze_incident(incident)}
        if name == "security.get_incident_history":
            return {
                "incident_id": args["incident_id"],
                "timeline": self.store.incident_history(args["incident_id"]),
            }
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
        if name in {"security.explain_action", "security.test_policy"}:
            context = {key: args[key] for key in ("event_type", "source") if key in args}
            result = self.service.policy.test(int(args["risk_score"]), context)
            result.update(
                {
                    "dry_run": True,
                    "preview": f"{result['action']} would be prepared; no action executed",
                }
            )
            return result
        if name == "security.get_policies":
            config = self.service.policy.config
            return {
                "rules": config.rules,
                "allow_below": config.allow_below,
                "challenge_below": config.challenge_below,
                "require_explicit_block_rule": config.require_explicit_block_rule,
            }
        if name == "security.get_trusted_entities":
            return self.store.trusted_entities()
        if name == "security.add_trusted_entity":
            return self.store.add_trusted_entity(
                args["entity_type"], args["value"], args["reason"], args.get("expires_at")
            )
        if name == "security.preview_action":
            context = {key: args[key] for key in ("event_type", "source") if key in args}
            result = self.service.policy.test(int(args["risk_score"]), context)
            result.update(
                {
                    "dry_run": True,
                    "preview": f"{result['action']} would be prepared; no action executed",
                }
            )
            return result
        if name == "security.get_actions":
            return self.store.actions(args.get("limit", 100))
        if name == "security.revoke_action":
            return await self.service.lifecycle.revoke(args["action_id"])
        if name == "security.analyze_ip":
            ip = args["ip"]
            return {
                "ip": ip,
                "analysis": await self._safe_llm(
                    self.llm.analyze_ip(
                        ip,
                        self.store.profile(ip),
                        [e.model_dump(mode="json") for e in self.store.events(ip=ip)],
                        self.store.intelligence_history(ip),
                    )
                ),
            }
        if name == "security.summarize_events":
            events = [
                e.model_dump(mode="json") for e in self.store.events(ip=args.get("ip"), limit=100)
            ]
            return {
                "analysis": await self._safe_llm(self.llm.summarize_events(events)),
                "event_count": len(events),
            }
        if name == "security.generate_report":
            incidents = self.store.incidents()
            return {
                "incidents": incidents,
                "report": self.store.daily_report(),
                "analysis": await self._safe_llm(self.llm.summarize_events(incidents)),
                "profiles": "available per IP",
            }
        if name == "security.get_audit_log":
            return self.store.audit_log(args.get("limit", 100))
        if name == "security.export_config":
            return (
                self.service.config_manager.export()
                if hasattr(self.service, "config_manager")
                else {"status": "available via API"}
            )
        raise KeyError(f"unknown tool: {name}")

    async def _safe_llm(self, awaitable):
        try:
            return await awaitable
        except Exception as exc:
            return {"status": "unavailable", "reason": type(exc).__name__}

    async def _analyze_incident(self, incident: dict):
        actions = [
            item for item in self.store.actions(1000) if item.get("ip") == incident.get("component")
        ]
        return await self._safe_llm(self.llm.analyze_incident(incident, actions))

    async def jsonrpc(self, request: dict, principal: Principal | None = None) -> dict:
        if principal is None:
            raise HTTPException(401, "authenticated user required")
        method, request_id = request.get("method"), request.get("id")
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "openclaw-sentinel", "version": "0.5.0"},
                }
            elif method == "tools/list":
                result = {"tools": self.definitions()}
            elif method == "tools/call":
                params = request.get("params", {})
                value = await self.call(params["name"], params.get("arguments", {}), principal)
                result = {"content": [{"type": "text", "text": json.dumps(value, default=str)}]}
            else:
                raise KeyError("method not found")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (KeyError, ValueError, TypeError, OSError, RuntimeError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": str(exc)},
            }
