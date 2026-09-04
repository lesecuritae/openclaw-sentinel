from __future__ import annotations

from core.models import RiskFactor


class GeoTimeAnalyzer:
    """Explainable geo_time_mismatch. Missing data = no positive finding."""
    def explain_geo_time_mismatch(
        self, event, baseline_profile: dict | None = None
    ) -> list[RiskFactor]:
        factors = []
        profile = baseline_profile or {}
        if profile.get("positive_event_count", 0) < 3 or profile.get(
            "positive_confidence", 0
        ) < 0.5:
            return factors
        ip_country = getattr(event, "country", None)
        known = profile.get("known_regions", [])
        if ip_country and known and ip_country not in known:
            factors.append(
                RiskFactor(
                    source="geo_time:country_mismatch",
                    score=10,
                    reason=f"country {ip_country} differs from learned regions",
                    kind="geo_time",
                )
            )
        typical_hours = {int(hour) for hour in profile.get("typical_hours", [])}
        if typical_hours and event.timestamp.hour not in typical_hours:
            factors.append(
                RiskFactor(
                    source="geo_time:unusual_hour",
                    score=10,
                    reason=f"UTC hour {event.timestamp.hour} outside learned hours",
                    kind="geo_time",
                )
            )
        timezones = profile.get("timezones", [])
        if event.client_timezone and timezones and event.client_timezone not in timezones:
            factors.append(
                RiskFactor(
                    source="geo_time:timezone_mismatch",
                    score=10,
                    reason="client timezone differs from learned timezones",
                    kind="geo_time",
                )
            )
        return factors
