from __future__ import annotations

from core.models import RiskFactor


class ClientMismatchAnalyzer:
    """Explainable client_mismatch. Never invent fingerprints when features missing."""
    def analyze_client(self, event, profile: dict | None = None) -> list[RiskFactor]:
        factors = []
        metadata = getattr(event, "metadata", {})
        ua = getattr(event, "user_agent", None) or metadata.get("user_agent")
        lang = getattr(event, "accept_language", None) or metadata.get("accept_language")
        tls = getattr(event, "tls_fingerprint", None) or metadata.get("tls_fingerprint")
        if ua is None and lang is None and tls is None:
            return factors
        profile = profile or {}
        expected_ua_sub = profile.get("user_agents", [])
        expected_lang = profile.get("languages", [])
        expected_tls = profile.get("tls_fingerprints", [])
        mismatch_reasons = []
        if ua and expected_ua_sub:
            ua_lower = ua.lower()
            if not any(expected.lower() in ua_lower for expected in expected_ua_sub):
                mismatch_reasons.append("user agent differs from learned clients")
        if lang and expected_lang:
            lang_lower = lang.lower()
            if not any(expected.lower() in lang_lower for expected in expected_lang):
                mismatch_reasons.append("language differs from learned clients")
        if tls and expected_tls and tls not in expected_tls:
            mismatch_reasons.append("TLS fingerprint differs from learned clients")
        if mismatch_reasons:
            factors.append(RiskFactor(
                source="client:mismatch",
                score=min(20, len(mismatch_reasons) * 8),
                reason="; ".join(mismatch_reasons),
                kind="client",
            ))
        return factors
