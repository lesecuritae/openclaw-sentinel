from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    event_types: list[str] = Field(default_factory=list)
    statuses: list[int] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    distinct_by: str | None = None
    threshold: int = 1
    window: int = 60
    score: int


class RulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: dict[str, DetectionRule]


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allow_below: int = Field(default=60, ge=0, le=99)
    challenge_below: int = Field(default=90, ge=1, le=100)
    challenge_enabled: bool = False
    block_enabled: bool = True
    challenge_provider: str = "anubis"
    block_provider: str = "haproxy"
    rules: list[dict[str, object]] = Field(default_factory=list)
    require_explicit_block_rule: bool = False

    @model_validator(mode="after")
    def ordered_thresholds(self):
        if self.allow_below >= self.challenge_below:
            raise ValueError("allow_below must be less than challenge_below")
        return self


class IntelligenceProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    weight: int = Field(default=0, ge=0, le=100)
    ttl: str | None = None
    timeout: float = Field(default=5.0, gt=0, le=60)
    endpoint: str | None = None


class IntelligenceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    providers: dict[str, IntelligenceProviderConfig]
    cache_time: dict[str, str] = Field(default_factory=lambda: {"default": "24h"})
    single_source_ceiling: int = Field(default=89, ge=0, le=99)


class CollectorCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=32, max_length=4096)
    source: str = Field(min_length=1, max_length=64)
    event_types: list[str] = Field(min_length=1, max_length=64)
    services: list[str] = Field(min_length=1, max_length=64)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_path: Path = Path("/data/sentinel.db")
    rules_path: Path = Path("/app/config/rules.yaml")
    policy_path: Path = Path("/app/config/policy.yaml")
    intelligence_path: Path = Path("/app/config/intelligence.yaml")
    haproxy_socket: Path = Path("/run/haproxy/admin.sock")
    haproxy_blocklist_path: str = "/etc/haproxy/sentinel-blocklist.lst"
    collector_interval_seconds: float = 5.0
    haproxy_collector_enabled: bool = True
    haproxy_request_collector_enabled: bool = False
    haproxy_request_host: str = "0.0.0.0"
    haproxy_request_port: int = 1514
    actions_enabled: bool = False
    response_dry_run: bool = True
    docker_collector_enabled: bool = False
    docker_api_url: str = ""
    auth_collector_enabled: bool = False
    service_log_collector_enabled: bool = False
    auth_log_paths: str = "/var/log/auth.log"
    service_log_path: str = ""
    integrity_collector_enabled: bool = False
    integrity_file_paths: str = ""
    integrity_package_report: str = ""
    sentinel_api_key: str = ""
    sentinel_admin_key: str = ""
    sentinel_analyst_key: str = ""
    sentinel_viewer_key: str = ""
    require_authentication: bool = True
    setup_bootstrap_token: str = ""
    collector_credentials: dict[str, CollectorCredential] = Field(default_factory=dict)
    api_rate_limit: int = Field(default=600, ge=1, le=10000)
    event_rate_limit: int = Field(default=300, ge=1, le=10000)
    mcp_rate_limit: int = Field(default=60, ge=1, le=1000)
    report_rate_limit: int = Field(default=10, ge=1, le=100)
    llm_rate_limit: int = Field(default=10, ge=1, le=100)
    max_event_bytes: int = Field(default=32768, ge=1024, le=65536)
    max_request_bytes: int = Field(default=262144, ge=1024, le=1048576)
    action_expiry_interval_seconds: float = Field(default=5, ge=0.1, le=60)
    llm_allowed_providers: list[str] = Field(default_factory=lambda: ["disabled", "local"])
    llm_data_classification: str = "internal"
    llm_max_analysis_bytes: int = Field(default=16384, ge=1024, le=65536)
    llm_provider: str = "disabled"
    openrouter_api_key: str = ""
    model: str = ""
    llm_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    local_llm_url: str = "http://host.docker.internal:11434"
    anubis_url: str = ""
    abusech_auth_key: str = ""
    cors_origin_allowlist: str = ""
    web_2fa_enabled: bool = False
    web_2fa_secret: str = ""
    web_2fa_secret_file: str = ""
    web_session_ttl_seconds: int = Field(default=900, ge=60, le=86400)

    # Docker allowlists passed from app / settings for collector use
    container_patterns: str = ""
    image_patterns: str = ""

    @model_validator(mode="after")
    def security_configuration(self):
        keys = [key for key in self.role_credentials.values() if key]
        keys += [config.token for config in self.collector_credentials.values()]
        if self.setup_bootstrap_token:
            keys.append(self.setup_bootstrap_token)
        if len(keys) != len(set(keys)):
            raise ValueError("Credentials must be unique across roles, collectors and bootstrap")
        if any(len(key) < 32 for key in keys):
            raise ValueError("Credentials must contain at least 32 characters")
        if not self.require_authentication:
            raise ValueError("Authentication cannot be disabled")
        if self.haproxy_request_collector_enabled:
            raise ValueError("Unauthenticated UDP ingest is disabled; use authenticated /events")
        return self

    def load_rules(self) -> RulesConfig:
        return RulesConfig.model_validate(yaml.safe_load(self.rules_path.read_text()))

    def load_policy(self) -> PolicyConfig:
        return PolicyConfig.model_validate(yaml.safe_load(self.policy_path.read_text()))

    def load_intelligence(self) -> IntelligenceConfig:
        return IntelligenceConfig.model_validate(yaml.safe_load(self.intelligence_path.read_text()))

    @property
    def allowed_origins(self) -> list[str]:
        return [
            origin.strip().rstrip("/")
            for origin in self.cors_origin_allowlist.split(",")
            if origin.strip()
        ]

    @property
    def allowed_containers(self) -> list[str]:
        return [p.strip() for p in self.container_patterns.split(",") if p.strip()]

    @property
    def allowed_images(self) -> list[str]:
        return [p.strip() for p in self.image_patterns.split(",") if p.strip()]

    @property
    def important_file_paths(self) -> list[str]:
        return [p.strip() for p in self.integrity_file_paths.split(",") if p.strip()]

    @property
    def role_credentials(self) -> dict[str, str]:
        """Credentials are mapped to roles server-side; roles never come from requests."""
        return {
            "administrator": self.sentinel_admin_key or self.sentinel_api_key,
            "analyst": self.sentinel_analyst_key,
            "viewer": self.sentinel_viewer_key,
        }
