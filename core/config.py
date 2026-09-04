from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DetectionRule(BaseModel):
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
    rules: dict[str, DetectionRule]


class PolicyConfig(BaseModel):
    allow_below: int = 60
    challenge_below: int = 90
    challenge_enabled: bool = False
    block_enabled: bool = True
    challenge_provider: str = "anubis"
    block_provider: str = "haproxy"


class IntelligenceProviderConfig(BaseModel):
    enabled: bool = False
    weight: int = Field(default=0, ge=0, le=100)
    ttl: str | None = None
    timeout: float = Field(default=5.0, gt=0, le=60)
    endpoint: str | None = None


class IntelligenceConfig(BaseModel):
    providers: dict[str, IntelligenceProviderConfig]
    cache_time: dict[str, str] = Field(default_factory=lambda: {"default": "24h"})
    single_source_ceiling: int = Field(default=89, ge=0, le=99)


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
    sentinel_api_key: str = ""
    llm_provider: str = "disabled"
    openrouter_api_key: str = ""
    model: str = ""
    local_llm_url: str = "http://host.docker.internal:11434"
    anubis_url: str = ""
    abusech_auth_key: str = ""

    def load_rules(self) -> RulesConfig:
        return RulesConfig.model_validate(yaml.safe_load(self.rules_path.read_text()))

    def load_policy(self) -> PolicyConfig:
        return PolicyConfig.model_validate(yaml.safe_load(self.policy_path.read_text()))

    def load_intelligence(self) -> IntelligenceConfig:
        return IntelligenceConfig.model_validate(yaml.safe_load(self.intelligence_path.read_text()))
