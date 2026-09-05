"""Only normalized, redacted analyst data may cross the provider boundary."""

import json
import re

from pydantic import BaseModel, ConfigDict, Field


class AnalystRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: str | None = Field(default=None, max_length=128)
    event_type: str | None = Field(default=None, max_length=128)
    service: str | None = Field(default=None, max_length=128)
    severity: str | None = Field(default=None, max_length=32)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    score: int | None = Field(default=None, ge=-100, le=100)
    kind: str | None = Field(default=None, max_length=64)
    status: str | None = Field(default=None, max_length=64)
    priority: str | None = Field(default=None, max_length=64)
    action: str | None = Field(default=None, max_length=32)
    reason: str | None = Field(default=None, max_length=256)


SECRET = re.compile(
    r"(?i)(?:bearer\s+\S+|(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)"
    r'\s*[=:]\s*["\']?[^\s,"\'}]+|sk-[a-z0-9_-]+|gh[pousr]_[a-z0-9]+|'
    r"AKIA[A-Z0-9]{16}|eyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+)"
)
INSTRUCTION = re.compile(
    r"(?i)(ignore|instruction|system\s*prompt|execute|curl|sudo|assistant|<\|)"
)


def redact(value: str) -> str:
    if INSTRUCTION.search(value) or "-----BEGIN" in value:
        return "[redacted]"
    value = SECRET.sub("[redacted]", value)
    # URLs, credentials, addresses, high-entropy blobs and free-form log payloads are private.
    value = re.sub(r"https?://\S+|[\w.+-]+@[\w.-]+|\b[A-Za-z0-9_+/=-]{32,}\b", "[redacted]", value)
    return value


def record(data: dict) -> dict:
    selected = {}
    for key in AnalystRecord.model_fields:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            value = redact(value)[: 128 if key not in {"reason"} else 256]
        selected[key] = value
    try:
        return AnalystRecord.model_validate(selected).model_dump(exclude_none=True)
    except ValueError:
        return {}


def payload(records: list[dict], classification: str) -> dict:
    return {"classification": classification, "records": [record(item) for item in records[:50]]}


def encode(data: dict, maximum: int) -> str:
    encoded = json.dumps(data, ensure_ascii=True)
    if len(encoded.encode()) > maximum:
        raise ValueError("analysis exceeds configured size limit")
    return encoded
