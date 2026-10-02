from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class AttackerProfile:
    name: str
    persistent_session: bool
    user_agent: str
    headers: Dict[str, str] = field(default_factory=dict)
    source_ip: str = ""
    fingerprint_headers: Dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class RequestAction:
    method: str
    path: str
    params: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    json_body: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    label: str = ""


@dataclass(slots=True)
class ResponseRecord:
    status_code: Optional[int]
    elapsed_ms: Optional[float]
    body_preview: str = ""
    error: str = ""


@dataclass(slots=True)
class RequestRecord:
    timestamp: str
    module: str
    scenario: str
    profile: str
    method: str
    url: str
    status_code: Optional[int]
    elapsed_ms: Optional[float]
    response_preview: str = ""
    execution_status: str = "unknown"
    attempt_number: Optional[int] = None
    attempted_username: str = ""
    tested_parameters: Dict[str, Any] = field(default_factory=dict)
    label: str = ""
    error: str = ""


@dataclass(slots=True)
class ModuleResult:
    module: str
    success: bool
    request_count: int
    duration_ms: float
    details: List[RequestRecord] = field(default_factory=list)
    validation_summary: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
