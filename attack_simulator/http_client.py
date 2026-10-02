from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from time import perf_counter
from typing import Dict, Optional
from urllib import parse, request
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin

from .models import AttackerProfile, RequestAction, RequestRecord


@dataclass(slots=True)
class SendOutcome:
    record: RequestRecord
    response_text: str = ""


class AttackHttpClient:
    def __init__(self, base_url: str, profile: AttackerProfile, timeout_seconds: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.profile = profile
        self.timeout_seconds = timeout_seconds
        self._cookie_jar = CookieJar() if profile.persistent_session else None

    def close(self) -> None:
        return None

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {"User-Agent": self.profile.user_agent, **self.profile.headers}
        if self.profile.source_ip:
            headers.setdefault("X-Forwarded-For", self.profile.source_ip)
            headers.setdefault("X-Real-IP", self.profile.source_ip)
        if self.profile.fingerprint_headers:
            headers.update(self.profile.fingerprint_headers)
        if extra:
            headers.update(extra)
        return headers

    def _build_body(self, action: RequestAction) -> tuple[Optional[bytes], Optional[str]]:
        if action.json_body is not None:
            return json.dumps(action.json_body).encode("utf-8"), "application/json"
        if action.data:
            encoded = parse.urlencode(action.data, doseq=True).encode("utf-8")
            return encoded, "application/x-www-form-urlencoded"
        return None, None

    def _opener(self) -> request.OpenerDirector:
        handlers = []
        if self._cookie_jar is not None:
            handlers.append(request.HTTPCookieProcessor(self._cookie_jar))
        return request.build_opener(*handlers)

    def send(self, action: RequestAction, module_name: str, scenario_name: str) -> SendOutcome:
        target_url = urljoin(self.base_url, action.path.lstrip("/"))
        request_headers = self._headers(action.headers)
        body, inferred_content_type = self._build_body(action)
        if inferred_content_type and "Content-Type" not in request_headers:
            request_headers["Content-Type"] = inferred_content_type
        start = perf_counter()
        response = None
        request_error = ""

        try:
            final_url = target_url
            if action.params:
                query = parse.urlencode(action.params, doseq=True)
                separator = "&" if parse.urlparse(target_url).query else "?"
                final_url = f"{target_url}{separator}{query}"
            req = request.Request(final_url, data=body, headers=request_headers, method=action.method.upper())
            response = self._opener().open(req, timeout=self.timeout_seconds)
        except HTTPError as exc:
            response = exc
        except (URLError, TimeoutError) as exc:
            request_error = str(exc)

        elapsed_ms = (perf_counter() - start) * 1000.0
        preview = ""
        status_code = None
        if response is not None:
            status_code = getattr(response, "status", None) or response.getcode()
            body_text = response.read(2500).decode("utf-8", errors="replace")
            preview = body_text[:2500].replace("\n", " ").replace("\r", " ")

        record = RequestRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            module=module_name,
            scenario=scenario_name,
            profile=self.profile.name,
            method=action.method.upper(),
            url=target_url,
            status_code=status_code,
            elapsed_ms=round(elapsed_ms, 2),
            response_preview=preview,
            execution_status="success" if status_code is not None else "request_failed",
            label=action.label,
            error=request_error,
        )
        return SendOutcome(record=record, response_text=preview)
