from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter, sleep
from typing import Any, Dict, List

from ..http_client import AttackHttpClient
from ..logging_utils import AttackLogger
from ..models import ModuleResult, RequestAction
from .base import AttackModule, ModuleContext


@dataclass(slots=True)
class ReconRequestTemplate:
    method: str
    path: str
    label: str
    category: str
    params: Dict[str, Any]
    headers: Dict[str, str]


DEFAULT_RECON_TEMPLATES: List[ReconRequestTemplate] = [
    ReconRequestTemplate("GET", "/", "homepage", "browsing", {} , {}),
    ReconRequestTemplate("GET", "/products", "product-listing", "browsing", {}, {}),
    ReconRequestTemplate("GET", "/product/1", "product-detail-1", "browsing", {}, {}),
    ReconRequestTemplate("GET", "/blog", "blog-index", "browsing", {}, {}),
    ReconRequestTemplate("GET", "/blog/1", "blog-post-1", "browsing", {}, {}),
    ReconRequestTemplate("GET", "/login", "login-page", "browsing", {}, {}),
    ReconRequestTemplate("GET", "/register", "registration-page", "browsing", {}, {}),
    ReconRequestTemplate("GET", "/about", "about-page", "browsing", {}, {}),
    ReconRequestTemplate("GET", "/contact", "contact-page", "browsing", {}, {}),
    ReconRequestTemplate("GET", "/admin", "admin-page", "discovery", {}, {}),
    ReconRequestTemplate("GET", "/admin/login", "admin-login", "discovery", {}, {}),
    ReconRequestTemplate("GET", "/api", "api-root", "discovery", {}, {}),
    ReconRequestTemplate("GET", "/api/v1", "api-v1-root", "discovery", {}, {}),
    ReconRequestTemplate("GET", "/robots.txt", "robots", "discovery", {}, {}),
    ReconRequestTemplate("GET", "/sitemap.xml", "sitemap", "discovery", {}, {}),
    ReconRequestTemplate("OPTIONS", "/api", "api-options", "discovery", {}, {}),
    ReconRequestTemplate("HEAD", "/", "head-root", "discovery", {}, {}),
]


def _template_to_dict(template: ReconRequestTemplate) -> Dict[str, Any]:
    return {
        "method": template.method,
        "path": template.path,
        "label": template.label,
        "category": template.category,
        "params": dict(template.params),
        "headers": dict(template.headers),
    }


class ReconnaissanceModule(AttackModule):
    name = "reconnaissance"

    def _load_templates(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "targets" in config:
            return [
                {
                    "method": str(item.get("method", "GET")),
                    "path": str(item.get("path", "/")),
                    "label": str(item.get("label", "recon")),
                    "category": str(item.get("category", "custom")),
                    "params": dict(item.get("params", {})),
                    "headers": dict(item.get("headers", {})),
                }
                for item in config.get("targets", [])
            ]

        templates = [_template_to_dict(template) for template in DEFAULT_RECON_TEMPLATES]
        categories = [str(value) for value in config.get("categories", ["browsing", "discovery"])]
        selected = [item for item in templates if item["category"] in categories]

        extra_paths = [str(value) for value in config.get("extra_paths", [])]
        for index, path in enumerate(extra_paths, start=1):
            selected.append(
                {
                    "method": "GET",
                    "path": path,
                    "label": f"extra-path-{index}",
                    "category": "custom",
                    "params": {},
                    "headers": {},
                }
            )

        return selected

    def run(self, client: AttackHttpClient, logger: AttackLogger, context: ModuleContext) -> ModuleResult:
        started = perf_counter()
        records = []
        config = context.module_config
        request_order = [str(value) for value in config.get("request_order", ["browsing", "discovery"])]
        delay_ms = float(config.get("delay_ms", 0.0))
        max_requests = int(config.get("max_requests", 0))
        templates = self._load_templates(config)

        ordered_targets: List[Dict[str, Any]] = []
        for category in request_order:
            ordered_targets.extend([item for item in templates if item["category"] == category])
        ordered_targets.extend([item for item in templates if item["category"] not in request_order])

        if max_requests > 0:
            ordered_targets = ordered_targets[:max_requests]

        for index, item in enumerate(ordered_targets, start=1):
            outcome = client.send(
                RequestAction(
                    method=str(item.get("method", "GET")),
                    path=str(item.get("path", "/")),
                    params=dict(item.get("params", {})),
                    headers={**dict(config.get("headers", {})), **dict(item.get("headers", {}))},
                    label=str(item.get("label", f"recon-{index}")),
                ),
                module_name=self.name,
                scenario_name=context.scenario_name,
            )
            logger.log_request(outcome.record)
            records.append(outcome.record)
            if delay_ms > 0 and index < len(ordered_targets):
                sleep(delay_ms / 1000.0)

        duration_ms = (perf_counter() - started) * 1000.0
        success = all(record.execution_status != "request_failed" for record in records)
        validation_summary = {
            "request_count": len(records),
            "ordered_by_timestamp": all(
                earlier.timestamp <= later.timestamp for earlier, later in zip(records, records[1:])
            ),
            "persistent_session": client.profile.persistent_session,
            "profile": client.profile.name,
            "configured_request_order": request_order,
            "logging_complete": len(records) == len(ordered_targets),
        }
        result = ModuleResult(
            module=self.name,
            success=success,
            request_count=len(records),
            duration_ms=round(duration_ms, 2),
            details=records,
            validation_summary=validation_summary,
            error="" if success else "One or more reconnaissance requests failed to send",
        )
        logger.log_module_result(result)
        return result
