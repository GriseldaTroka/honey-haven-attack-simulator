from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter, sleep
from typing import Any, Dict, List

from ..http_client import AttackHttpClient
from ..logging_utils import AttackLogger
from ..models import ModuleResult, RequestAction
from .base import AttackModule, ModuleContext


@dataclass(slots=True)
class ApiProbeRequest:
    phase: str
    method: str
    path: str
    label: str
    params: Dict[str, Any]
    data: Dict[str, Any]
    headers: Dict[str, str]
    repeat: int = 1


DEFAULT_API_TARGETS: List[Dict[str, Any]] = [
    {"phase": "discovery", "method": "GET", "path": "/api", "label": "api-root"},
    {"phase": "discovery", "method": "GET", "path": "/api/health", "label": "api-health"},
    {"phase": "discovery", "method": "GET", "path": "/api/admin", "label": "api-admin"},
    {"phase": "discovery", "method": "OPTIONS", "path": "/api/admin", "label": "api-admin-options"},
    {"phase": "interaction", "method": "GET", "path": "/api/users", "label": "api-users"},
    {"phase": "interaction", "method": "POST", "path": "/api/admin", "label": "api-admin-post"},
    {"phase": "decoy", "method": "GET", "path": "/api/decoy", "label": "api-decoy"},
]


def _stringify_mapping(value: Any) -> Dict[str, str]:
    return {str(key): str(item) for key, item in dict(value or {}).items()}


class ApiProbeModule(AttackModule):
    name = "api_probe"

    def _build_requests(self, config: Dict[str, Any]) -> List[ApiProbeRequest]:
        global_headers = _stringify_mapping(config.get("headers", {}))
        default_delay_ms = float(config.get("delay_ms", 0.0))
        requests: List[ApiProbeRequest] = []

        if config.get("scenarios"):
            for scenario_index, scenario in enumerate(config.get("scenarios", []), start=1):
                phase = str(scenario.get("phase", scenario.get("type", "discovery")))
                label_prefix = str(scenario.get("label", f"api-scenario-{scenario_index}"))
                method = str(scenario.get("method", "GET"))
                headers = {**global_headers, **_stringify_mapping(scenario.get("headers", {}))}
                repeat = int(scenario.get("repeat", 1))

                if phase == "scan":
                    phase = "discovery"

                if scenario.get("kind") == "endpoint-list" or scenario.get("endpoints"):
                    parameter_name = str(scenario.get("parameter", "id"))
                    for endpoint_index, endpoint in enumerate([str(value) for value in scenario.get("endpoints", [])], start=1):
                        for payload_index, payload in enumerate([str(value) for value in scenario.get("payloads", [parameter_name])], start=1):
                            for iteration in range(1, repeat + 1):
                                requests.append(
                                    ApiProbeRequest(
                                        phase=phase,
                                        method=method,
                                        path=endpoint,
                                        label=f"{label_prefix}-endpoint-{endpoint_index}-{payload_index}-{iteration}",
                                        params={parameter_name: payload},
                                        data={},
                                        headers=headers,
                                        repeat=1,
                                    )
                                )
                    continue

                path = str(scenario.get("path", scenario.get("endpoint", "/api")))
                params = dict(scenario.get("params", {}))
                data = dict(scenario.get("data", {}))
                extra_params = _stringify_mapping(scenario.get("unexpected_params", {}))
                params.update(extra_params)
                for iteration in range(1, repeat + 1):
                    requests.append(
                        ApiProbeRequest(
                            phase=phase,
                            method=method,
                            path=path,
                            label=f"{label_prefix}-{iteration}",
                            params=params,
                            data=data,
                            headers=headers,
                            repeat=1,
                        )
                    )
            return requests

        phases = [str(value) for value in config.get("phases", ["discovery", "interaction", "decoy"])]
        selected_targets = [item for item in DEFAULT_API_TARGETS if item["phase"] in phases]

        if config.get("discovery_targets"):
            selected_targets = []
            for target in config.get("discovery_targets", []):
                selected_targets.append(
                    {
                        "phase": "discovery",
                        "method": str(target.get("method", "GET")),
                        "path": str(target.get("path", "/api")),
                        "label": str(target.get("label", "api-discovery")),
                        "params": dict(target.get("params", {})),
                        "data": dict(target.get("data", {})),
                        "headers": _stringify_mapping(target.get("headers", {})),
                        "repeat": int(target.get("repeat", 1)),
                    }
                )

        for item in selected_targets:
            item_headers = {**global_headers, **_stringify_mapping(item.get("headers", {}))}
            repeat = int(item.get("repeat", config.get("repeat", 1)))
            for iteration in range(1, repeat + 1):
                requests.append(
                    ApiProbeRequest(
                        phase=str(item.get("phase", "discovery")),
                        method=str(item.get("method", "GET")),
                        path=str(item.get("path", "/api")),
                        label=f"{item.get('label', 'api-probe')}-{iteration}" if repeat > 1 else str(item.get("label", "api-probe")),
                        params=dict(item.get("params", {})),
                        data=dict(item.get("data", {})),
                        headers=item_headers,
                        repeat=1,
                    )
                )

        if config.get("return_targets"):
            for return_index, target in enumerate(config.get("return_targets", []), start=1):
                requests.append(
                    ApiProbeRequest(
                        phase="persistent",
                        method=str(target.get("method", "GET")),
                        path=str(target.get("path", "/api")),
                        label=str(target.get("label", f"api-return-{return_index}")),
                        params=dict(target.get("params", {})),
                        data=dict(target.get("data", {})),
                        headers={**global_headers, **_stringify_mapping(target.get("headers", {}))},
                        repeat=1,
                    )
                )

        return requests

    def run(self, client: AttackHttpClient, logger: AttackLogger, context: ModuleContext) -> ModuleResult:
        started = perf_counter()
        records = []
        config = context.module_config
        delay_ms = float(config.get("delay_ms", 0.0))
        requests = self._build_requests(config)

        for index, request_template in enumerate(requests, start=1):
            outcome = client.send(
                RequestAction(
                    method=request_template.method,
                    path=request_template.path,
                    params=request_template.params,
                    data=request_template.data,
                    headers={"X-Attack-Test": "api-probing", **request_template.headers},
                    label=request_template.label,
                ),
                module_name=self.name,
                scenario_name=context.scenario_name,
            )
            outcome.record.execution_status = "success" if outcome.record.status_code is not None else "request_failed"
            outcome.record.tested_parameters = {
                **request_template.params,
                **request_template.data,
                "phase": request_template.phase,
            }
            logger.log_request(outcome.record)
            records.append(outcome.record)

            if delay_ms > 0 and index < len(requests):
                sleep(delay_ms / 1000.0)

        duration_ms = (perf_counter() - started) * 1000.0
        validation_summary = {
            "request_count": len(records),
            "profile": client.profile.name,
            "persistent_session": client.profile.persistent_session,
            "delay_ms": delay_ms,
            "all_logged": len(records) == len(requests),
            "phases_observed": sorted({record.tested_parameters.get("phase", "unknown") for record in records}),
            "endpoint_targets": sorted({record.url for record in records}),
        }
        result = ModuleResult(
            module=self.name,
            success=all(record.execution_status != "request_failed" for record in records),
            request_count=len(records),
            duration_ms=round(duration_ms, 2),
            details=records,
            validation_summary=validation_summary,
            error="" if records else "No API probing requests were generated",
        )
        logger.log_module_result(result)
        return result
