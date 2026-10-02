from __future__ import annotations

import re
from itertools import product
from time import perf_counter, sleep
from typing import Any, Dict, Iterable, List

from ..http_client import AttackHttpClient
from ..logging_utils import AttackLogger
from ..models import ModuleResult, RequestAction
from .base import AttackModule, ModuleContext


class BruteForceModule(AttackModule):
    name = "brute_force"

    def _attempts(self, config: Dict[str, Any]) -> Iterable[Dict[str, str]]:
        usernames = [str(value) for value in config.get("usernames", ["admin", "root", "test", "user"])]
        passwords = [str(value) for value in config.get("passwords", ["admin", "password", "123456", "qwerty"])]
        for username, password in product(usernames, passwords):
            yield {"username": username, "password": password}

    def run(self, client: AttackHttpClient, logger: AttackLogger, context: ModuleContext) -> ModuleResult:
        started = perf_counter()
        records = []
        config = context.module_config
        login_path = str(config.get("login_path", "/login"))
        method = str(config.get("method", "POST"))
        username_field = str(config.get("username_field", "username"))
        password_field = str(config.get("password_field", "password"))
        max_attempts = int(config.get("max_attempts", 6))
        delay_ms = float(config.get("delay_ms", 0.0))
        headers = {str(key): str(value) for key, value in dict(config.get("headers", {})).items()}

        csrf_token = None

        # Bootstrap browser session and obtain CSRF token
        login_page = client.send(
            RequestAction(
                method="GET",
                path=login_path,
                headers=headers,
                label="login-page-csrf-bootstrap",
            ),
            module_name=self.name,
            scenario_name=context.scenario_name,
        )

        logger.log_request(login_page.record)
        records.append(login_page.record)

        if login_page.response_text:
            csrf_match = re.search(
                r'name="csrfmiddlewaretoken" value="([^"]+)"',
                login_page.response_text,
            )

            if csrf_match:
              csrf_token = csrf_match.group(1)
              print("CSRF token obtained")
            else:
              print("CSRF token NOT found")
        attempt_count = 0
        for attempt in self._attempts(config):
            if attempt_count >= max_attempts:
                break
            attempt_count += 1
            outcome = client.send(
                RequestAction(
                    method=method,
                    path=login_path,
                    data={
    username_field: attempt["username"],
    password_field: attempt["password"],
    **({"csrfmiddlewaretoken": csrf_token} if csrf_token else {}),
},
                    headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
                    label=f"login-attempt-{attempt_count}",
                ),
                module_name=self.name,
                scenario_name=context.scenario_name,
            )
            outcome.record.attempt_number = attempt_count
            outcome.record.attempted_username = attempt["username"]
            outcome.record.execution_status = "success" if outcome.record.status_code is not None else "request_failed"
            logger.log_request(outcome.record)
            records.append(outcome.record)
            if delay_ms > 0 and attempt_count < max_attempts:
                sleep(delay_ms / 1000.0)

        duration_ms = (perf_counter() - started) * 1000.0
        validation_summary = {
            "attempt_count": len(records),
            "unique_usernames": sorted({record.attempted_username for record in records if record.attempted_username}),
            "persistent_session": client.profile.persistent_session,
            "profile": client.profile.name,
            "delay_ms": delay_ms,
            "target_login_endpoint": login_path,
            "configured_max_attempts": max_attempts,
            "all_logged": all(record.attempt_number is not None for record in records),
        }
        result = ModuleResult(
            module=self.name,
            success=all(record.execution_status != "request_failed" for record in records),
            request_count=len(records),
            duration_ms=round(duration_ms, 2),
            details=records,
            validation_summary=validation_summary,
            error="" if records else "No brute-force requests were generated",
        )
        logger.log_module_result(result)
        return result
