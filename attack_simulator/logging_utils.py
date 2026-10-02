from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .models import ModuleResult, RequestRecord


class AttackLogger:
    def __init__(self, scenario_name: str, output_dir: Path) -> None:
        self.scenario_name = scenario_name
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.log_path = self.output_dir / f"{scenario_name}-{timestamp}.jsonl"
        self._file = self.log_path.open("a", encoding="utf-8")
        self.console = logging.getLogger(f"attack-simulator.{scenario_name}")

    def close(self) -> None:
        self._file.close()

    def _write(self, payload: Dict[str, Any]) -> None:
        self._file.write(json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n")
        self._file.flush()

    def log_event(self, event_type: str, **fields: Any) -> None:
        payload = {
            "event_type": event_type,
            "scenario": self.scenario_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **fields,
        }
        self._write(payload)

    def log_request(self, record: RequestRecord) -> None:
        self._write({"event_type": "request", **asdict(record)})

    def log_module_result(self, result: ModuleResult) -> None:
        payload = asdict(result)
        payload["event_type"] = "module_result"
        payload["scenario"] = self.scenario_name
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._write(payload)

    def log_campaign_start(self, campaign_name: str, profile_name: str, base_url: str, **fields: Any) -> None:
        self.log_event("campaign_start", campaign_name=campaign_name, profile=profile_name, base_url=base_url, **fields)

    def log_campaign_end(self, campaign_name: str, success: bool, duration_ms: float, **fields: Any) -> None:
        self.log_event("campaign_end", campaign_name=campaign_name, success=success, duration_ms=duration_ms, **fields)
