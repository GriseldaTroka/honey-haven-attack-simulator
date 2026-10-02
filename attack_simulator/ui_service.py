from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from .config import AttackConfiguration, load_configuration
from .controller import CampaignOutcome, MODULE_REGISTRY, ScenarioController
from .eval.runner import run_evaluation
from .profiles import build_profile


MODULE_DESCRIPTIONS = {
    "reconnaissance": "Browse configured paths and discovery endpoints to establish the target surface.",
    "brute_force": "Submit bounded username and password combinations to the configured login endpoint.",
    "sql_injection": "Deliver configured SQL injection payloads through query, form, or endpoint scenarios.",
    "api_probe": "Probe configured API, administrative, decoy, and persistent follow-up endpoints.",
}

PROFILE_DESCRIPTIONS = {
    "browser_like": "Persistent session, browser-style headers, and a Chrome-like user agent.",
    "scanner_like": "Stateless scanner-style requests with a scanner user agent and minimal browser behavior.",
}


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _read_jsonl(path: Path) -> list[Dict[str, Any]]:
    if not path.exists():
        return []
    events: list[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    events.append(value)
    except OSError:
        return events
    return events


@dataclass
class RunState:
    run_id: str
    execution_kind: str
    name: str
    requested_at: str
    status: str = "starting"
    error: str = ""
    log_path: str = ""
    outcome: Optional[CampaignOutcome] = None
    events: list[Dict[str, Any]] = field(default_factory=list)


class RunManager:
    def __init__(self, configuration: AttackConfiguration) -> None:
        self.configuration = configuration
        self.controller = ScenarioController(configuration)
        self._runs: Dict[str, RunState] = {}
        self._lock = threading.Lock()

    def start(self, execution_kind: str, name: str, module_config: Optional[Dict[str, Any]] = None, profile: Optional[str] = None) -> RunState:
        if execution_kind not in {"campaign", "scenario", "module"}:
            raise ValueError("execution_kind must be campaign, scenario, or module")
        if execution_kind == "campaign" and name not in self.configuration.campaigns:
            raise KeyError(f"Unknown campaign: {name}")
        if execution_kind == "scenario" and name not in self.configuration.scenarios:
            raise KeyError(f"Unknown scenario: {name}")
        if execution_kind == "module" and name not in MODULE_REGISTRY:
            raise KeyError(f"Unknown module: {name}")

        state = RunState(
            run_id=uuid.uuid4().hex[:12],
            execution_kind=execution_kind,
            name=name,
            requested_at=datetime.now(timezone.utc).isoformat(),
        )
        with self._lock:
            self._runs[state.run_id] = state
        worker = threading.Thread(
            target=self._execute,
            args=(state, module_config or {}, profile),
            name=f"attack-simulator-{state.run_id}",
            daemon=True,
        )
        worker.start()
        return state

    def _execute(self, state: RunState, module_config: Dict[str, Any], profile: Optional[str]) -> None:
        with self._lock:
            state.status = "running"
        try:
            if state.execution_kind == "campaign":
                outcome = self.controller.run_campaign(state.name)
            elif state.execution_kind == "scenario":
                outcome = self.controller.run_scenario(state.name)
            else:
                outcome = self.controller.run_module(state.name, profile_name=profile, module_config=module_config)
            with self._lock:
                state.outcome = outcome
                state.log_path = outcome.log_path
                state.status = "completed" if outcome.success else "failed"
        except Exception as exc:  # Keep service errors structured and user-readable.
            with self._lock:
                state.status = "failed"
                state.error = str(exc)
        finally:
            self.refresh(state)

    def _find_log(self, state: RunState) -> Optional[Path]:
        if state.log_path:
            return Path(state.log_path)
        candidates = sorted(
            self.configuration.output_dir.glob(f"{state.name}*.jsonl"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        return candidates[0] if candidates else None

    def refresh(self, state: RunState) -> RunState:
        log_path = self._find_log(state)
        if log_path:
            state.log_path = str(log_path)
            state.events = _read_jsonl(log_path)
        return state

    def get(self, run_id: str) -> Optional[RunState]:
        with self._lock:
            state = self._runs.get(run_id)
        return self.refresh(state) if state else None

    def list_runs(self) -> list[RunState]:
        with self._lock:
            active = list(self._runs.values())
        for state in active:
            self.refresh(state)
        return sorted(active, key=lambda item: item.requested_at, reverse=True)


class UiService:
    def __init__(self, config_path: str = "configs/example_campaign.json") -> None:
        self.config_path = config_path
        self.configuration = load_configuration(config_path)
        self.runs = RunManager(self.configuration)

    def bootstrap(self) -> Dict[str, Any]:
        config = self.configuration
        profiles = []
        for name, values in config.profiles.items():
            profile = build_profile(name, values)
            profiles.append(
                {
                    "name": profile.name,
                    "description": PROFILE_DESCRIPTIONS.get(profile.name, "Configured attacker profile."),
                    "persistent_session": profile.persistent_session,
                    "user_agent": profile.user_agent,
                    "source_ip": profile.source_ip,
                }
            )
        return {
            "target": {"base_url": config.base_url, "timeout_seconds": config.default_timeout_seconds},
            "profiles": profiles,
            "modules": [
                {"name": name, "description": MODULE_DESCRIPTIONS.get(name, "Configured attack module."), "defaults": config.module_defaults.get(name, {})}
                for name in MODULE_REGISTRY
            ],
            "scenarios": [_json_value(item) for item in config.scenarios.values()],
            "campaigns": [_json_value(item) for item in config.campaigns.values()],
            "runs": [self.run_payload(run) for run in self.runs.list_runs()[:20]],
        }

    def run_payload(self, state: RunState) -> Dict[str, Any]:
        self.runs.refresh(state)
        payload = {
            "run_id": state.run_id,
            "execution_kind": state.execution_kind,
            "name": state.name,
            "requested_at": state.requested_at,
            "status": state.status,
            "error": state.error,
            "log_path": state.log_path,
            "events": state.events,
        }
        if state.outcome:
            payload["outcome"] = _json_value(state.outcome)
        return payload

    def evaluations(self) -> list[Dict[str, Any]]:
        results: list[Dict[str, Any]] = []
        roots = [Path("evaluation_reports"), Path("experiments_output")]
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*.json"):
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(value, dict) and "detection" in value and "logging" in value:
                    results.append({"path": str(path), "label": path.stem, "report": value})
        return sorted(results, key=lambda item: item["path"], reverse=True)

    def evaluate(self, body: Dict[str, Any]) -> Dict[str, Any]:
        sim_log = Path(str(body.get("sim_log", "")))
        hp_log = Path(str(body.get("hp_log", "")))
        if not sim_log.exists() or not hp_log.exists():
            raise FileNotFoundError("Both simulator and honeypot JSONL log paths must exist")
        out_dir = Path(str(body.get("out", "evaluation_reports")))
        base = run_evaluation(sim_log, hp_log, out_dir, label=body.get("label"))
        json_path = base.with_suffix(".json")
        return {"path": str(json_path), "label": json_path.stem, "report": json.loads(json_path.read_text(encoding="utf-8"))}


class RequestHandler(BaseHTTPRequestHandler):
    service: UiService

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _send(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/health":
                self._send(200, {"status": "ok"})
            elif path == "/api/bootstrap":
                self._send(200, self.service.bootstrap())
            elif path == "/api/runs":
                self._send(200, {"runs": [self.service.run_payload(run) for run in self.service.runs.list_runs()]})
            elif path.startswith("/api/runs/"):
                run = self.service.runs.get(path.rsplit("/", 1)[-1])
                self._send(200, self.service.run_payload(run) if run else {"error": "Run not found"})
                if not run:
                    return
            elif path == "/api/evaluations":
                self._send(200, {"evaluations": self.service.evaluations()})
            else:
                self._send(404, {"error": "Not found"})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == "/api/runs":
                state = self.service.runs.start(
                    str(body.get("execution_kind", "")),
                    str(body.get("name", "")),
                    body.get("module_config") if isinstance(body.get("module_config"), dict) else {},
                    str(body.get("profile")) if body.get("profile") else None,
                )
                self._send(202, self.service.run_payload(state))
            elif path == "/api/evaluations":
                self._send(201, self.service.evaluate(body))
            else:
                self._send(404, {"error": "Not found"})
        except (KeyError, ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})


def serve(config_path: str = "configs/example_campaign.json", host: str = "127.0.0.1", port: int = 8765) -> None:
    service = UiService(config_path)
    handler = type("AttackSimulatorRequestHandler", (RequestHandler,), {"service": service})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Attack Simulator UI service listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    serve()