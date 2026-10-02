from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _parse_ts(v: Any) -> datetime:
    if isinstance(v, datetime):
        return v
    try:
        return datetime.fromisoformat(str(v))
    except Exception:
        try:
            return datetime.utcfromtimestamp(float(v))
        except Exception:
            return datetime.utcfromtimestamp(0)


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                # skip malformed lines
                continue


@dataclass
class DetectionMetrics:
    executed_attacks: int = 0
    detected_attacks: int = 0
    detection_rate: float = 0.0
    generated_alerts: int = 0
    detection_latency_ms_avg: float = 0.0


@dataclass
class LoggingMetrics:
    total_requests_generated: int = 0
    total_events_stored: int = 0
    missing_events: int = 0


@dataclass
class JourneyMetrics:
    attacker_sessions_expected: int = 0
    attacker_sessions_reconstructed: int = 0
    correctly_grouped_events: int = 0
    incorrectly_grouped_events: int = 0


@dataclass
class PerformanceMetrics:
    average_response_ms: float = 0.0
    average_logging_processing_ms: float = 0.0


@dataclass
class EvalMetrics:
    detection: DetectionMetrics
    logging: LoggingMetrics
    journey: JourneyMetrics
    performance: PerformanceMetrics
    details: Dict[str, Any]


def compute_metrics(simulator_log: Path, honeypot_log: Path, time_window_seconds: int = 5) -> EvalMetrics:
    """Compute evaluation metrics by comparing simulator JSONL logs with
    honeypot telemetry JSONL.

    Matching heuristic: match simulator request to honeypot event when
    (url, method, source_ip) are equal and timestamps are within the
    `time_window_seconds` window.
    """
    sim_events = list(_iter_jsonl(simulator_log))
    hp_events = list(_iter_jsonl(honeypot_log))

    # Index honeypot events by key -> list of (ts, event)
    hp_index: Dict[Tuple[str, str, str], List[Tuple[datetime, Dict[str, Any]]]] = defaultdict(list)
    for e in hp_events:
        url = e.get("url") or e.get("request_url") or e.get("endpoint")
        method = (e.get("method") or e.get("http_method") or "GET").upper()
        src = e.get("source_ip") or e.get("ip") or e.get("client_ip") or ""
        ts = _parse_ts(e.get("timestamp") or e.get("time") or e.get("ts") or 0)
        if url:
            key = (url, method, src)
            hp_index[key].append((ts, e))

    # Prepare stats
    executed_attacks = 0
    detected_attacks = 0
    latencies: List[float] = []
    total_requests_generated = 0

    # For journey reconstruction: group by source_ip/user_agent
    sim_sessions = defaultdict(list)
    hp_sessions = defaultdict(list)

    for e in sim_events:
        if e.get("event_type") == "request" or e.get("type") == "request":
            executed_attacks += 1
            total_requests_generated += 1
            url = e.get("url")
            method = (e.get("method") or "GET").upper()
            profile_obj = e.get("profile")
            if isinstance(profile_obj, dict):
                profile_src = profile_obj.get("source_ip")
            else:
                profile_src = None
            src = profile_src or e.get("source_ip") or e.get("ip") or ""
            ts = _parse_ts(e.get("timestamp") or e.get("time") or 0)
            key = (url, method, src)
            # try to find matching hp event
            found = False
            if key in hp_index:
                for hts, hev in hp_index[key]:
                    delta = abs((hts - ts).total_seconds())
                    if delta <= time_window_seconds:
                        detected_attacks += 1
                        latencies.append(delta * 1000.0)
                        found = True
                        break
            # session grouping
            sess_key = f"{src}|{e.get('user_agent') or e.get('ua') or ''}"
            sim_sessions[sess_key].append(e)

    # Build hp_sessions grouping by source_ip/user_agent
    for e in hp_events:
        src = e.get("source_ip") or e.get("ip") or e.get("client_ip") or ""
        ua = e.get("user_agent") or e.get("ua") or e.get("headers", {}).get("User-Agent") or ""
        sess_key = f"{src}|{ua}"
        hp_sessions[sess_key].append(e)

    # Journey reconstruction metrics (simple heuristics)
    attacker_sessions_expected = len([k for k in sim_sessions.keys() if k and not k.startswith("|")])
    attacker_sessions_reconstructed = sum(1 for k in hp_sessions.keys() if k in sim_sessions)

    # correctness of grouping: count events that share session keys
    correctly = 0
    incorrectly = 0
    for k, evs in sim_sessions.items():
        if k in hp_sessions:
            # count min matched events as correctly grouped
            correctly += min(len(evs), len(hp_sessions[k]))
            incorrectly += abs(len(evs) - len(hp_sessions[k]))
        else:
            incorrectly += len(evs)

    detection_rate = (detected_attacks / executed_attacks * 100.0) if executed_attacks else 0.0
    detection_latency_ms_avg = (sum(latencies) / len(latencies)) if latencies else 0.0

    detection = DetectionMetrics(
        executed_attacks=executed_attacks,
        detected_attacks=detected_attacks,
        detection_rate=detection_rate,
        generated_alerts=len(hp_events),
        detection_latency_ms_avg=detection_latency_ms_avg,
    )

    logging = LoggingMetrics(
        total_requests_generated=total_requests_generated,
        total_events_stored=len(hp_events),
        missing_events=max(0, executed_attacks - detected_attacks),
    )

    journey = JourneyMetrics(
        attacker_sessions_expected=attacker_sessions_expected,
        attacker_sessions_reconstructed=attacker_sessions_reconstructed,
        correctly_grouped_events=correctly,
        incorrectly_grouped_events=incorrectly,
    )

    # performance: average simulator response time if available
    sim_elapsed = [float(e.get("elapsed_ms")) for e in sim_events if e.get("elapsed_ms")]
    hp_elapsed = [float(e.get("processing_ms")) for e in hp_events if e.get("processing_ms")]
    performance = PerformanceMetrics(
        average_response_ms=(sum(sim_elapsed) / len(sim_elapsed)) if sim_elapsed else 0.0,
        average_logging_processing_ms=(sum(hp_elapsed) / len(hp_elapsed)) if hp_elapsed else 0.0,
    )

    details = {
        "simulator_events": len(sim_events),
        "honeypot_events": len(hp_events),
    }

    return EvalMetrics(detection=detection, logging=logging, journey=journey, performance=performance, details=details)
