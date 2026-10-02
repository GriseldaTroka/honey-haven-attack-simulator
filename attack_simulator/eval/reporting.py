from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


def _safe_name(s: str) -> str:
    return s.replace(" ", "_").replace("/", "_")


def generate_report(metrics: Any, output_dir: Path, label: str = "evaluation") -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    base = output_dir / f"{_safe_name(label)}_{ts}"
    json_path = base.with_suffix(".json")
    html_path = base.with_suffix(".html")

    # dump JSON
    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(_metrics_to_dict(metrics), fh, indent=2)

    # simple HTML summary
    with html_path.open("w", encoding="utf-8") as fh:
        fh.write("<html><head><meta charset=\"utf-8\"><title>Evaluation Report</title></head><body>")
        fh.write(f"<h1>Evaluation Report: {label}</h1>")
        fh.write(f"<p>Generated: {ts} UTC</p>")
        fh.write("<h2>Detection</h2>")
        fh.write("<ul>")
        fh.write(f"<li>Executed attacks: {metrics.detection.executed_attacks}</li>")
        fh.write(f"<li>Detected attacks: {metrics.detection.detected_attacks}</li>")
        fh.write(f"<li>Detection rate: {metrics.detection.detection_rate:.2f}%</li>")
        fh.write(f"<li>Generated alerts: {metrics.detection.generated_alerts}</li>")
        fh.write("</ul>")
        fh.write("<h2>Logging</h2>")
        fh.write("<ul>")
        fh.write(f"<li>Requests generated: {metrics.logging.total_requests_generated}</li>")
        fh.write(f"<li>Events stored: {metrics.logging.total_events_stored}</li>")
        fh.write(f"<li>Missing events: {metrics.logging.missing_events}</li>")
        fh.write("</ul>")
        fh.write("<h2>Journey</h2>")
        fh.write("<ul>")
        fh.write(f"<li>Expected sessions: {metrics.journey.attacker_sessions_expected}</li>")
        fh.write(f"<li>Reconstructed sessions: {metrics.journey.attacker_sessions_reconstructed}</li>")
        fh.write(f"<li>Correctly grouped events: {metrics.journey.correctly_grouped_events}</li>")
        fh.write(f"<li>Incorrectly grouped events: {metrics.journey.incorrectly_grouped_events}</li>")
        fh.write("</ul>")
        fh.write("<h2>Performance</h2>")
        fh.write("<ul>")
        fh.write(f"<li>Average response (sim): {metrics.performance.average_response_ms:.1f} ms</li>")
        fh.write(f"<li>Average logging processing (hp): {metrics.performance.average_logging_processing_ms:.1f} ms</li>")
        fh.write("</ul>")
        fh.write("</body></html>")

    return base


def _metrics_to_dict(m: Any) -> Dict[str, Any]:
    return {
        "detection": {
            "executed_attacks": m.detection.executed_attacks,
            "detected_attacks": m.detection.detected_attacks,
            "detection_rate": m.detection.detection_rate,
            "generated_alerts": m.detection.generated_alerts,
            "detection_latency_ms_avg": m.detection.detection_latency_ms_avg,
        },
        "logging": {
            "total_requests_generated": m.logging.total_requests_generated,
            "total_events_stored": m.logging.total_events_stored,
            "missing_events": m.logging.missing_events,
        },
        "journey": {
            "attacker_sessions_expected": m.journey.attacker_sessions_expected,
            "attacker_sessions_reconstructed": m.journey.attacker_sessions_reconstructed,
            "correctly_grouped_events": m.journey.correctly_grouped_events,
            "incorrectly_grouped_events": m.journey.incorrectly_grouped_events,
        },
        "performance": {
            "average_response_ms": m.performance.average_response_ms,
            "average_logging_processing_ms": m.performance.average_logging_processing_ms,
        },
        "details": getattr(m, "details", {}),
    }
