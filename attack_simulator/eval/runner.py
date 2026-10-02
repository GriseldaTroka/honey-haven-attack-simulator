from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .metrics import compute_metrics, EvalMetrics
from .reporting import generate_report


def run_evaluation(simulator_log: Path, honeypot_log: Path, out_dir: Path, label: Optional[str] = None) -> Path:
    metrics: EvalMetrics = compute_metrics(simulator_log, honeypot_log)
    report_base = generate_report(metrics, out_dir, label or simulator_log.stem)
    return report_base


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run evaluation comparing simulator logs with honeypot telemetry")
    parser.add_argument("--sim-log", required=True, help="Path to simulator JSONL log produced by AttackLogger")
    parser.add_argument("--hp-log", required=True, help="Path to honeypot telemetry JSONL")
    parser.add_argument("--out", default="evaluation_reports", help="Output directory for reports")
    parser.add_argument("--label", default=None, help="Label for this evaluation run")
    args = parser.parse_args(argv)

    sim_log = Path(args.sim_log)
    hp_log = Path(args.hp_log)
    out_dir = Path(args.out)

    if not sim_log.exists():
        print(f"Simulator log not found: {sim_log}")
        return 3
    if not hp_log.exists():
        print(f"Honeypot log not found: {hp_log}")
        return 4

    base = run_evaluation(sim_log, hp_log, out_dir, args.label)
    print(f"Report base generated: {base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
