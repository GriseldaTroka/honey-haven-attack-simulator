"""Simple experiment runner to automate simulator -> collect -> evaluate flows.

Usage examples:
  python tools/experiment_runner.py --experiment reconnaissance

This script expects `configs/experiments.json` to define experiments and the
honeypot log paths. It will run the configured scenario (or campaign) using the
simulator CLI, wait, copy the honeypot log into the run directory, and invoke
the evaluation runner to produce a report.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, Any


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS_CFG = ROOT / "configs" / "experiments.json"


def _run_cmd(cmd, capture=False):
    print("+ ", " ".join(cmd))
    if capture:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return p.returncode, p.stdout
    else:
        p = subprocess.run(cmd)
        return p.returncode, None


def run_experiment(name: str, out_dir: Path, config_path: Path = None) -> Path:
    cfg = json.loads(EXPERIMENTS_CFG.read_text(encoding="utf-8"))
    exp = cfg["experiments"].get(name)
    if not exp:
        raise SystemExit(f"Experiment not found: {name}")

    config_path = Path(config_path or cfg.get("default_config"))
    out_dir = out_dir / f"{name}_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # optional honeypot reset (not provided by default)
    honeypot_log_value = os.environ.get("HONEY_HAVEN_LOG_PATH", exp["honeypot_log"])
    honeypot_log = Path(honeypot_log_value).resolve()
    if honeypot_log.exists():
        archive = out_dir / f"honeypot_log_before_{int(time.time())}.jsonl"
        shutil.copy2(honeypot_log, archive)

    # run the simulator
    exp_type = exp.get("type")
    if exp_type == "campaign":
        cmd = ["python", "-m", "attack_simulator", "--config", str(config_path), "campaign", "--campaign", exp["name"]]
    elif exp_type == "scenario":
        cmd = ["python", "-m", "attack_simulator", "--config", str(config_path), "run", "--scenario", exp["name"]]
    elif exp_type == "module":
        cmd = [
            "python",
            "-m",
            "attack_simulator",
            "--config",
            str(config_path),
            "module",
            exp["name"],
            "--profile",
            exp.get("profile", "scanner_like"),
            "--module-config",
            json.dumps(exp.get("module_config", {})),
        ]
    else:
        raise SystemExit(f"Unsupported experiment type: {exp_type}")

    ret, out = _run_cmd(cmd, capture=True)
    if ret != 0:
        # Keep going when a log is present. This allows evaluation of failed/blocked attacks too.
        print("Simulator returned non-zero exit", ret)
        print(out)

    # parse simulator log path from CLI output (looks for 'log=...')
    sim_log_path = None
    for line in out.splitlines():
        if " log=" in line:
            # parse after ' log='
            try:
                parts = line.split()
                for p in parts:
                    if p.startswith("log="):
                        sim_log_path = p.split("=", 1)[1]
            except Exception:
                continue

    if not sim_log_path:
        print("Could not determine simulator log path from output:")
        print(out)
        raise SystemExit(3)

    sim_log = Path(sim_log_path)
    if not sim_log.exists():
        print("Simulator log does not exist:", sim_log)
        raise SystemExit(4)

    # wait for honeypot ingestion to complete
    wait = int(exp.get("wait_after_seconds", 5))
    print(f"Waiting {wait}s for honeypot ingestion...")
    time.sleep(wait)

    # copy honeypot log to out_dir
    hp_copy = out_dir / honeypot_log.name
    if honeypot_log.exists():
        shutil.copy2(honeypot_log, hp_copy)
    else:
        # create an empty placeholder so evaluation can run but will show missing events
        hp_copy.write_text("", encoding="utf-8")

    # run evaluation
    eval_cmd = [
        "python",
        "-m",
        "attack_simulator",
        "evaluate",
        "--sim-log",
        str(sim_log),
        "--hp-log",
        str(hp_copy),
        "--out",
        str(out_dir / "reports"),
        "--label",
        name,
    ]

    ret2, out2 = _run_cmd(eval_cmd, capture=True)
    print(out2)
    if ret2 != 0:
        raise SystemExit(5)

    # the evaluation prints the base path, but the runner returns it; find generated base
    # look for files in out_dir/reports
    reports_dir = out_dir / "reports"
    report_files = list(reports_dir.glob("*")) if reports_dir.exists() else []
    print(f"Experiment output in: {out_dir}")
    return out_dir


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--out", default="experiments_output")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    run_experiment(args.experiment, Path(args.out), config_path=args.config)


if __name__ == "__main__":
    main()
