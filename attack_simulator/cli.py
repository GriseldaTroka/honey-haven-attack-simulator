from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict

from .config import load_configuration
from .controller import ScenarioController


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Modular attack simulation framework")
    parser.add_argument("--config", default="configs/example_campaign.json", help="Path to the JSON configuration file")

    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Run a configured scenario")
    run_parser.add_argument("--scenario", required=True, help="Scenario name to execute")

    campaign_parser = subparsers.add_parser("campaign", help="Run a configured campaign")
    campaign_parser.add_argument("--campaign", required=True, help="Campaign name to execute")

    module_parser = subparsers.add_parser("module", help="Run one module independently")
    module_parser.add_argument("module_name", choices=["reconnaissance", "brute_force", "sql_injection", "api_probe"], help="Module to execute")
    module_parser.add_argument("--profile", default="scanner_like", help="Attacker profile to use")
    module_parser.add_argument("--module-config", default="{}", help="JSON object with module-specific overrides")

    eval_parser = subparsers.add_parser("evaluate", help="Evaluate simulator results against honeypot telemetry")
    eval_parser.add_argument("--sim-log", required=True, help="Path to simulator JSONL log produced by AttackLogger")
    eval_parser.add_argument("--hp-log", required=True, help="Path to honeypot telemetry JSONL (JSONL)")
    eval_parser.add_argument("--out", default="evaluation_reports", help="Directory to write reports")
    eval_parser.add_argument("--label", default=None, help="Label for the evaluation run")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    configuration = load_configuration(args.config)
    controller = ScenarioController(configuration)

    if args.command == "run":
        outcome = controller.run_scenario(args.scenario)
    elif args.command == "campaign":
        outcome = controller.run_campaign(args.campaign)
    elif args.command == "module":
        import json

        module_config: Dict[str, Any] = json.loads(args.module_config)
        outcome = controller.run_module(args.module_name, profile_name=args.profile, module_config=module_config)
    elif args.command == "evaluate":
        # run evaluation comparing the simulator's log to honeypot telemetry
        from .eval.runner import run_evaluation

        out = Path(args.out)
        base = run_evaluation(Path(args.sim_log), Path(args.hp_log), out, label=args.label)
        print(f"Evaluation report generated: {base}")
        return 0
    else:
        parser.print_help()
        return 1

    campaign_label = outcome.campaign_name or outcome.scenario_name
    print(f"campaign={campaign_label} success={outcome.success} duration_ms={outcome.duration_ms} requests={outcome.request_count} log={outcome.log_path}")
    if outcome.phase_names:
        print(f"phases={','.join(outcome.phase_names)}")
    if outcome.errors:
        print(f"errors={len(outcome.errors)}")
    for result in outcome.module_results:
        print(f"module={result.module} requests={result.request_count} duration_ms={result.duration_ms} success={result.success}")
    return 0 if outcome.success else 2


if __name__ == "__main__":
    raise SystemExit(main())
