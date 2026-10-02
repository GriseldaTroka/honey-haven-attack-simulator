from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass(slots=True)
class ScenarioStep:
    module: str
    config: Dict[str, Any]


@dataclass(slots=True)
class ScenarioDefinition:
    name: str
    profile: str
    description: str
    steps: List[ScenarioStep]


@dataclass(slots=True)
class CampaignStep:
    phase: str
    module: str
    config: Dict[str, Any]
    delay_before_ms: float = 0.0
    delay_after_ms: float = 0.0
    target_endpoints: List[str] = field(default_factory=list)


@dataclass(slots=True)
class CampaignDefinition:
    name: str
    profile: str
    description: str
    steps: List[CampaignStep]
    target_environment: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AttackConfiguration:
    base_url: str
    default_timeout_seconds: float
    output_dir: Path
    profiles: Dict[str, Any]
    scenarios: Dict[str, ScenarioDefinition]
    campaigns: Dict[str, CampaignDefinition]
    module_defaults: Dict[str, Dict[str, Any]]


def load_configuration(path: str | Path) -> AttackConfiguration:
    config_path = Path(path)
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    base_url = str(raw["target"]["base_url"])
    default_timeout_seconds = float(raw.get("default_timeout_seconds", 10.0))
    output_dir = Path(raw.get("logging", {}).get("output_dir", "logs"))

    profiles = raw.get("profiles", {})
    scenarios: Dict[str, ScenarioDefinition] = {}
    for name, scenario_data in raw.get("scenarios", {}).items():
        steps = [ScenarioStep(module=str(step["module"]), config=dict(step.get("config", {}))) for step in scenario_data.get("steps", [])]
        scenarios[name] = ScenarioDefinition(
            name=name,
            profile=str(scenario_data.get("profile", "browser_like")),
            description=str(scenario_data.get("description", "")),
            steps=steps,
        )

    campaigns: Dict[str, CampaignDefinition] = {}
    for name, campaign_data in raw.get("campaigns", {}).items():
        steps = [
            CampaignStep(
                phase=str(step.get("phase", step.get("name", f"phase-{index}"))),
                module=str(step["module"]),
                config=dict(step.get("config", {})),
                delay_before_ms=float(step.get("delay_before_ms", step.get("delay_ms_before", 0.0))),
                delay_after_ms=float(step.get("delay_after_ms", step.get("delay_ms_after", 0.0))),
                target_endpoints=[str(value) for value in step.get("target_endpoints", [])],
            )
            for index, step in enumerate(campaign_data.get("steps", []), start=1)
        ]
        campaigns[name] = CampaignDefinition(
            name=name,
            profile=str(campaign_data.get("profile", "browser_like")),
            description=str(campaign_data.get("description", "")),
            steps=steps,
            target_environment=dict(campaign_data.get("target_environment", {})),
        )

    module_defaults = {str(name): dict(value) for name, value in raw.get("module_defaults", {}).items()}
    return AttackConfiguration(
        base_url=base_url,
        default_timeout_seconds=default_timeout_seconds,
        output_dir=output_dir,
        profiles=profiles,
        scenarios=scenarios,
        campaigns=campaigns,
        module_defaults=module_defaults,
    )
