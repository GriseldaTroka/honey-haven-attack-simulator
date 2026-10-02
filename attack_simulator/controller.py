from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter, sleep
from typing import Any, Dict, List

from .config import AttackConfiguration, CampaignDefinition, CampaignStep, ScenarioDefinition, ScenarioStep
from .http_client import AttackHttpClient
from .logging_utils import AttackLogger
from .models import ModuleResult
from .modules import ApiProbeModule, BruteForceModule, ReconnaissanceModule, SqlInjectionModule
from .modules.base import AttackModule, ModuleContext
from .profiles import build_profile


MODULE_REGISTRY = {
    "reconnaissance": ReconnaissanceModule(),
    "brute_force": BruteForceModule(),
    "sql_injection": SqlInjectionModule(),
    "api_probe": ApiProbeModule(),
}


@dataclass(slots=True)
class CampaignOutcome:
    scenario_name: str
    campaign_name: str = ""
    execution_kind: str = "scenario"
    success: bool = True
    duration_ms: float = 0.0
    phase_names: List[str] = field(default_factory=list)
    module_results: List[ModuleResult] = field(default_factory=list)
    request_count: int = 0
    errors: List[str] = field(default_factory=list)
    log_path: str = ""
    target_base_url: str = ""
    profile_name: str = ""
    target_environment: Dict[str, Any] = field(default_factory=dict)


class ScenarioController:
    def __init__(self, configuration: AttackConfiguration) -> None:
        self.configuration = configuration

    def _module_for(self, module_name: str) -> AttackModule:
        try:
            return MODULE_REGISTRY[module_name]
        except KeyError as exc:
            raise KeyError(f"Unknown module: {module_name}") from exc

    def _run_sequence(
        self,
        execution_name: str,
        execution_kind: str,
        profile_name: str,
        base_url: str,
        steps: List[Dict[str, Any]],
        target_environment: Dict[str, Any] | None = None,
    ) -> CampaignOutcome:
        profile_config = self.configuration.profiles.get(profile_name, {})
        profile = build_profile(profile_name, profile_config)
        logger = AttackLogger(scenario_name=execution_name, output_dir=self.configuration.output_dir)
        client = AttackHttpClient(base_url, profile, self.configuration.default_timeout_seconds)
        started = perf_counter()
        duration_ms = 0.0
        module_results: List[ModuleResult] = []
        phase_names: List[str] = []
        errors: List[str] = []
        request_count = 0
        success = True
        log_path = ""
        target_environment = dict(target_environment or {})

        try:
            logger.log_campaign_start(
                campaign_name=execution_name,
                profile_name=profile.name,
                base_url=base_url,
                execution_kind=execution_kind,
                phase_count=len(steps),
                target_environment=target_environment,
            )
            for index, step in enumerate(steps, start=1):
                phase_name = str(step.get("phase", step.get("module", f"phase-{index}")))
                module_name = str(step["module"])
                step_config = dict(self.configuration.module_defaults.get(module_name, {}))
                step_config.update(dict(step.get("config", {})))
                target_endpoints = [str(value) for value in step.get("target_endpoints", [])]
                delay_before_ms = float(step.get("delay_before_ms", 0.0))
                delay_after_ms = float(step.get("delay_after_ms", 0.0))

                if delay_before_ms > 0:
                    sleep(delay_before_ms / 1000.0)

                logger.log_event(
                    "campaign_phase_start",
                    campaign_name=execution_name,
                    execution_kind=execution_kind,
                    phase=phase_name,
                    phase_index=index,
                    module=module_name,
                    target_endpoints=target_endpoints,
                    delay_before_ms=delay_before_ms,
                    delay_after_ms=delay_after_ms,
                )

                step_config.setdefault("target_endpoints", target_endpoints)
                context = ModuleContext(
                    scenario_name=execution_name,
                    module_name=module_name,
                    module_config=step_config,
                )

                try:
                    result = self._module_for(module_name).run(client, logger, context)
                except Exception as exc:  # pragma: no cover - defensive runtime guard
                    result = ModuleResult(
                        module=module_name,
                        success=False,
                        request_count=0,
                        duration_ms=0.0,
                        error=str(exc),
                    )
                    errors.append(f"{phase_name}: {exc}")

                module_results.append(result)
                phase_names.append(phase_name)
                request_count += result.request_count
                success = success and result.success
                if result.error:
                    errors.append(f"{phase_name}: {result.error}")

                logger.log_event(
                    "campaign_phase_end",
                    campaign_name=execution_name,
                    execution_kind=execution_kind,
                    phase=phase_name,
                    phase_index=index,
                    module=module_name,
                    success=result.success,
                    request_count=result.request_count,
                    duration_ms=result.duration_ms,
                    error=result.error,
                )

                if delay_after_ms > 0:
                    sleep(delay_after_ms / 1000.0)
        finally:
            client.close()
            duration_ms = (perf_counter() - started) * 1000.0
            logger.log_campaign_end(
                campaign_name=execution_name,
                success=success and not errors,
                duration_ms=round(duration_ms, 2),
                execution_kind=execution_kind,
                phase_count=len(phase_names),
                request_count=request_count,
                error_count=len(errors),
                phases=phase_names,
                target_environment=target_environment,
            )
            log_path = str(logger.log_path)
            logger.close()

        return CampaignOutcome(
            scenario_name=execution_name,
            campaign_name=execution_name if execution_kind == "campaign" else "",
            execution_kind=execution_kind,
            success=success and not errors,
            duration_ms=round(duration_ms, 2),
            phase_names=phase_names,
            module_results=module_results,
            request_count=request_count,
            errors=errors,
            log_path=log_path,
            target_base_url=base_url,
            profile_name=profile.name,
            target_environment=target_environment,
        )

    def run_scenario(self, scenario_name: str) -> CampaignOutcome:
        scenario = self.configuration.scenarios.get(scenario_name)
        if scenario is None:
            raise KeyError(f"Unknown scenario: {scenario_name}")

        steps = [
            {
                "phase": step.module,
                "module": step.module,
                "config": step.config,
            }
            for step in scenario.steps
        ]
        return self._run_sequence(
            execution_name=scenario.name,
            execution_kind="scenario",
            profile_name=scenario.profile,
            base_url=self.configuration.base_url,
            steps=steps,
        )

    def run_campaign(self, campaign_name: str) -> CampaignOutcome:
        campaign = self.configuration.campaigns.get(campaign_name)
        if campaign is None:
            raise KeyError(f"Unknown campaign: {campaign_name}")

        steps = [
            {
                "phase": step.phase,
                "module": step.module,
                "config": step.config,
                "delay_before_ms": step.delay_before_ms,
                "delay_after_ms": step.delay_after_ms,
                "target_endpoints": step.target_endpoints,
            }
            for step in campaign.steps
        ]
        base_url = str(campaign.target_environment.get("base_url", self.configuration.base_url))
        return self._run_sequence(
            execution_name=campaign.name,
            execution_kind="campaign",
            profile_name=campaign.profile,
            base_url=base_url,
            steps=steps,
            target_environment=campaign.target_environment,
        )

    def run_module(self, module_name: str, profile_name: str | None = None, module_config: Dict[str, Any] | None = None) -> CampaignOutcome:
        module = self._module_for(module_name)
        execution_name = f"module-{module_name}"
        profile_key = profile_name or "scanner_like"
        profile_config = self.configuration.profiles.get(profile_key, {})
        profile = build_profile(profile_key, profile_config)
        logger = AttackLogger(scenario_name=execution_name, output_dir=self.configuration.output_dir)
        client = AttackHttpClient(self.configuration.base_url, profile, self.configuration.default_timeout_seconds)
        started = perf_counter()
        duration_ms = 0.0
        try:
            logger.log_campaign_start(
                campaign_name=execution_name,
                profile_name=profile.name,
                base_url=self.configuration.base_url,
                execution_kind="module",
                phase_count=1,
            )
            context = ModuleContext(
                scenario_name=execution_name,
                module_name=module_name,
                module_config={**self.configuration.module_defaults.get(module_name, {}), **(module_config or {})},
            )
            result = module.run(client, logger, context)
            duration_ms = (perf_counter() - started) * 1000.0
            logger.log_campaign_end(
                campaign_name=execution_name,
                success=result.success,
                duration_ms=round(duration_ms, 2),
                execution_kind="module",
                phase_count=1,
                request_count=result.request_count,
                error_count=1 if result.error else 0,
                phases=[module_name],
            )
            log_path = str(logger.log_path)
            return CampaignOutcome(
                scenario_name=execution_name,
                execution_kind="module",
                success=result.success,
                duration_ms=round(duration_ms, 2),
                phase_names=[module_name],
                module_results=[result],
                request_count=result.request_count,
                errors=[result.error] if result.error else [],
                log_path=log_path,
                target_base_url=self.configuration.base_url,
                profile_name=profile.name,
            )
        finally:
            client.close()
            logger.close()
