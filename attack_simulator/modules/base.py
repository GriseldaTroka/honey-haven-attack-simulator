from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict

from ..http_client import AttackHttpClient
from ..logging_utils import AttackLogger
from ..models import ModuleResult


@dataclass(slots=True)
class ModuleContext:
    scenario_name: str
    module_name: str
    module_config: Dict[str, Any]


class AttackModule(ABC):
    name: str

    @abstractmethod
    def run(self, client: AttackHttpClient, logger: AttackLogger, context: ModuleContext) -> ModuleResult:
        raise NotImplementedError
