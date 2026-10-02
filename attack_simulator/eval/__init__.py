"""Evaluation and metrics package for the attack simulator.

Provides routines to compute detection/logging/journey/performance metrics
and to generate simple JSON/HTML reports comparing simulator output vs
honeypot telemetry.
"""

from .metrics import compute_metrics
from .reporting import generate_report
from .runner import run_evaluation

__all__ = ["compute_metrics", "generate_report", "run_evaluation"]
