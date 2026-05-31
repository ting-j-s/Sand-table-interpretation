"""
D03 Integration Package — Sandbox Deduction & Red-Blue Teaming
==============================================================
Provides evaluation metrics, sandbox orchestration, and cross-module
interfaces for the D03 sandbox deduction pipeline.

Modules:
  - D03_evaluation: Escape success rate, defense effectiveness, cost models
  - D03_sandbox_orchestrator: Cyber range MARL simulation, red/blue rounds

Cross-module interfaces:
  D02 -> D03: Agent flow attack results feed into sandbox evaluation
  D03 -> D04: Sandbox findings inform GNN topology optimization
  D03 -> D05: Red-team discoveries seed data poisoning strategies
  D03 -> D06: Cost models from sandbox inform budget controls

Usage:
  from D03_integration import SandboxOrchestrator, EscapeSuccessRate
  from D03_integration import BenchmarkResult, DefenseEvaluator
"""
from .D03_evaluation import (
    BenchmarkResult,
    EscapeSuccessRate,
    DefenseEvaluator,
    CostModel,
)
from .D03_sandbox_orchestrator import (
    SandboxOrchestrator,
)

__all__ = [
    # Evaluation
    "BenchmarkResult",
    "EscapeSuccessRate",
    "DefenseEvaluator",
    "CostModel",
    # Orchestration
    "SandboxOrchestrator",
]

__version__ = "1.0.0"
