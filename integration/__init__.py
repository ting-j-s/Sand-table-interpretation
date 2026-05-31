"""
D03 Integration Package — Sandbox Deduction & Red-Blue Teaming
==============================================================
Provides evaluation metrics, sandbox orchestration, and cross-module
interfaces for the D03 sandbox deduction pipeline.

Modules:
  - D03_评估引擎_逃逸成功率与成本: Escape success rate, defense effectiveness, cost models
  - D03_沙盘编排器_基础版: Sandbox orchestration, red/blue rounds
  - D03_沙盘编排器扩展_红蓝对抗: Extended red-blue teaming

Cross-module interfaces:
  D02 -> D03: Agent flow attack results feed into sandbox evaluation
  D03 -> D04: Sandbox findings inform GNN topology optimization
  D03 -> D05: Red-team discoveries seed data poisoning strategies
  D03 -> D06: Cost models from sandbox inform budget controls

Usage:
  from integration.D03_沙盘编排器_基础版 import SandboxOrchestrator
"""

__all__ = [
    "SandboxOrchestrator",
]

__version__ = "1.0.0"
