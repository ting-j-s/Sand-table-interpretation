
"""D03 Framework Adapter — bridges D03_agent_framework with existing sandbox agents.

Wraps formula-based agents (UserAgent/RedAgent/BlueAgent/CompanyAgent) and
LLM-driven agents with the D03Agent framework interface. Provides
FrameworkOrchestrator as a framework-native orchestration layer.
"""

import sys, time, math, random, json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from collections import defaultdict

try:
    from D03_agent_framework import (
        D03Agent, AgentDefinition, AgentType, AgentContext,
        D03Tool, ToolRegistry, PermissionContext, PermissionMode,
        d03_tool_registry, d03_agent_registry,
    )
    HAS_FRAMEWORK = True
except ImportError as e:
    HAS_FRAMEWORK = False
    print(f"[Adapter] D03_agent_framework not available: {e}")

try:
    from D03_four_party_sandbox import RedAgent, BlueAgent, UserAgent, OCEANProfile, UserRole
    HAS_SANDBOX = True
except ImportError:
    HAS_SANDBOX = False


# ============================================================================
# AgentAdapter — wraps any agent to expose D03Agent interface
# ============================================================================

class AgentAdapter(D03Agent if HAS_FRAMEWORK else object):
    """Wraps an existing agent into the D03Agent framework interface."""

    def __init__(self, definition, wrapped_agent=None):
        if HAS_FRAMEWORK:
            super().__init__(definition)
        self.definition = definition
        self.wrapped = wrapped_agent
        self.adapter_stats = {"adapted_calls": 0, "errors": 0}
        self.custom_turn_count = 0

    def init_context(self, agent_name: str, agent_type, parent_permission=None):
        if HAS_FRAMEWORK:
            self.context = AgentContext(agent_name=agent_name, agent_type=agent_type)
            self.permission_context = PermissionContext(
                parent_mode=parent_permission,
                child_mode=PermissionMode.MANUAL,  # Allow tools requiring MANUAL
            )
            self.turn_count = 0

    def execute_turn(self, task: str) -> Dict[str, Any]:
        """Framework-compatible execute_turn: takes task string, returns result dict."""
        if not HAS_FRAMEWORK:
            return {"status": "no_framework", "task": task}

        self.adapter_stats["adapted_calls"] += 1
        self.custom_turn_count += 1

        try:
            delegated = self._delegate(task)
            tool_name = self._match_task_to_tool(task)

            if tool_name and self.context:
                try:
                    tool_result = self.use_tool(tool_name, task=task)
                    return {
                        "status": "completed",
                        "delegated": delegated,
                        "tool_used": tool_name,
                        "tool_result": tool_result,
                        "turn": self.custom_turn_count,
                    }
                except Exception as e:
                    return {"status": "tool_error", "error": str(e), "delegated": delegated}

            return {
                "status": "completed",
                "delegated": delegated,
                "tool_used": tool_name,
                "turn": self.custom_turn_count,
            }
        except Exception as e:
            self.adapter_stats["errors"] += 1
            return {"status": "error", "error": str(e)}

    def _delegate(self, task: str) -> Dict:
        raise NotImplementedError

    def get_summary(self) -> Dict:
        base = super().get_summary() if HAS_FRAMEWORK else {}
        base["adapter_stats"] = self.adapter_stats
        base["wrapped_type"] = type(self.wrapped).__name__ if self.wrapped else "None"
        return base


# ============================================================================
# Specific Adapters
# ============================================================================

class RedAgentAdapter(AgentAdapter):
    def _delegate(self, task: str) -> Dict:
        skill = getattr(self.wrapped, "skill_level", 0.5)
        stealth = getattr(self.wrapped, "stealth", 0.5)
        task_lower = task.lower()

        if "recon" in task_lower:
            return {"action": "recon", "detection_risk": round(max(0.1, 1 - skill * 0.7), 3)}
        elif "exploit" in task_lower:
            return {"action": "exploit", "success_prob": round(0.25 + skill * 0.3, 3)}
        elif "escape" in task_lower or "sandbox" in task_lower:
            return {"action": "sandbox_escape", "success_prob": round(0.15 + skill * 0.25, 3)}
        elif "exfiltrate" in task_lower or "exfil" in task_lower:
            detected = random.random() > skill * 0.6
            return {"action": "exfiltrate", "detected": detected, "data_mb": random.randint(10, 500)}
        else:
            return {"action": "generic_attack", "skill": skill, "stealth": stealth}


class BlueAgentAdapter(AgentAdapter):
    def _delegate(self, task: str) -> Dict:
        det_rate = getattr(self.wrapped, "detection_rate", 0.7) if self.wrapped else 0.7
        exp = getattr(self.wrapped, "experience", 0.5) if self.wrapped else 0.5
        task_lower = task.lower()

        shift_mult = 1.0
        if "night" in task_lower:
            shift_mult = 0.7
        elif "swing" in task_lower:
            shift_mult = 0.85

        eff = det_rate * (1 - random.uniform(0, 0.1)) * shift_mult
        detected = random.random() < eff
        return {
            "action": "analyze_threat",
            "detected": detected,
            "effective_detection_rate": round(eff, 3),
            "experience": round(exp, 3),
        }


class UserAgentAdapter(AgentAdapter):
    def _delegate(self, task: str) -> Dict:
        user = self.wrapped
        task_lower = task.lower()

        if "email" in task_lower or "phish" in task_lower:
            soph = 0.5
            if hasattr(user, "phishing_click_probability"):
                click_prob = user.phishing_click_probability(soph)
            else:
                click_prob = 0.25
            clicked = random.random() < click_prob
            reported = (not clicked) and random.random() < getattr(user, "report_probability", lambda: 0.3)()
            return {"action": "email_processed", "clicked": clicked, "reported": reported}

        elif "daily" in task_lower or "action" in task_lower:
            if hasattr(user, "generate_daily_actions"):
                actions = user.generate_daily_actions(0)
            else:
                actions = [{"action": "login"}]
            return {"action": "daily_actions", "count": len(actions)}

        elif "training" in task_lower:
            if hasattr(user, "receive_training"):
                user.receive_training(0.7)
            return {"action": "training_completed"}

        return {"action": "daily_routine", "security_awareness": getattr(user, "security_awareness", 0.5)}


class CompanyAgentAdapter(AgentAdapter):
    def _delegate(self, task: str) -> Dict:
        return {
            "budget_personnel": 0.45,
            "budget_tools": 0.30,
            "budget_training": 0.15,
            "monitoring_coverage": 0.75,
            "patch_cycle_days": 14,
        }


# ============================================================================
# FrameworkOrchestrator
# ============================================================================

class FrameworkOrchestrator:
    """Coordinates agents using the D03Agent framework with permission model."""

    def __init__(self, config: Dict = None):
        self.config = config or {"num_users": 50, "num_episodes": 20}
        self.agents: Dict[str, D03Agent] = {}
        self.episode_log: List[Dict] = []

    def register_agent(self, agent: D03Agent, agent_id: str):
        """Register an agent with the orchestrator."""
        self.agents[agent_id] = agent
        if HAS_FRAMEWORK:
            agent.init_context(agent_id, AgentType.BUILT_IN, PermissionMode.BYPASS)

    def run_episode(self, episode_num: int) -> Dict:
        tasks = {
            "company": "allocate security budget for the quarter",
            "red": "recon and exploit target network infrastructure",
            "blue": "monitor alerts and detect threats in the network",
            "user": "process daily emails and handle routine tasks",
        }
        results = {}
        for agent_id, agent in self.agents.items():
            task = tasks.get(agent_id, f"execute episode {episode_num}")
            result = agent.execute_turn(task)
            results[agent_id] = result

        self.episode_log.append({"episode": episode_num, "results": results})
        return {"episode": episode_num, "agents_active": len(results)}

    def run_simulation(self, n_episodes: int = 10) -> List[Dict]:
        print(f"[FrameworkOrchestrator] Running {n_episodes} episodes, {len(self.agents)} agents...")
        for ep in range(n_episodes):
            self.run_episode(ep)
            if ep % 3 == 0:
                print(f"  Ep {ep+1}/{n_episodes}")
        print(f"  Done. {n_episodes} episodes completed.")
        return self.episode_log

    def get_summary(self) -> Dict:
        return {
            "total_episodes": len(self.episode_log),
            "agents": {aid: a.get_summary() for aid, a in self.agents.items()},
        }


# ============================================================================
# Pre-built Agent Definitions (matching actual framework AgentDefinition)
# ============================================================================

def create_red_def():
    return AgentDefinition(
        name="red_agent",
        agent_type=AgentType.BUILT_IN,
        system_prompt="Red team operator targeting corporate network. Execute multi-stage attacks.",
        tools=["exploit_attempt", "sandbox_escape", "phish_send"],
        description="Offensive security agent for multi-stage attack simulation",
    )

def create_blue_def():
    return AgentDefinition(
        name="blue_agent",
        agent_type=AgentType.BUILT_IN,
        system_prompt="SOC analyst defending corporate network. Detect and respond to threats.",
        tools=["threat_detect", "monitor_alert", "mtd_rotate", "security_log"],
        description="Defensive security agent for detection and response",
    )

def create_user_def():
    return AgentDefinition(
        name="user_agent",
        agent_type=AgentType.BUILT_IN,
        system_prompt="Enterprise employee processing daily tasks with OCEAN personality traits.",
        tools=["email_process"],
        description="Enterprise employee digital twin",
    )

def create_company_def():
    return AgentDefinition(
        name="company_agent",
        agent_type=AgentType.BUILT_IN,
        system_prompt="CISO making strategic security budget and policy decisions.",
        tools=["security_log", "monitor_alert"],
        description="Executive agent for security strategy decisions",
    )


# ============================================================================
# Self-Test
# ============================================================================

if __name__ == "__main__":
    print("=" * 65)
    print("  D03 Framework Adapter — Self-Test")
    print("=" * 65)

    # Test 1: Framework detection
    print(f"\n[1] Framework available: {HAS_FRAMEWORK}")
    print(f"    Sandbox available: {HAS_SANDBOX}")

    # Test 2: Create mock agents and adapters
    print("\n[2] Creating adapters...")
    class MockRedAgent:
        skill_level = 0.6; stealth = 0.5; id = 1
    class MockBlueAgent:
        detection_rate = 0.75; experience = 0.5
    class MockUserAgent:
        security_awareness = 0.6
        def phishing_click_probability(self, s): return 0.3 * s
        def report_probability(self): return 0.4
        def generate_daily_actions(self, d): return [{"action": "login"}]
        def receive_training(self, q): pass

    if HAS_FRAMEWORK:
        red_agent = RedAgentAdapter(create_red_def(), MockRedAgent())
        blue_agent = BlueAgentAdapter(create_blue_def(), MockBlueAgent())
        user_agent = UserAgentAdapter(create_user_def(), MockUserAgent())
        print(f"  [OK] Created 3 adapters: Red, Blue, User")

        # Test 3: Execute turns
        print("\n[3] Executing turns...")
        orch = FrameworkOrchestrator()
        orch.register_agent(red_agent, "red")
        orch.register_agent(blue_agent, "blue")
        orch.register_agent(user_agent, "user")

        r = red_agent.execute_turn("exploit vulnerability in web server")
        assert r["status"] == "completed", f"Red failed: {r}"
        print(f"  [OK] Red: tool_used={r.get('tool_used')}, delegated={r['delegated']['action']}")

        b = blue_agent.execute_turn("monitor alerts and detect threats")
        assert b["status"] == "completed"
        print(f"  [OK] Blue: tool_used={b.get('tool_used')}, detected={b['delegated']['detected']}")

        u = user_agent.execute_turn("process email from external sender")
        assert u["status"] == "completed"
        print(f"  [OK] User: tool_used={u.get('tool_used')}, action={u['delegated']['action']}")

        # Test 4: Run simulation
        print("\n[4] Running 5-episode simulation...")
        logs = orch.run_simulation(5)
        assert len(logs) == 5
        summary = orch.get_summary()
        print(f"  [OK] {summary['total_episodes']} episodes completed with {len(summary['agents'])} agents")

        # Test 5: Permission inheritance
        print("\n[5] Permission inheritance test...")
        parent = PermissionContext(parent_mode=PermissionMode.AUTO, child_mode=PermissionMode.MANUAL)
        child = PermissionContext(parent_mode=parent.effective_mode(), child_mode=PermissionMode.BYPASS)
        assert child.effective_mode() == PermissionMode.AUTO, f"Child must not escalate! Got: {child.effective_mode()}"
        print(f"  [OK] Child BYPASS with parent AUTO → effective={child.effective_mode().name} (child cannot escalate)")

        print(f"\n{'=' * 65}")
        print(f"  [D03 Framework Adapter] All self-tests passed.")
        print(f"{'=' * 65}")
    else:
        print("  [SKIP] Framework not available, skipping tests")
