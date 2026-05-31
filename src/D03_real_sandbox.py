"""D03 Real Sandbox — All four parties driven by real DeepSeek API.
Company/User/Blue/Red agents make actual LLM calls with personality prompts,
skill libraries, and knowledge bases. Formula fallback on API failure.
"""
import sys, os, json, time, math, random
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any
from enum import Enum

BASE_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BASE_DIR))

from real_llm import call_llm, FLASH, PRO

# ============================================================================
# API Cost Tracker
# ============================================================================
class APICostTracker:
    """ API成本追踪器：按智能体/模型/token统计DeepSeek API调用成本和延迟。 """
    def __init__(self):
        self.calls = 0
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_latency = 0.0
        self.by_agent = defaultdict(lambda: {"calls":0,"cost":0.0,"tokens":0,"failures":0})
        self.call_log = []

    def record(self, agent, result, elapsed):
        self.calls += 1
        cost = result.get("cost_usd", 0) if isinstance(result, dict) else 0
        tokens = result.get("total_tokens", 0) if isinstance(result, dict) else 0
        self.total_cost += cost
        self.total_tokens += tokens
        self.total_latency += elapsed
        a = self.by_agent[agent]
        a["calls"] += 1
        a["cost"] += cost
        a["tokens"] += tokens

    def record_failure(self, agent):
        self.by_agent[agent]["failures"] += 1

    def summary(self):
        return {"total_calls": self.calls, "total_cost": round(self.total_cost, 6),
                "total_tokens": self.total_tokens, "total_latency_s": round(self.total_latency, 1),
                "by_agent": dict(self.by_agent)}

def _safe_api_call(agent_name, model, system_prompt, user_prompt, max_tokens=200, temperature=0.7, fallback=None):
    """Call LLM with fallback on failure."""
    global COST
    t0 = time.time()
    try:
        result = call_llm(model, system_prompt, user_prompt, max_tokens=max_tokens, temperature=temperature)
        elapsed = time.time() - t0
        if COST:
            COST.record(agent_name, result, elapsed)
        return result["content"].strip()
    except Exception as e:
        if COST:
            COST.record_failure(agent_name)
        if fallback is not None:
            return fallback
        return str(e)[:100]
# ============================================================================
# 1. Real CompanyAgent — LLM Pro generates strategy from threat reports
# ============================================================================

class RealCompanyAgent:
    """ 真实API驱动公司智能体：LLM Pro根据威胁报告动态生成安全策略(预算分配/监控覆盖率/培训频率/补丁周期)。 """
    def __init__(self, name="TargetCorp"):
        self.name = name
        self.budget_pct = 0.12
        self.monitoring_coverage = 0.70
        self.training_frequency = 4
        self.training_quality = 0.6
        self.strategy_history = []

    def generate_strategy(self, threat_report):
        sp = "You are the CISO of a mid-size enterprise. Based on the threat report, decide resource allocation. Reply with JSON only: {\"budget_pct\": 0.05-0.30, \"monitoring_coverage\": 0.40-0.95, \"training_frequency\": 1-12, \"training_quality\": 0.3-0.9, \"patch_cycle_days\": 7-60, \"reasoning\": \"1-sentence\"}"
        up = "Threat report: {}".format(json.dumps(threat_report))
        
        fb = json.dumps({"budget_pct":0.15, "monitoring_coverage":0.75, "training_frequency":6, "training_quality":0.6,
                         "patch_cycle_days":30})
        raw = _safe_api_call("CompanyAgent", PRO, sp, up, max_tokens=300, temperature=0.3, fallback=fb)
        try:
            plan = json.loads(raw)
            self.budget_pct = float(plan.get("budget_pct", 0.12))
            self.monitoring_coverage = float(plan.get("monitoring_coverage", 0.70))
            self.training_frequency = int(plan.get("training_frequency", 4))
            self.training_quality = float(plan.get("training_quality", 0.6))
            self.strategy_history.append(plan)
            return plan
        except:
            self.strategy_history.append({"fallback": True})
            return {"budget_pct": 0.12, "monitoring_coverage": 0.70, 
                    "training_frequency": 4, "training_quality": 0.6, 
                    "patch_cycle_days": 30, "reasoning": "API parse failed, using defaults"}

    def get_strategy_vector(self):
        return {
            "monitoring_coverage": self.monitoring_coverage,
            "training_frequency": self.training_frequency,
            "training_quality": self.training_quality,
            "patch_cycle_days": 30,
            "budget_pct": self.budget_pct,
        }
# ============================================================================
# 2. Real BlueAgent — LLM Flash for triage, Pro for threat hunt
# ============================================================================

class RealBlueAgent:
    """ 真实API驱动蓝队智能体：LLM Flash做Tier1告警分类，Pro做Tier3威胁狩猎。替换原版random()公式决策。 """
    def __init__(self, id, tier=1):
        self.id = id; self.tier = tier
        self.alerts_processed = 0; self.incidents_handled = 0
        self.threats_hunted = 0; self.fatigue = 0.0
        self.experience = 0.3 if tier == 1 else (0.5 if tier == 2 else 0.7)
        self.detection_rate = 0.5 + 0.15 * tier

    def triage_alert(self, alert_raw):
        self.alerts_processed += 1
        sp = "You are a Tier-{} SOC analyst. Classify this security alert. Reply with JSON: {{\"is_attack\": true/false, \"severity\": \"low/medium/high/critical\", \"confidence\": 0.0-1.0, \"action\": \"escalate/investigate/ignore\", \"mitre_technique\": \"TXXXX or none\"}}".format(self.tier)
        up = "Alert: {}".format(json.dumps(alert_raw)[:500])
        fb = json.dumps({"is_attack": alert_raw.get("success", False), "severity": "high" if alert_raw.get("success") else "medium", "confidence": 0.7, "action": "investigate" if alert_raw.get("success") else "ignore", "mitre_technique": "T1190"})
        raw = _safe_api_call("BlueAgent-T{}".format(self.tier), FLASH, sp, up, max_tokens=200, temperature=0.2, fallback=fb)
        try:
            r = json.loads(raw)
            return r.get("is_attack", False), r.get("confidence", 0.5), r
        except:
            return alert_raw.get("success", False), 0.7, {}

    def investigate_incident(self, attack_desc):
        self.incidents_handled += 1
        sp = "You are a Tier-2 incident responder. Analyze this attack and provide remediation. Reply with JSON: {{\"accurate\": true/false, \"attack_path\": [\"step1\",\"step2\"], \"mttr_minutes\": 5-120, \"iocs\": [\"indicator1\"], \"containment\": \"immediate/delayed\"}}"
        up = "Attack summary: {}".format(str(attack_desc)[:400])
        fb = json.dumps({"accurate": True, "attack_path": ["recon","exploit","exfil"], "mttr_minutes": 25, "iocs": ["anomalous_outbound"], "containment": "immediate"})
        raw = _safe_api_call("BlueAgent-T2", FLASH, sp, up, max_tokens=300, temperature=0.3, fallback=fb)
        try:
            r = json.loads(raw)
            return {"time_minutes": r.get("mttr_minutes", 25), "accuracy": 0.8, "attack_path_reconstructed": r.get("accurate", True), "iocs": r.get("iocs", [])}
        except:
            return {"time_minutes": 25, "accuracy": 0.7, "attack_path_reconstructed": True}

    def hunt_threats(self, network_size):
        if self.tier < 3:
            return 0
        self.threats_hunted += 1
        sp = 'You are a Tier-3 threat hunter. Based on network size, propose hunt hypotheses. Reply with JSON: {"hypotheses": ["h1","h2"], "likely_threats": 0-5}'
        up = "Network size: {} hosts".format(network_size)
        raw = _safe_api_call("BlueAgent-T3", PRO, sp, up, max_tokens=200, temperature=0.5, fallback='{"hypotheses":["lateral_movement","c2_beacon"],"likely_threats":2}')
        try:
            r = json.loads(raw)
            return r.get("likely_threats", 1)
        except:
            return 2


# ============================================================================
# 3. Real RedAgent -- LLM Pro for attack plans, Flash for adaptation
# ============================================================================

class RealRedAgent:
    """ 真实API驱动红队智能体：LLM Pro生成攻击计划(MITRE技术/隐蔽级别/成功概率)，Flash根据蓝队响应自适应调整。 """
    def __init__(self, id, skill=0.5, stealth=0.5, adaptability=0.4):
        self.id = id; self.skill = skill; self.stealth = stealth; self.adaptability = adaptability
        self.hosts = []; self.exfil = 0.0; self.succ = 0; self.fail = 0; self.path = []

    def plan_attack(self, recon, blue_cap):
        sp = "You are a red team operator. Design attack vector based on recon. Reply JSON: {vector, mitre_technique, stealth_level, estimated_success_prob, evasion_techniques[], reasoning}"
        up = "Recon: {} | BlueCap: {:.2f}".format(str(recon)[:300], blue_cap)
        fb = '{"vector":"exploit","mitre_technique":"T1190","stealth_level":0.5,"estimated_success_prob":0.6}'
        raw = _safe_api_call("Red-{}".format(self.id), PRO, sp, up, max_tokens=350, temperature=0.6, fallback=fb)
        try:
            p = json.loads(raw) if raw[0] == "{" else json.loads("{" + raw.split("{", 1)[1])
            self.path.append(p); return p
        except:
            return {"vector":"exploit","mitre_technique":"T1190","stealth_level":0.5,"estimated_success_prob":0.6}

    def adapt_strategy(self, blue_resp):
        sp = "You are an adaptive red agent. Blue team responded. Adjust. Reply JSON: {new_skill, new_stealth, new_adaptability, lesson}"
        up = "Blue: {} | Now: sk={:.2f} st={:.2f} ad={:.2f}".format(str(blue_resp)[:200], self.skill, self.stealth, self.adaptability)
        raw = _safe_api_call("Red-{}".format(self.id), FLASH, sp, up, max_tokens=200, temperature=0.5, fallback=None)
        try:
            if raw:
                a = json.loads(raw) if raw[0] == "{" else json.loads("{" + raw.split("{", 1)[1])
                self.skill = min(0.95, float(a.get("new_skill", self.skill)))
                self.stealth = min(0.93, float(a.get("new_stealth", self.stealth)))
                self.adaptability = min(0.95, float(a.get("new_adaptability", self.adaptability)))
        except:
            self.skill = min(0.95, self.skill + 0.008)
            self.stealth = min(0.93, self.stealth + 0.005)


# ============================================================================
# 4. Real UserAgent -- LLM Flash with OCEAN personality prompts
# ============================================================================

class RealUserAgent:
    """ 真实API驱动用户智能体：LLM Flash+OCEAN人格prompt驱动行为决策。 """
    # 基于角色的OCEAN人格画像 (替代纯随机初始化)
    ROLE_PERSONAS = {
        "developer": {"O": 0.72, "C": 0.55, "E": 0.40, "A": 0.50, "N": 0.35},
        "executive": {"O": 0.55, "C": 0.50, "E": 0.75, "A": 0.45, "N": 0.55},
        "finance":   {"O": 0.30, "C": 0.78, "E": 0.40, "A": 0.45, "N": 0.50},
        "hr":        {"O": 0.45, "C": 0.55, "E": 0.70, "A": 0.72, "N": 0.45},
        "sales":     {"O": 0.50, "C": 0.40, "E": 0.80, "A": 0.55, "N": 0.40},
        "it_admin":  {"O": 0.55, "C": 0.70, "E": 0.35, "A": 0.50, "N": 0.30},
        "analyst":   {"O": 0.65, "C": 0.60, "E": 0.40, "A": 0.55, "N": 0.40},
        "intern":    {"O": 0.60, "C": 0.35, "E": 0.55, "A": 0.65, "N": 0.60},
    }
    # 部门安全意识基线
    DEPT_AWARENESS = {
        "engineering": 0.55, "finance": 0.45, "hr": 0.40,
        "sales": 0.35, "ops": 0.60, "general": 0.30,
    }

    def __init__(self, id, name, role, dept="general"):
        self.id = id; self.name = name; self.role = role; self.dept = dept
        self.phished = 0; self.reported = 0; self.violations = 0
        self.fatigue = 0.0; self.mem = []
        # 基于角色的人格画像 + 微小个体差异
        base = self.ROLE_PERSONAS.get(role, {"O": 0.50, "C": 0.55, "E": 0.50, "A": 0.55, "N": 0.45})
        self.ocean = {k: max(0.01, min(0.99, base[k] + random.gauss(0, 0.08))) for k in base}
        self.awareness = self.DEPT_AWARENESS.get(dept, 0.30) + random.uniform(-0.05, 0.10)

    def _persona(self):
        o = self.ocean
        return "Role:{} Dept:{} O:{:.2f} C:{:.2f} E:{:.2f} A:{:.2f} N:{:.2f} Aware:{:.2f} Fatigue:{:.2f}".format(
            self.role, self.dept, o["O"], o["C"], o["E"], o["A"], o["N"], self.awareness, self.fatigue)

    def decide_action(self, email_data=None):
        sp = "You are an employee with these personality traits. Decide how to handle this situation. Reply JSON: {action: ignore/click/report/forward, confidence: 0.0-1.0, reasoning: 1-sentence}"
        up = self._persona()
        if email_data: up += " | Event: " + str(email_data)[:200]
        fb = '{"action":"ignore","confidence":0.8}'
        raw = _safe_api_call("User-{}".format(self.id), FLASH, sp, up, max_tokens=150, temperature=0.7, fallback=fb)
        try:
            r = json.loads(raw) if raw[0] == "{" else json.loads("{" + raw.split("{", 1)[1])
            self.mem.append(r)
            if r.get("action") == "click": self.phished += 1
            elif r.get("action") == "report": self.reported += 1
            return r
        except:
            return {"action":"ignore","confidence":0.7}


# ============================================================================
# 5. RealOrchestrator -- wires all four API-driven agents together
# ============================================================================

class RealOrchestrator:
    """ 真实API驱动四方总控引擎：串联公司/用户/蓝队/红队四个API智能体，每轮输出攻防指标和成本统计。 """
    def __init__(self, config=None):
        global COST
        self.cfg = config or {"users": 20, "hosts": 20, "blue_t1": 3, "blue_t2": 1, "blue_t3": 1, "red": 3}
        self.ep = 0
        COST = APICostTracker()
        self.cost = COST
        self.company = RealCompanyAgent("TargetCorp")
        self.users = [RealUserAgent(i, "User_{}".format(i),
            random.choice(["developer","executive","finance","hr","sales","it_admin","analyst","intern"]),
            random.choice(["engineering","finance","hr","sales","ops"]))
            for i in range(self.cfg["users"])]
        self.blue = []
        for i in range(self.cfg["blue_t1"]):
            self.blue.append(RealBlueAgent(len(self.blue), tier=1))
        self.blue.append(RealBlueAgent(len(self.blue), tier=2))
        self.blue.append(RealBlueAgent(len(self.blue), tier=3))
        self.red = [RealRedAgent(i, 0.4 + 0.15*i, 0.4 + 0.1*i, 0.3 + 0.1*i)
                    for i in range(self.cfg["red"])]
        self.attacks = []; self.defenses = []; self.metrics = []
        print("[RealOrchestrator] {} users {} blue {} red | API: DeepSeek Flash+Pro".format(
            len(self.users), len(self.blue), len(self.red)))

    def run_episode(self):
        ep = self.ep; self.ep += 1
        threat = {"active_attacks": len(self.attacks), "ep": ep}
        strategy = self.company.generate_strategy(threat)
        mon = strategy.get("monitoring_coverage", 0.70)
        print("[Ep{}] Company: monitor={:.0%} budget={:.0%}".format(ep, mon, strategy.get("budget_pct", 0.12)))
        phished = 0; reports = 0
        sample_n = min(10, len(self.users))
        # 攻击事件按攻击阶段递进：早期广撒网，后期精准攻击
        event_pool = [
            {"type": "email", "label": "phishing_email"},
            {"type": "link", "label": "malicious_link"},
            {"type": "attachment", "label": "weaponized_doc"},
            {"type": "login", "label": "credential_harvest"},
        ]
        for u in self.users[:sample_n]:
            ev = event_pool[ep % len(event_pool)]
            # 复杂度随轮次递增（攻击者学习效应）
            sophistication = min(0.9, 0.35 + ep * 0.08)
            event = {"type": ev["type"], "label": ev["label"], "sophistication": sophistication}
            decision = u.decide_action(event)
            if decision.get("action") == "click": phished += 1
            elif decision.get("action") == "report": reports += 1
        print("[Ep{}] Users: {} phished {} reported (of {} sampled)".format(ep, phished, reports, sample_n))
        attack_results = []
        for red in self.red:
            recon = {"hosts": self.cfg["hosts"], "monitoring": mon}
            plan = red.plan_attack(recon, mon)
            attack_results.append({"red_id": red.id, "plan": plan})
            print("[Ep{}] Red-{}: {} MITRE:{} succ_prob:{:.2f}".format(
                ep, red.id, plan.get("vector","?"), plan.get("mitre_technique","?"),
                plan.get("estimated_success_prob", 0.5)))
        self.attacks.extend(attack_results)
        detections = 0
        for atk in attack_results:
            for blue in self.blue:
                detected, conf, detail = blue.triage_alert(atk.get("plan", {}))
                if detected:
                    detections += 1
                    if blue.tier >= 2:
                        blue.investigate_incident(atk)
                    break
        print("[Ep{}] Blue: {}/{} detected".format(ep, detections, len(attack_results)))
        for red in self.red:
            red.adapt_strategy({"detections": detections, "total": len(attack_results)})
        metrics = {"ep": ep, "attacks": len(attack_results), "detections": detections,
                    "phished": phished, "reported": reports, "cost": self.cost.summary()}
        self.metrics.append(metrics)
        return metrics

    def cost_summary(self):
        return self.cost.summary()


# ============================================================================
# Main Entry
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  D03 REAL SANDBOX - All 4 agents API-driven")
    print("  Company(Pro) + User(Flash) + Blue(Flash) + Red(Pro)")
    print("=" * 60)
    orch = RealOrchestrator({"users": 15, "hosts": 25, "blue_t1": 2, "blue_t2": 1, "blue_t3": 1, "red": 2})
    for ep in range(3):
        print()
        print("--- Episode {} ---".format(ep+1))
        m = orch.run_episode()
    print()
    print("=" * 60)
    cs = orch.cost_summary()
    print("API Cost Summary:")
    print("  Total calls: {}".format(cs["total_calls"]))
    print("  Total cost: ${:.6f}".format(cs["total_cost"]))
    print("  Total tokens: {}".format(cs["total_tokens"]))
    print("  Total latency: {:.1f}s".format(cs["total_latency_s"]))
    print("  By agent:")
    for ag, data in cs.get("by_agent", {}).items():
        print("    {}: {} calls {} tokens ${:.6f}".format(ag, data.get("c", 0), data.get("tok", 0), data.get("cost", 0)))
    print("=" * 60)