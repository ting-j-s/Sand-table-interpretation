"""
D03 Real Multi-Agent Framework — 真实LLM驱动的多智能体框架
每个Agent由真实LLM驱动，拥有独立的系统提示词、工具集和记忆
包含: 红队攻击Agent / 蓝队防御Agent / 绿队业务Agent / 紫队审计Agent
"""
import json, time, os, random, logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from D03_real_api_config import RealAPIConfig
from D03_real_llm_bridge import RealLLMBridge, SOCLLMBridge, RedLLMBridge
from D03_real_threat_intel import ThreatIntelAggregator

logger = logging.getLogger("D03_RealAgents")


@dataclass
class AgentMemory:
    """Agent记忆系统 - 存储操作历史和上下文"""
    agent_id: str
    short_term: List[Dict] = field(default_factory=list)
    long_term: List[Dict] = field(default_factory=list)
    max_short: int = 50

    def remember(self, event: Dict):
        self.short_term.append({**event, "ts": time.time()})
        if len(self.short_term) > self.max_short:
            self.long_term.append(self.short_term.pop(0))

    def recent_context(self, n: int = 5) -> str:
        return json.dumps(self.short_term[-n:], indent=2, ensure_ascii=False)


class RealRedAgent:
    """真实红队攻击Agent - LLM驱动的攻击者"""

    RED_SYSTEM = """你是"D03-Red-{agent_id}"，一名由AI驱动的红队攻击Agent。
你的任务是在授权范围内执行渗透测试和攻击模拟。

操作原则:
1. 每一步操作前评估风险与收益
2. 根据目标防御状态动态调整策略
3. 记录所有操作和发现
4. 使用MITRE ATT&CK框架标注技术

每次行动，你需要从以下工具中选择并使用:
- recon(target): 对目标执行侦察，获取开放端口、服务信息
- exploit(vuln_type, target): 尝试利用漏洞获取访问权限
- persist(method): 建立持久化后门
- lateral(target): 横向移动到其他主机
- exfil(data_type): 数据外泄
- cleanup(): 清除痕迹

返回格式: {{"tool": "工具名", "params": {{}}, "reasoning": "操作理由", "mitre_tech": "Txxxx"}}"""

    def __init__(self, agent_id: str, llm: RealLLMBridge, threat_intel: Optional[ThreatIntelAggregator] = None):
        self.agent_id = agent_id
        self.llm = llm
        self.ti = threat_intel
        self.memory = AgentMemory(agent_id)
        self.tools = {
            "recon": self._tool_recon,
            "exploit": self._tool_exploit,
            "persist": self._tool_persist,
            "lateral": self._tool_lateral,
            "exfil": self._tool_exfil,
            "cleanup": self._tool_cleanup,
        }
        self.stats = {"ops": 0, "successes": 0, "detected": 0}
        logger.info(f"红队Agent {agent_id} 初始化完成")

    def act(self, target: Dict, defense_level: float = 0.5) -> Dict:
        """Agent执行一次攻击行动"""
        context = {
            "target": target,
            "defense_level": defense_level,
            "recent_memory": self.memory.recent_context(),
            "stats": self.stats,
        }
        prompt = f"""当前状态:
目标: {json.dumps(target, indent=2)}
防御强度: {defense_level} (0-1)
最近操作: {self.memory.recent_context()}
统计: {json.dumps(self.stats)}

请选择下一步行动。返回JSON格式。"""
        result = self.llm.chat_json(self.RED_SYSTEM.format(agent_id=self.agent_id), prompt, temperature=0.7)
        action = result.get("parsed", {})

        tool_name = action.get("tool", "recon")
        tool_fn = self.tools.get(tool_name, self._tool_recon)
        tool_result = tool_fn(target, defense_level)

        outcome = {
            "agent_id": self.agent_id,
            "action": action,
            "result": tool_result,
            "success": tool_result.get("success", False),
            "detected": tool_result.get("detected", False),
            "timestamp": time.time(),
        }
        self.memory.remember(outcome)
        self.stats["ops"] += 1
        if outcome["success"]:
            self.stats["successes"] += 1
        if outcome["detected"]:
            self.stats["detected"] += 1
        return outcome

    def _tool_recon(self, target: Dict, defense: float) -> Dict:
        target_ip = target.get("ip", target.get("name", "unknown"))
        result = {"tool": "recon", "target": target_ip}
        if self.ti and self.ti.shodan.enabled:
            host_info = self.ti.shodan.host_info(target_ip)
            result.update({
                "open_ports": host_info.get("ports", []),
                "services": host_info.get("services", []),
                "vulns": host_info.get("vulns", []),
                "source": "Shodan",
            })
        else:
            recon_prompt = f"""目标: {target_ip}，防御水平: {defense}
基于典型的网络侦察模式，生成合理的目标扫描结果JSON:
{{"open_ports": [端口列表], "services": [服务列表], "possible_vulns": [可能的漏洞]}}"""
            llm_result = self.llm.chat_json("你是网络侦察专家", recon_prompt, temperature=0.5)
            parsed = llm_result.get("parsed", {})
            result.update({
                "open_ports": parsed.get("open_ports", [80, 443]),
                "services": parsed.get("services", []),
                "possible_vulns": parsed.get("possible_vulns", []),
                "source": "LLM",
            })
        # LLM评估侦察检测风险
        a = self._llm_assess_operation("recon", target, defense,
            {"ports": result.get("open_ports", [])})
        result["success"] = a["success"]
        result["detected"] = a["detected"]
        result["assessment"] = a
        return result

    def _llm_assess_operation(self, op_type: str, target: Dict, defense: float,
                              extra: Dict = None) -> Dict:
        """LLM评估操作成功概率和被检测风险 (替代random.random())"""
        if not self.llm or not self.llm.creds:
            # 无API时使用基于知识的基础启发式
            return self._heuristic_assess(op_type, defense, extra)

        context = {
            "operation": op_type,
            "target": target.get("ip", target.get("name", "unknown")),
            "defense_level": round(defense, 2),
            "target_services": target.get("services", []),
            "extra": extra or {},
        }
        prompt = f"""评估以下攻击操作的成功概率和被检测风险:

操作类型: {op_type}
目标: {json.dumps(context, ensure_ascii=False)[:400]}
防御水平: {defense} (0=无防御, 1=顶级防御)

返回JSON: {{"success_prob": <0.0-1.0>, "detection_prob": <0.0-1.0>,
"reasoning": "<一句话分析>", "mitre_technique": "<最相关的MITRE技术ID>"}}"""
        try:
            result = self.llm.chat_json(
                "你是红队攻击专家，评估攻击操作的成功率和被检测概率。只返回JSON。",
                prompt, temperature=0.3
            )
            parsed = result.get("parsed", {})
            if parsed and "success_prob" in parsed:
                return {
                    "success": float(parsed.get("success_prob", 0.5)) > 0.35,
                    "detected": float(parsed.get("detection_prob", 0.5)) > 0.5,
                    "success_prob": float(parsed.get("success_prob", 0.5)),
                    "detection_prob": float(parsed.get("detection_prob", 0.5)),
                    "reasoning": parsed.get("reasoning", ""),
                    "mitre": parsed.get("mitre_technique", ""),
                }
        except Exception:
            pass
        return self._heuristic_assess(op_type, defense, extra)

    def _heuristic_assess(self, op_type: str, defense: float, extra: Dict = None) -> Dict:
        """最小启发式评估 (API不可用时的回退)"""
        base_rates = {
            "exploit": (0.55, 0.50), "persist": (0.65, 0.35),
            "lateral": (0.45, 0.45), "exfil": (0.55, 0.60),
            "recon": (0.90, 0.25), "cleanup": (0.85, 0.15),
        }
        succ_base, det_base = base_rates.get(op_type, (0.5, 0.5))
        stealth = (extra or {}).get("stealth", 0.5)
        return {
            "success": succ_base * (1 - defense * 0.5) > 0.35,
            "detected": det_base * defense / max(stealth, 0.1) > 0.5,
            "success_prob": round(succ_base * (1 - defense * 0.5), 2),
            "detection_prob": round(det_base * defense / max(stealth, 0.1), 2),
            "reasoning": "heuristic",
            "mitre": "",
        }

    def _tool_exploit(self, target: Dict, defense: float) -> Dict:
        vuln = target.get("vulnerability", "CVE-2023-XXXX")
        a = self._llm_assess_operation("exploit", target, defense, {"vulnerability": vuln})
        return {"tool": "exploit", "vulnerability": vuln, "success": a["success"],
                "detected": a["detected"], "assessment": a}

    def _tool_persist(self, target: Dict, defense: float) -> Dict:
        a = self._llm_assess_operation("persist", target, defense, {"method": "scheduled_task"})
        return {"tool": "persist", "method": "scheduled_task", "success": a["success"],
                "detected": a["detected"], "assessment": a}

    def _tool_lateral(self, target: Dict, defense: float) -> Dict:
        a = self._llm_assess_operation("lateral", target, defense,
            {"subnet": target.get("subnet", "10.0.2.0/24")})
        return {"tool": "lateral", "destination": target.get("subnet", "10.0.2.0/24"),
                "success": a["success"], "detected": a["detected"], "assessment": a}

    def _tool_exfil(self, target: Dict, defense: float) -> Dict:
        a = self._llm_assess_operation("exfil", target, defense, {"method": "dns_tunnel"})
        gb = round(a.get("success_prob", 0.5) * 5.0, 2) if a["success"] else 0
        return {"tool": "exfil", "method": "dns_tunnel", "data_gb": gb,
                "success": a["success"], "detected": a["detected"], "assessment": a}

    def _tool_cleanup(self, target: Dict, defense: float) -> Dict:
        a = self._llm_assess_operation("cleanup", target, defense)
        return {"tool": "cleanup", "success": a["success"], "detected": a["detected"], "assessment": a}


class RealBlueAgent:
    """真实蓝队防御Agent - LLM驱动的防御者"""

    BLUE_SYSTEM = """你是"D03-Blue-{agent_id}"，一名由AI驱动的蓝队防御Agent。
你的任务是检测、响应和遏制安全威胁。

防御层级: {defense_layer}
当前强度: {strength}

操作原则:
1. 持续监控网络流量和系统日志
2. 对异常行为进行快速分诊和响应
3. 协调多层级防御体系
4. 使用MITRE D3FEND框架标注防御措施

可用工具:
- scan_logs(source): 扫描指定日志源
- analyze_alert(alert_data): 分析安全告警
- block_ioc(ioc_data): 封禁威胁指标
- isolate_host(host_id): 隔离受感染主机
- hunt_threat(hypothesis): 主动威胁狩猎

返回JSON格式响应。"""

    def __init__(self, agent_id: str, defense_layer: str, strength: float,
                 llm: RealLLMBridge, ti: Optional[ThreatIntelAggregator] = None):
        self.agent_id = agent_id
        self.defense_layer = defense_layer
        self.strength = strength
        self.llm = llm
        self.ti = ti
        self.memory = AgentMemory(agent_id)
        self.detections = []
        self.alerts = 0
        self.false_positives = 0
        logger.info(f"蓝队Agent {agent_id} ({defense_layer}, 强度{strength:.2f}) 初始化完成")

    def detect(self, operation: Dict) -> Dict:
        """检测红队操作 — 基于威胁情报和LLM评估"""
        # 使用真实威胁情报验证IOC
        ioc_check = {}
        op_target = operation.get("result", {}).get("target", "")
        if self.ti and op_target:
            if self._is_ip(op_target):
                ioc_check = self.ti.quick_domain_check(op_target) if "." in op_target else {}

        # 基础检测概率：防御强度 × (1 - 攻击隐匿度)
        stealth = operation.get("result", {}).get("assessment", {}).get("detection_prob",
                   operation.get("result", {}).get("stealth", 0.3))
        detection_prob = self.strength * (1 - stealth * 0.7)
        if ioc_check.get("verdict") == "malicious":
            detection_prob += 0.3

        # LLM辅助检测决策
        if self.llm and self.llm.creds:
            try:
                prompt = f"""评估蓝队能否检测到以下红队操作:

防御层: {self.defense_layer}
防御强度: {self.strength:.2f}
威胁情报命中: {ioc_check.get('verdict', 'none')}
基础检测概率: {detection_prob:.2f}
操作类型: {operation.get('action', {}).get('tool', 'unknown')}
操作详情: {json.dumps(operation, ensure_ascii=False)[:300]}

返回JSON: {{"detected": true/false, "confidence": <0.0-1.0>}}"""
                result = self.llm.chat_json(
                    "你是蓝队SOC分析师，判断能否检测到红队攻击操作。只返回JSON。",
                    prompt, temperature=0.2
                )
                parsed = result.get("parsed", {})
                if parsed and "detected" in parsed:
                    detected = bool(parsed["detected"])
                    detection_prob = float(parsed.get("confidence", detection_prob))
            except Exception:
                detected = detection_prob > 0.45
        else:
            detected = detection_prob > 0.45

        detection = {
            "timestamp": time.time(),
            "defender_id": self.agent_id,
            "defense_layer": self.defense_layer,
            "operation_detected": operation,
            "detected": detected,
            "threat_intel_hit": bool(ioc_check.get("verdict") == "malicious"),
            "strength_applied": self.strength,
        }
        if detected:
            self.detections.append(detection)
            self.alerts += 1
            if not operation.get("success"):
                self.false_positives += 1

        self.memory.remember(detection)
        return detection

    def respond(self, alert: Dict) -> Dict:
        """对告警生成响应措施"""
        prompt = f"""检测到安全事件:
防御层: {self.defense_layer}
告警详情: {json.dumps(alert, indent=2)}
已检测操作: {len(self.detections)}个

请生成防御响应方案，返回JSON:
{{"action": "block/isolate/monitor/escalate", "iocs_to_block": [], "hosts_to_isolate": [],
  "mitre_d3fend": "D3-xxxx", "confidence": 0.0-1.0}}"""
        result = self.llm.chat_json(self.BLUE_SYSTEM.format(
            agent_id=self.agent_id, defense_layer=self.defense_layer, strength=self.strength
        ), prompt, temperature=0.3)
        return result.get("parsed", {"action": "monitor"})

    def _is_ip(self, s: str) -> bool:
        parts = s.split(".")
        return len(parts) == 4 and all(p.isdigit() for p in parts)

    def get_stats(self) -> Dict:
        return {
            "agent_id": self.agent_id, "defense_layer": self.defense_layer,
            "strength": self.strength, "detections": len(self.detections),
            "alerts": self.alerts, "false_positives": self.false_positives,
            "fpr": self.false_positives / max(self.alerts, 1),
        }


class RealGreenAgent:
    """真实绿队业务连续性Agent"""

    GREEN_SYSTEM = """你是"D03-Green-{agent_id}"，业务连续性保障Agent。
在红蓝对抗中确保核心业务不受影响。

职责:
1. 监控业务SLA指标
2. 在攻击发生时执行业务连续性计划(BCP)
3. 评估安全措施对业务的影响
4. 平衡安全与可用性

返回JSON格式的业务状态报告。"""

    def __init__(self, agent_id: str, llm: RealLLMBridge, critical_services: List[str] = None):
        self.agent_id = agent_id
        self.llm = llm
        self.critical_services = critical_services or ["auth", "db", "web", "dns", "email"]
        self.memory = AgentMemory(agent_id)
        self.service_status = {s: {"available": True, "latency_ms": 0} for s in self.critical_services}
        logger.info(f"绿队Agent {agent_id} 初始化完成 (服务: {self.critical_services})")

    def assess_impact(self, attack: Dict, defense: Dict) -> Dict:
        """评估攻防对业务的影响"""
        prompt = f"""当前攻防状态:
攻击操作: {json.dumps(attack, indent=2)}
防御响应: {json.dumps(defense, indent=2)}
服务状态: {json.dumps(self.service_status, indent=2)}

评估业务影响，返回JSON:
{{"affected_services": [], "sla_breach": bool, "recovery_actions": [],
  "estimated_downtime_min": int, "business_impact": "low/medium/high/critical"}}"""
        result = self.llm.chat_json(self.GREEN_SYSTEM.format(agent_id=self.agent_id), prompt, temperature=0.3)
        return result.get("parsed", {"business_impact": "low"})

    def get_bcp_status(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "services": self.service_status,
            "overall_availability": sum(1 for s in self.service_status.values() if s["available"]) / len(self.service_status),
        }


class RealPurpleAgent:
    """真实紫队审计Agent - 红蓝对抗效果审计"""

    PURPLE_SYSTEM = """你是"D03-Purple"，紫队审计Agent。你的任务是评估红蓝对抗的整体效果，
识别检测盲区，并给出改进建议。

分析维度:
1. 攻击检测覆盖率
2. 响应时间有效性
3. MITRE ATT&CK覆盖度
4. 防御层间协调性

返回JSON格式的审计报告。"""

    def __init__(self, llm: RealLLMBridge):
        self.llm = llm
        logger.info("紫队审计Agent初始化完成")

    def audit_round(self, red_ops: List[Dict], blue_detections: List[Dict],
                    green_status: Dict) -> Dict:
        """审计一轮对抗"""
        prompt = f"""请审计本轮红蓝对抗:

红队操作 ({len(red_ops)}个):
{json.dumps(red_ops[-5:], indent=2)}

蓝队检测 ({len(blue_detections)}个):
{json.dumps(blue_detections[-5:], indent=2)}

绿队业务状态:
{json.dumps(green_status, indent=2)}

返回审计报告JSON:
{{"detection_gaps": [], "response_time_issues": [], "recommendations": [],
  "overall_score": 0-100, "purple_team_findings": []}}"""
        result = self.llm.chat_json(self.PURPLE_SYSTEM, prompt, temperature=0.4)
        return result.get("parsed", {"overall_score": 50, "recommendations": []})


class RealMultiAgentOrchestrator:
    """真实多智能体编排器 - 协调红/蓝/绿/紫四队"""

    def __init__(self, config: Optional[RealAPIConfig] = None):
        self.cfg = config or RealAPIConfig()
        self.llm = RealLLMBridge(self.cfg)
        self.ti = ThreatIntelAggregator(self.cfg) if any([
            self.cfg.virustotal_api.available,
            self.cfg.abuseipdb_api.available,
            self.cfg.shodan_api.available,
        ]) else None
        self.soc_llm = SOCLLMBridge(self.cfg)
        self.red_llm = RedLLMBridge(self.cfg)

        self.red_team: List[RealRedAgent] = []
        self.blue_team: List[RealBlueAgent] = []
        self.green_agent: Optional[RealGreenAgent] = None
        self.purple_agent: Optional[RealPurpleAgent] = None
        self.round_history: List[Dict] = []
        logger.info("多智能体编排器初始化完成")

    def setup_teams(self, red_count: int = 4, blue_count: int = 4,
                    defense_layers: List[str] = None):
        """初始化红蓝绿紫四队"""
        defense_layers = defense_layers or ["network", "endpoint", "identity", "siem"]

        for i in range(red_count):
            agent = RealRedAgent(f"red_{i:03d}", self.red_llm, self.ti)
            self.red_team.append(agent)

        for i in range(blue_count):
            layer = defense_layers[i % len(defense_layers)]
            strength = 0.4 + 0.6 * random.random()
            agent = RealBlueAgent(f"blue_{i:03d}", layer, strength, self.soc_llm, self.ti)
            self.blue_team.append(agent)

        self.green_agent = RealGreenAgent("green_001", self.llm)
        self.purple_agent = RealPurpleAgent(self.llm)

        logger.info(f"队伍就绪: 红队{len(self.red_team)}人, 蓝队{len(self.blue_team)}人, "
                    f"绿队+紫队")

    def run_round(self, round_num: int, target: Dict) -> Dict:
        """运行一轮完整的红蓝对抗"""
        logger.info(f"--- 第{round_num}轮对抗开始 ---")

        # 红队攻击
        red_ops = []
        for agent in self.red_team:
            op = agent.act(target, defense_level=0.3 + 0.1 * round_num)
            red_ops.append(op)

        # 蓝队检测与响应
        blue_detections = []
        blue_responses = []
        for op in red_ops:
            for defender in self.blue_team:
                detection = defender.detect(op)
                if detection["detected"]:
                    blue_detections.append(detection)
                    response = defender.respond(detection)
                    blue_responses.append(response)

        # 绿队业务影响评估
        green_status = self.green_agent.assess_impact(red_ops[-1] if red_ops else {},
                                                       blue_responses[-1] if blue_responses else {})

        # 紫队审计
        if round_num % 3 == 0:
            audit = self.purple_agent.audit_round(red_ops, blue_detections, green_status)
        else:
            audit = {}

        round_result = {
            "round": round_num,
            "red_ops": red_ops,
            "red_successes": sum(1 for o in red_ops if o.get("success")),
            "red_detected": sum(1 for o in red_ops if o.get("detected")),
            "blue_detections": blue_detections,
            "blue_responses": blue_responses,
            "green_status": green_status,
            "purple_audit": audit,
            "timestamp": time.time(),
        }
        self.round_history.append(round_result)

        logger.info(f"第{round_num}轮: 红队{round_result['red_successes']}成功/"
                    f"{round_result['red_detected']}被检测, "
                    f"蓝队{len(blue_detections)}次检测")
        return round_result

    def get_stats(self) -> Dict:
        return {
            "red_team": [a.stats for a in self.red_team],
            "blue_team": [a.get_stats() for a in self.blue_team],
            "green_team": self.green_agent.get_bcp_status() if self.green_agent else {},
            "llm_stats": self.llm.get_stats(),
            "ti_stats": self.ti.get_stats() if self.ti else {},
            "rounds_completed": len(self.round_history),
        }


if __name__ == "__main__":
    print("=" * 60)
    print("D03 Real Multi-Agent Framework — 自检")
    print("=" * 60)
    config = RealAPIConfig()
    orch = RealMultiAgentOrchestrator(config)
    orch.setup_teams(red_count=2, blue_count=2)

    target = {"name": "test_target", "ip": "10.0.1.100", "services": ["web", "ssh", "rdp"]}
    for r in range(1, 4):
        result = orch.run_round(r, target)
        print(f"\n第{r}轮完成: "
              f"红队{result['red_successes']}/{len(result['red_ops'])}成功, "
              f"蓝队{len(result['blue_detections'])}次检测")

    print(f"\n最终统计:\n{json.dumps(orch.get_stats(), indent=2, ensure_ascii=False, default=str)[:800]}")
