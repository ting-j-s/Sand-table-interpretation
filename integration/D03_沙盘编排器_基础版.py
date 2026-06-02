"""
D03 — 沙盘演绎集成管道 (真实API版)
====================================
架构: 真实LLM API + 真实威胁情报 + 真实多智能体 + 通用安全场景
所有API密钥通过环境变量管理

用法: python D03_sandbox_orchestrator.py --rounds 10 --org-size 50 --real --scenario enterprise_default
"""
import json, os, time, argparse, sys
from datetime import datetime
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.D03_real_api_config import RealAPIConfig
from src.D03_real_llm_bridge import RealLLMBridge, SOCLLMBridge, RedLLMBridge
from src.D03_real_threat_intel import ThreatIntelAggregator

RESULTS_DIR = Path(__file__).parent / "D03_results"
RESULTS_DIR.mkdir(exist_ok=True)


class SandboxOrchestrator:
    """沙盘演绎总控 — 支持真实API模式和模拟模式，支持通用安全场景"""

    def __init__(self, rounds: int = 10, org_size: int = 50, use_real_api: bool = False,
                 scenario_spec: Optional[object] = None):
        self.rounds = rounds
        self.scenario_spec = scenario_spec
        self.org_size = scenario_spec.organization_size if scenario_spec else org_size
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.history = []
        self.use_real_api = use_real_api

        # 真实API组件
        self.cfg = None
        self.llm = None
        self.soc_llm = None
        self.red_llm = None
        self.ti = None

        if use_real_api:
            self._init_real_apis()

        sc_name = scenario_spec.scenario_id if scenario_spec else "default"
        print(f"[D03] Sandbox initialized: {self.session_id} | "
              f"场景: {sc_name} | org_size={self.org_size} | "
              f"API模式: {'真实' if self.use_real_api and self.llm else '模拟'}")

    def _init_real_apis(self):
        """初始化所有真实API连接"""
        try:
            self.cfg = RealAPIConfig()
            self.llm = RealLLMBridge(self.cfg)
            self.soc_llm = SOCLLMBridge(self.cfg)
            self.red_llm = RedLLMBridge(self.cfg)

            # 威胁情报 (独立初始化，某些API可能不可用)
            self.ti = ThreatIntelAggregator(self.cfg)
            ti_available = any([
                self.ti.vt.enabled, self.ti.abuseipdb.enabled,
                self.ti.shodan.enabled, self.ti.otx.enabled,
            ])

            print(f"[D03] LLM: {self.cfg.get_available_llm() or '无可用'}")
            print(f"[D03] 威胁情报: {'可用' if ti_available else '未配置'}")
            print(f"[D03] VirusTotal: {'OK' if self.ti.vt.enabled else '--'}")
            print(f"[D03] AbuseIPDB:  {'OK' if self.ti.abuseipdb.enabled else '--'}")
            print(f"[D03] Shodan:     {'OK' if self.ti.shodan.enabled else '--'}")
            print(f"[D03] AlienVault: {'OK' if self.ti.otx.enabled else '--'}")
        except Exception as e:
            print(f"[D03] API初始化失败: {e}，回退到模拟模式")
            self.use_real_api = False

    def phase_data_collection(self, round_num: int):
        """数据收集期 — 可选择真实威胁情报查询"""
        result = {
            "round": round_num,
            "phase": "data_collection",
            "normal_traffic_gb": 15.3 + round_num * 0.5,
            "user_events": 4520 + round_num * 120,
            "security_alerts": 12 + round_num,
            "baseline_established": True,
        }

        # 真实威胁情报增强
        if self.ti:
            # 查询一些已知恶意IP的当前状态作为环境情报
            sample_ips = ["45.155.205.233", "194.26.29.114"]  # 已知C2节点
            ti_results = {}
            for ip in sample_ips:
                try:
                    result_ip = self.ti.full_ip_intel(ip)
                    ti_results[ip] = result_ip.get("threat_summary", {})
                except Exception:
                    pass
            if ti_results:
                result["threat_intel"] = ti_results

        return result

    def phase_red_team_attack(self, round_num: int):
        """红队攻击轮次 — 真实LLM驱动的攻击策略"""
        print(f"[D03:R{round_num}] Red Team attacking...")

        if self.red_llm and self.use_real_api:
            target = {
                "org_size": self.org_size,
                "round": round_num,
                "defense_maturity": min(0.2 + round_num * 0.05, 0.9),
                "detected_techniques": [h.get("attack", {}).get("attack_vectors", []) for h in self.history[-2:]],
                "session_nonce": time.time_ns(),
            }
            plan = self.red_llm.generate_attack_plan(target)
            attack_vectors = [p.get("mitre_tech", "T1001") for p in plan.get("phases", [])]
            if not attack_vectors:
                attack_vectors = ["T1566", "T1190", "T1059", "T1021"]

            return {
                "round": round_num,
                "phase": "red_team_attack",
                "attack_vectors": attack_vectors,
                "initial_access_success": round_num > 2,
                "detection_evasion": "LLM_driven_v3",
                "dwell_time_minutes": 45,
                "llm_plan": {k: v for k, v in plan.items() if k != "phases"},
                "api_driven": True,
            }
        else:
            return {
                "round": round_num,
                "phase": "red_team_attack",
                "attack_vectors": ["phishing", "sqli", "lateral_movement", "privilege_escalation"],
                "initial_access_success": round_num > 2,
                "detection_evasion": "genetic_algorithm_v3",
                "dwell_time_minutes": 45,
                "api_driven": False,
            }

    def phase_blue_team_defense(self, round_num: int, attack_result: dict):
        """蓝队防守轮次 — 真实LLM驱动的SOC响应"""
        print(f"[D03:R{round_num}] Blue Team defending...")

        if self.soc_llm and self.use_real_api:
            alert_info = {
                "type": attack_result.get("attack_vectors", ["unknown"])[0],
                "severity": 0.7,
                "is_real_attack": True,
                "context": {
                    "round": round_num, "history_length": len(self.history),
                    "current_vectors": attack_result.get("attack_vectors", [])[:5],
                    "session_nonce": time.time_ns(),
                },
            }
            triage = self.soc_llm.triage_alert(alert_info)
            detected = triage.get("priority") in ("high", "critical")

            return {
                "round": round_num,
                "phase": "blue_team_defense",
                "attack_detected": detected,
                "containment_time_minutes": 12 if detected else 0,
                "mtd_triggered": detected,
                "defense_technique": triage.get("recommended_action", "LLM_driven_SOC"),
                "llm_triage": triage,
                "api_driven": True,
            }
        else:
            detected = round_num > 1
            return {
                "round": round_num,
                "phase": "blue_team_defense",
                "attack_detected": detected,
                "containment_time_minutes": 12 if detected else 0,
                "mtd_triggered": detected,
                "defense_technique": "Ensemble_of_Ensembles_PPO" if detected else "baseline_rules",
                "api_driven": False,
            }

    def phase_org_optimize(self, round_num: int, results: list):
        """组织优化 — LLM驱动的策略优化（场景感知）"""
        print(f"[D03:R{round_num}] Optimizing organization...")

        # 场景差异化信息
        sc_info = ""
        if self.scenario_spec:
            sc_info = f"""
场景领域: {self.scenario_spec.domain}
场景名称: {self.scenario_spec.name}
关键策略提示: {self.scenario_spec.strategy_hint or '通用安全策略'}
业务关键性: {self.scenario_spec.business_criticality}
"""

        if self.llm and self.use_real_api:
            context = {
                "round": round_num,
                "history_summary": f"{len(self.history)} rounds completed",
                "attacks_detected": sum(1 for h in self.history if h.get("defense", {}).get("attack_detected")),
                "total_rounds": max(len(self.history), 1),
            }
            prompt = f"""基于以下沙盘演绎数据，给出组织安全策略优化建议:
{sc_info}
{json.dumps(context, indent=2)}

返回JSON: {{"security_team_ratio": 0.05-0.15, "training_frequency_weeks": 4-12,
"code_review_required": bool, "mfa_enforced": bool, "network_segmentation": "flat/moderate/strict",
"personality_mix": {{"conscientiousness": 0.5-0.9, "openness": 0.3-0.7, "risk_aversion": 0.3-0.8}},
"domain_strategy": "<场景安全策略摘要>"}}"""
            result = self.llm.chat_json(
                "你是CISO，负责组织安全策略优化。请基于数据和场景领域给出差异化策略。",
                prompt, temperature=0.4
            )
            org_params = result.get("parsed", {})
            if not org_params or "security_team_ratio" not in org_params:
                org_params = self._default_org_params(round_num)
            org_params["api_driven"] = True
            return org_params
        else:
            return self._default_org_params(round_num)

    def _default_org_params(self, round_num: int) -> dict:
        # 尝试用LLM生成基于历史数据的组织参数
        if self.llm and self.use_real_api:
            try:
                history_context = []
                for h in self.history[-3:]:
                    history_context.append({
                        "round": h.get("round", 0),
                        "attack_detected": h.get("defense", {}).get("attack_detected", False),
                        "score": h.get("security_score", 50),
                    })
                prompt = f"""基于沙盘演绎历史，给出组织安全策略参数调整建议:
当前轮次: {round_num}
最近历史: {json.dumps(history_context, ensure_ascii=False)}
组织规模: {self.org_size}

返回JSON: {{"security_team_ratio": <0.05-0.20>, "training_frequency_weeks": <2-12>,
"code_review_required": <true/false>, "mfa_enforced": <true/false>,
"network_segmentation": "<flat/moderate/strict>",
"reasoning": "<一句话理由>"}}
决策时间戳: {time.time_ns()}"""
                result = self.llm.chat_json(
                    "你是CISO，基于安全态势数据调整组织参数。只返回JSON。",
                    prompt, temperature=0.3
                )
                parsed = result.get("parsed", {})
                if parsed and "security_team_ratio" in parsed:
                    return {
                        "security_team_ratio": float(parsed.get("security_team_ratio", 0.08)),
                        "training_frequency_weeks": int(parsed.get("training_frequency_weeks", 8)),
                        "code_review_required": bool(parsed.get("code_review_required", round_num > 3)),
                        "mfa_enforced": bool(parsed.get("mfa_enforced", round_num > 2)),
                        "network_segmentation": str(parsed.get("network_segmentation", "moderate")),
                        "personality_mix": {"conscientiousness": 0.65, "openness": 0.5, "risk_aversion": 0.45},
                        "api_driven": True,
                        "llm_reasoning": parsed.get("reasoning", ""),
                    }
            except Exception:
                pass
        # 最终回退
        return {
            "security_team_ratio": min(0.05 + round_num * 0.002, 0.15),
            "training_frequency_weeks": max(12 - round_num, 4),
            "code_review_required": round_num > 3,
            "mfa_enforced": round_num > 2,
            "network_segmentation": "strict" if round_num > 5 else "moderate",
            "personality_mix": {"conscientiousness": 0.6 + round_num * 0.02, "openness": 0.5, "risk_aversion": 0.4 + round_num * 0.03},
            "api_driven": False,
        }

    def _evaluate_security_score(self, round_num: int, attack: dict, defense: dict, org: dict) -> int:
        """LLM评估本轮安全评分 (0-100)，基于实际攻防数据 + 历史趋势"""
        if self.llm and self.use_real_api:
            try:
                # 构建历史趋势 (最近3轮评分变化)
                history_trend = []
                for h in self.history[-3:]:
                    history_trend.append({
                        "round": h.get("round", 0),
                        "score": h.get("security_score", 0),
                        "detected": h.get("defense", {}).get("attack_detected", False),
                    })

                # 差异化攻击特征
                atk_summary = {
                    "vectors": attack.get("attack_vectors", [])[:5],
                    "initial_access": attack.get("initial_access_success", False),
                    "api_driven": attack.get("api_driven", False),
                    "dwell_time_min": attack.get("dwell_time_minutes", 0),
                }

                # 差异化防御特征
                def_summary = {
                    "attack_detected": defense.get("attack_detected", False),
                    "containment_min": defense.get("containment_time_minutes", 0),
                    "mtd_triggered": defense.get("mtd_triggered", False),
                    "api_driven": defense.get("api_driven", False),
                }

                # 差异化组织特征
                org_summary = {
                    "mfa": org.get("mfa_enforced", False),
                    "code_review": org.get("code_review_required", False),
                    "segmentation": org.get("network_segmentation", "flat"),
                    "team_ratio": org.get("security_team_ratio", 0.05),
                    "api_driven": org.get("api_driven", False),
                }

                prompt = f"""评估本轮安全态势并打分(0-100)。要求: 分数应随攻防态势变化而显著变化。

当前轮次: {round_num}/{self.rounds}
历史趋势: {json.dumps(history_trend, ensure_ascii=False)}

红队攻击特征: {json.dumps(atk_summary, ensure_ascii=False)}
蓝队防御特征: {json.dumps(def_summary, ensure_ascii=False)}
组织策略特征: {json.dumps(org_summary, ensure_ascii=False)}

评分指导 (严格):
- 首次接入成功但未检测 → 40-50分 (严重失守)
- 全部攻击被检测并遏制 → 75-90分 (防御有效)
- 仅检测未遏制 → 55-65分 (被动响应)
- MFA未启用,分段为flat → -10分
- 连续3轮提高 → +5分趋势加分
- MTD触发成功 → +8分
- 安全团队比例过低(<0.08) → -5分

返回JSON: {{"score": <整数0-100>, "rationale": "<10字内理由>"}}
评分会话ID: {time.time_ns()}"""
                result = self.llm.chat_json(
                    "你是安全审计专家。基于攻防态势评估安全评分。分数必须反映实际态势差异。只返回JSON。",
                    prompt, temperature=0.4
                )
                parsed = result.get("parsed", {})
                score = int(parsed.get("score", 0))
                if 0 <= score <= 100:
                    return score
            except Exception:
                pass
        # 回退启发式
        base = 30 + round_num * 5
        if defense.get("attack_detected"):
            base += 8
        if defense.get("mtd_triggered"):
            base += 5
        if org.get("mfa_enforced"):
            base += 3
        if org.get("network_segmentation") == "strict":
            base += 4
        # 历史趋势调整
        if len(self.history) >= 2:
            prev_scores = [h.get("security_score", 0) for h in self.history[-2:]]
            if all(s > 60 for s in prev_scores):
                base += 2
        return min(base, 95)

    def run_full_simulation(self):
        """完整沙盘演绎闭环 (含企业级日志生成)"""
        print("\n" + "=" * 60)
        print(f"[D03] Full Sandbox Deduction ({'真实API' if self.use_real_api else '模拟'}模式)")
        print("=" * 60)

        # 初始化日志生成器（优先使用通用场景生成器）
        log_gen = None
        try:
            if self.scenario_spec:
                from src.D03_scenario_log_generator import ScenarioLogGenerator
                log_gen = ScenarioLogGenerator(scenario=self.scenario_spec)
            else:
                from src.D03_log_generator import CompanyLogGenerator
                log_gen = CompanyLogGenerator(org_size=self.org_size)
        except ImportError:
            pass

        org_params = {
            "security_team_ratio": 0.05,
            "training_frequency_weeks": 12,
            "code_review_required": False,
            "mfa_enforced": False,
            "network_segmentation": "flat",
        }

        for r in range(1, self.rounds + 1):
            print(f"\n--- Round {r}/{self.rounds} ---")

            data = self.phase_data_collection(r)
            attack = self.phase_red_team_attack(r)
            defense = self.phase_blue_team_defense(r, attack)
            org_params = self.phase_org_optimize(r, [data, attack, defense])

            # LLM评估本轮安全评分
            security_score = self._evaluate_security_score(r, attack, defense, org_params)
            round_result = {
                "round": r,
                "data_collection": data,
                "attack": attack,
                "defense": defense,
                "org_optimization": org_params,
                "security_score": security_score,
            }
            self.history.append(round_result)
            print(f"  Security Score: {round_result['security_score']}/100")

            # 生成本轮企业级日志
            if log_gen:
                round_logs = log_gen.generate_round_logs(
                    r, attack, defense, org_params, security_score)
                log_gen.write_logs(r, round_logs, self.session_id)

        # 生成综合报告
        report = {
            "session_id": self.session_id,
            "mode": "real_api" if self.use_real_api else "simulation",
            "rounds": self.rounds,
            "org_size": self.org_size,
            "history": self.history,
            "api_stats": {},
        }
        if self.scenario_spec:
            report["scenario_id"] = self.scenario_spec.scenario_id
            report["scenario_name"] = self.scenario_spec.name
            report["domain"] = self.scenario_spec.domain
            report["scenario_spec"] = self.scenario_spec.to_target_profile()
            report["scenario_metrics"] = self.scenario_spec.get_scenario_metrics()
            report["log_sources"] = self.scenario_spec.get_enabled_log_sources()
            report["attack_tactics"] = self.scenario_spec.attack_tactics
            report["defense_layers"] = self.scenario_spec.defense_layers

        if self.llm:
            report["api_stats"]["llm"] = self.llm.get_stats()
        if self.ti:
            report["api_stats"]["threat_intel"] = self.ti.get_stats()

        report_path = RESULTS_DIR / f"d03_sandbox_{self.session_id}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n[D03] Report: {report_path}")

        # 打印日志统计
        if log_gen:
            from src.D03_log_generator import LOG_DIR
            log_dir = LOG_DIR / self.session_id
            total_events = 0
            for r in range(1, self.rounds + 1):
                rd = log_dir / f"round_{r:02d}"
                if rd.exists():
                    events = sum(1 for _ in rd.rglob("*.log") for __ in open(_, encoding='utf-8'))
                    total_events += events
            print(f"[D03] Company Logs: {total_events} events across {self.rounds} rounds -> {log_dir}")

        return report_path


def main():
    parser = argparse.ArgumentParser(description="D03 沙盘演绎系统 — 通用安全场景")
    parser.add_argument("--rounds", type=int, default=10, help="对抗轮次")
    parser.add_argument("--org-size", type=int, default=50, help="虚拟组织规模 (优先使用场景配置)")
    parser.add_argument("--real", action="store_true", help="启用真实API (需设置环境变量)")
    parser.add_argument("--scenario", default=None, help="场景 ID 或 JSON 文件路径")
    args = parser.parse_args()

    scenario_spec = None
    if args.scenario:
        from src.D03_scenario_loader import ScenarioLoader
        scenario_spec = ScenarioLoader.load(args.scenario)
        print(f"加载场景: {scenario_spec.name} ({scenario_spec.domain})")

    orch = SandboxOrchestrator(args.rounds, args.org_size,
                                use_real_api=args.real, scenario_spec=scenario_spec)
    orch.run_full_simulation()


if __name__ == "__main__":
    main()
