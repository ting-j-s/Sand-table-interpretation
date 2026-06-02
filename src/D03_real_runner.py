"""
D03 Real Runner — 真实API统一运行入口
======================================
串联所有D03真实API模块:
  1. real_llm.py — 多Provider LLM (DeepSeek/OpenAI/Anthropic)
  2. D03_real_api_config.py — API密钥管理与配置
  3. D03_real_llm_bridge.py — SOC/Red Team LLM桥接
  4. D03_real_threat_intel.py — 威胁情报 (VirusTotal/AbuseIPDB/Shodan/OTX)
  5. D03_real_agents.py — 真实多智能体 (红/蓝/绿/紫)
  6. D03_real_sandbox.py — 真实Docker沙箱
  7. D03_沙盘编排器_基础版.py — 主编排器

用法:
  # 模拟模式 (无需API密钥)
  python D03_real_runner.py --mode mock --rounds 10

  # 真实API模式 (需设置环境变量)
  set DEEPSEEK_API_KEY=sk-xxxx
  python D03_real_runner.py --mode real --rounds 20

  # 完整模式 (真实API + Docker沙箱)
  python D03_real_runner.py --mode full --rounds 30 --enable-sandbox
"""
import sys, os, json, time, argparse, logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

BASE_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR.parent))

from D03_scenario_spec import ScenarioSpec
from D03_scenario_loader import ScenarioLoader

logging.basicConfig(level=logging.INFO, format='[%(name)s] %(message)s')
logger = logging.getLogger("D03_Runner")


class D03RealRunner:
    """D03真实API统一运行器"""

    def __init__(self, mode: str = "mock", enable_sandbox: bool = False,
                 scenario_spec: Optional[ScenarioSpec] = None):
        self.mode = mode
        self.enable_sandbox = enable_sandbox
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.start_time = time.time()
        self.results: Dict = {}
        self.scenario_spec = scenario_spec

        # 组件引用
        self.cfg = None
        self.llm = None
        self.threat_intel = None
        self.real_agents = None
        self.real_sandbox = None

        sc_name = scenario_spec.scenario_id if scenario_spec else "default"
        logger.info(f"D03 Runner启动: mode={mode}, sandbox={enable_sandbox}, scenario={sc_name}, session={self.session_id}")

    def initialize(self):
        """按模式初始化所有组件"""
        print("\n" + "=" * 70)
        print("  D03 真实API运行器 — 初始化")
        print("=" * 70)

        # Step 1: API配置
        print("\n[1/5] 加载API配置...")
        from D03_real_api_config import RealAPIConfig, ENV_SETUP_GUIDE
        self.cfg = RealAPIConfig()

        if self.mode in ("real", "full"):
            available_llm = self.cfg.get_available_llm()
            if not available_llm:
                print(f"\n{ENV_SETUP_GUIDE}")
                print("\n[WARNING] 未检测到任何LLM API密钥，将使用模拟模式")
                self.mode = "mock"
            else:
                print(f"  LLM Provider: {available_llm}")
                print(f"  VirusTotal: {'可用' if self.cfg.virustotal_api.available else '未配置'}")
                print(f"  AbuseIPDB:  {'可用' if self.cfg.abuseipdb_api.available else '未配置'}")
                print(f"  Shodan:     {'可用' if self.cfg.shodan_api.available else '未配置'}")
                print(f"  AlienVault: {'可用' if self.cfg.alienvault_otx_api.available else '未配置'}")

        # Step 2: LLM桥接
        print("\n[2/5] 初始化LLM桥接...")
        from D03_real_llm_bridge import RealLLMBridge, SOCLLMBridge, RedLLMBridge
        self.llm = RealLLMBridge(self.cfg)
        self.soc_llm = SOCLLMBridge(self.cfg) if self.mode != "mock" else None
        self.red_llm = RedLLMBridge(self.cfg) if self.mode != "mock" else None
        print(f"  LLM状态: {self.llm.get_stats()}")

        # Step 3: 威胁情报
        print("\n[3/5] 初始化威胁情报...")
        if self.mode != "mock":
            from D03_real_threat_intel import ThreatIntelAggregator
            self.threat_intel = ThreatIntelAggregator(self.cfg)
            print(f"  已就绪: {self.threat_intel.get_stats()}")
        else:
            print("  跳过 (模拟模式)")

        # Step 4: 真实多智能体
        print("\n[4/5] 初始化多智能体框架...")
        if self.mode != "mock":
            from D03_real_agents import RealMultiAgentOrchestrator
            self.real_agents = RealMultiAgentOrchestrator(self.cfg)
            self.real_agents.setup_teams(red_count=4, blue_count=4)
            print(f"  队伍: 红{len(self.real_agents.red_team)} 蓝{len(self.real_agents.blue_team)} "
                  f"绿+紫")
        else:
            print("  跳过 (模拟模式)")

        # Step 5: Docker沙箱
        print("\n[5/5] 初始化真实沙箱...")
        if self.enable_sandbox and self.mode != "mock":
            from D03_real_sandbox import RealSandbox
            self.real_sandbox = RealSandbox(self.cfg)
            status = self.real_sandbox.get_status()
            print(f"  沙箱状态: {status}")
            if self.real_sandbox.enabled:
                self.real_sandbox.pull_image("alpine")
        else:
            print("  跳过 (未启用或模拟模式)")

        print("\n" + "=" * 70)
        print("  初始化完成")
        print("=" * 70)

    def run_scenario(self, scenario_name: str = "apt_campaign", rounds: int = 10) -> Dict:
        """运行指定场景"""
        sc = self.scenario_spec
        sc_name = sc.name if sc else scenario_name
        sc_id = sc.scenario_id if sc else scenario_name

        print(f"\n{'='*70}")
        print(f"  场景: {sc_name} ({sc.domain if sc else 'default'}) | 轮次: {rounds}")
        print(f"{'='*70}")

        scenario_results = {
            "scenario_id": sc_id,
            "scenario_name": sc_name,
            "domain": sc.domain if sc else "generic",
            "scenario": scenario_name,
            "rounds": rounds,
            "mode": self.mode,
            "session_id": self.session_id,
            "start_time": datetime.now().isoformat(),
            "scenario_spec": sc.to_target_profile() if sc else {},
            "scenario_metrics": sc.get_scenario_metrics() if sc else {},
        }

        # === 威胁情报侦察阶段 ===
        if self.threat_intel:
            print("\n[威胁情报] 执行预侦察...")
            # 优先使用场景 IOC，其次使用场景资产 IP，再次使用默认 IP
            if sc and sc.threat_intel_iocs:
                target_ips = list(sc.threat_intel_iocs)
            elif sc and sc.assets:
                target_ips = [a.ip for a in sc.assets if a.ip and "/" not in str(a.ip)][:4]
            else:
                target_ips = ["45.155.205.233", "194.26.29.114"]
            if not target_ips:
                target_ips = ["8.8.8.8"]
            recon_results = {}
            for ip in target_ips:
                try:
                    result = self.threat_intel.full_ip_intel(ip)
                    recon_results[ip] = result.get("threat_summary", {})
                    verdict = result.get("threat_summary", {}).get("verdict", "clean")
                    print(f"  {ip}: {verdict}")
                except Exception as e:
                    print(f"  {ip}: 查询失败 ({e})")
            scenario_results["threat_recon"] = recon_results

        # === 多智能体对抗阶段 ===
        if self.real_agents:
            print("\n[多智能体] 开始红蓝对抗...")
            if sc:
                target = sc.to_target_profile()
            else:
                target = {
                    "name": f"scenario_{scenario_name}",
                    "ip": "10.0.1.100",
                    "services": ["web", "ssh", "rdp", "dns", "sql"],
                    "defense_maturity": 0.3 + 0.1 * rounds / 10,
                }
            agent_rounds = []
            for r in range(1, min(rounds + 1, 11)):
                result = self.real_agents.run_round(r, target)
                agent_rounds.append(result)
                if r % 3 == 0:
                    print(f"  第{r}轮: 红队{result['red_successes']}成功/"
                          f"{result['red_detected']}被检测, "
                          f"蓝队{len(result['blue_detections'])}次检测")
            scenario_results["agent_rounds"] = agent_rounds
            scenario_results["agent_stats"] = self.real_agents.get_stats()

        # === 沙箱逃逸测试 ===
        if self.real_sandbox and self.enable_sandbox:
            print("\n[沙箱] 执行逃逸测试...")
            from D03_real_sandbox import SandboxEscapeTester
            tester = SandboxEscapeTester(self.real_sandbox)
            escape_results = tester.run_escape_tests("d03_escape_test")
            print(f"  逃逸率: {escape_results['escape_rate']:.1%} "
                  f"({escape_results['escaped_categories']}/{escape_results['total_categories']})")
            scenario_results["sandbox_tests"] = escape_results

        # === 传统编排器运行 ===
        print("\n[编排器] 运行沙盘...")
        from integration.D03_沙盘编排器_基础版 import SandboxOrchestrator
        org_size = sc.organization_size if sc else 50
        orch = SandboxOrchestrator(
            rounds=rounds, org_size=org_size,
            use_real_api=(self.mode != "mock"),
            scenario_spec=sc,
        )
        orch_path = orch.run_full_simulation()
        scenario_results["orchestrator_report"] = str(orch_path)
        scenario_results["orchestrator_history"] = orch.history

        scenario_results["end_time"] = datetime.now().isoformat()
        scenario_results["duration_s"] = round(time.time() - self.start_time, 1)

        self.results = scenario_results
        return scenario_results

    def save_report(self):
        """保存综合报告"""
        output_dir = BASE_DIR.parent / "integration" / "D03_results"
        output_dir.mkdir(parents=True, exist_ok=True)

        report_path = output_dir / f"d03_real_{self.session_id}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n综合报告已保存: {report_path}")

        # 生成摘要
        summary = self._generate_summary()
        summary_path = output_dir / f"d03_real_{self.session_id}_summary.txt"
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(summary)
        print(f"摘要已保存: {summary_path}")
        print(f"\n{summary}")

    def _generate_summary(self) -> str:
        """生成运行摘要"""
        duration = round(time.time() - self.start_time, 1)
        lines = [
            "=" * 60,
            "  D03 Real API 运行摘要",
            "=" * 60,
            f"  会话ID:    {self.session_id}",
            f"  模式:      {self.mode}",
            f"  耗时:      {duration}s",
            f"  沙箱:      {'启用' if self.enable_sandbox else '关闭'}",
            "",
            "--- API 统计 ---",
        ]
        if self.llm:
            stats = self.llm.get_stats()
            lines.append(f"  LLM调用:   {stats.get('calls', 0)} 次")
            lines.append(f"  LLM Token: {stats.get('total_tokens', 0)}")
            lines.append(f"  LLM Provider: {stats.get('provider', 'mock')}")
        if self.threat_intel:
            ti_stats = self.threat_intel.get_stats()
            lines.append(f"  威胁情报查询: {ti_stats.get('total', 0)} 次")
        if self.real_agents:
            agent_stats = self.real_agents.get_stats()
            rounds = agent_stats.get("rounds_completed", 0)
            lines.append(f"  智能体对抗: {rounds} 轮")
            red_successes = sum(a.get("successes", 0) for a in agent_stats.get("red_team", []))
            blue_detections = sum(a.get("detections", 0) for a in agent_stats.get("blue_team", []))
            lines.append(f"  红队成功:   {red_successes}")
            lines.append(f"  蓝队检测:   {blue_detections}")
        if self.real_sandbox:
            status = self.real_sandbox.get_status()
            lines.append(f"  沙箱容器:   {status.get('active_containers', 0)}")
            lines.append(f"  命令执行:   {status.get('total_executions', 0)}")

        lines.extend([
            "",
            "--- 环境变量配置提示 ---",
            "  当前已配置的API:",
        ])
        if self.cfg:
            for field_name in self.cfg.__dataclass_fields__:
                val = getattr(self.cfg, field_name)
                from D03_real_api_config import APICredential
                if isinstance(val, APICredential) and val.available:
                    lines.append(f"    [OK] {val.env_var}")
                elif isinstance(val, APICredential):
                    lines.append(f"    [--] {val.env_var}")
        lines.append("=" * 60)
        return "\n".join(lines)

    def cleanup(self):
        """清理资源"""
        if self.real_sandbox:
            self.real_sandbox.cleanup_all()
        logger.info("D03 Runner清理完成")


def main():
    parser = argparse.ArgumentParser(
        description="D03 Real Runner — 真实API驱动的通用安全场景沙盘演绎系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python D03_real_runner.py --list-scenarios
  python D03_real_runner.py --mode mock --rounds 2 --scenario enterprise_default
  python D03_real_runner.py --mode mock --rounds 2 --scenario campus_network
  python D03_real_runner.py --mode mock --rounds 2 --scenario hospital_medical_system
  python D03_real_runner.py --mode mock --rounds 2 --scenario industrial_control_system
  python D03_real_runner.py --mode mock --rounds 2 --scenario cloud_native_platform
  python D03_real_runner.py --mode mock --rounds 2 --scenario ecommerce_platform
  python D03_real_runner.py --mode mock --rounds 2 --scenario scenarios/custom.json
  python D03_real_runner.py --mode real --rounds 20 --scenario enterprise_default
  python D03_real_runner.py --mode full --rounds 30 --enable-sandbox --scenario cloud_native_platform

环境变量 (至少设置一个LLM API):
  DEEPSEEK_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY

威胁情报 (可选):
  VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY / SHODAN_API_KEY / ALIENVAULT_OTX_KEY
        """
    )
    parser.add_argument("--mode", choices=["mock", "real", "full"], default="mock",
                       help="运行模式: mock=模拟, real=真实API, full=完整(API+沙箱)")
    parser.add_argument("--rounds", type=int, default=2, help="对抗轮次 (默认2)")
    parser.add_argument("--scenario", default=None,
                       help="场景 ID (如 enterprise_default) 或 JSON 文件路径")
    parser.add_argument("--list-scenarios", action="store_true", help="列出所有可用场景")
    parser.add_argument("--enable-sandbox", action="store_true", help="启用Docker沙箱")
    parser.add_argument("--skip-sandbox-tests", action="store_true", help="跳过沙箱逃逸测试")

    args = parser.parse_args()

    if args.list_scenarios:
        print("\n可用安全场景:\n")
        for s in ScenarioLoader.list_scenarios():
            print(f"  [{s['domain']:12s}] {s['id']:35s} {s['name']}")
        print(f"\n用法: python {__file__} --mode mock --rounds 2 --scenario <场景ID>")
        return

    # 加载场景
    scenario_spec = None
    if args.scenario:
        try:
            scenario_spec = ScenarioLoader.load(args.scenario)
            print(f"\n加载场景: {scenario_spec.name} ({scenario_spec.domain})")
            print(f"  描述: {scenario_spec.description}")
            print(f"  资产: {len(scenario_spec.assets)} 个 | 角色: {len(scenario_spec.actors)} 个")
            print(f"  日志源: {scenario_spec.get_enabled_log_sources()}")
            print(f"  防御成熟度: {scenario_spec.defense_maturity}")
            if scenario_spec.strategy_hint:
                print(f"  策略提示: {scenario_spec.strategy_hint}")
        except FileNotFoundError as e:
            print(f"错误: {e}")
            return
        except Exception as e:
            logger.error(f"场景加载失败: {e}")
            return

    runner = D03RealRunner(
        mode=args.mode,
        enable_sandbox=args.enable_sandbox and not args.skip_sandbox_tests,
        scenario_spec=scenario_spec,
    )

    try:
        runner.initialize()
        runner.run_scenario(scenario_name=args.scenario or "default", rounds=args.rounds)
        runner.save_report()
    except KeyboardInterrupt:
        print("\n[中断] 用户取消运行")
    except Exception as e:
        logger.error(f"运行失败: {e}", exc_info=True)
    finally:
        runner.cleanup()


if __name__ == "__main__":
    main()
