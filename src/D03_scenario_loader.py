"""
D03 Scenario Loader — 通用安全场景加载器

支持从 scenarios/ 目录加载 JSON 场景配置，转换为 ScenarioSpec 对象。
可加载内置场景 ID 或外部 JSON 文件路径。
"""
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any

from D03_scenario_spec import (
    ScenarioSpec, ActorProfile, AssetProfile,
    LogSourceProfile, EvaluationProfile,
)

SCENARIOS_DIR = Path(__file__).parent.parent / "scenarios"


class ScenarioLoader:
    """场景加载器 — 从 scenarios/ 目录或外部 JSON 加载场景"""

    @staticmethod
    def list_scenarios() -> list:
        """列出所有可用场景"""
        scenarios = []
        if SCENARIOS_DIR.exists():
            for f in sorted(SCENARIOS_DIR.glob("*.json")):
                try:
                    with open(f, encoding="utf-8") as fh:
                        data = json.load(fh)
                    scenarios.append({
                        "id": data.get("scenario_id", f.stem),
                        "name": data.get("name", f.stem),
                        "domain": data.get("domain", "unknown"),
                        "description": data.get("description", "")[:80],
                        "path": str(f),
                    })
                except Exception:
                    scenarios.append({"id": f.stem, "name": f.stem, "domain": "unknown", "description": "", "path": str(f)})
        return scenarios

    @staticmethod
    def load(scenario_ref: str = None, defaults: Optional[Dict[str, Any]] = None) -> ScenarioSpec:
        """
        加载场景配置。

        Args:
            scenario_ref: 场景 ID (如 "enterprise_default") 或 JSON 文件路径
            defaults: 缺省字段补全字典

        Returns:
            ScenarioSpec 对象
        """
        if scenario_ref is None:
            return ScenarioLoader.load_default()

        data = None

        # 1. 检查是否为文件路径
        if scenario_ref.endswith(".json") and os.path.isfile(scenario_ref):
            with open(scenario_ref, encoding="utf-8") as f:
                data = json.load(f)
        elif scenario_ref.endswith(".json"):
            raise FileNotFoundError(
                f"场景文件不存在: {scenario_ref}\n"
                f"可用场景: {[s['id'] for s in ScenarioLoader.list_scenarios()]}"
            )

        # 2. 从 scenarios/ 目录加载
        if data is None:
            candidate = SCENARIOS_DIR / f"{scenario_ref}.json"
            if candidate.exists():
                with open(candidate, encoding="utf-8") as f:
                    data = json.load(f)
            else:
                available = [s["id"] for s in ScenarioLoader.list_scenarios()]
                raise FileNotFoundError(
                    f"未找到场景 '{scenario_ref}'。\n"
                    f"可用场景: {available}\n"
                    f"或传入 JSON 文件路径。"
                )

        # 3. 补全缺省字段
        if defaults:
            for k, v in defaults.items():
                if k not in data or data[k] is None:
                    data[k] = v

        # 4. 转换为 ScenarioSpec
        return ScenarioLoader._dict_to_spec(data)

    @staticmethod
    def load_default() -> ScenarioSpec:
        """加载默认场景 (enterprise_default)"""
        return ScenarioLoader.load("enterprise_default")

    @staticmethod
    def _dict_to_spec(data: Dict[str, Any]) -> ScenarioSpec:
        """将 JSON dict 转换为 ScenarioSpec 对象"""
        actors = [
            ActorProfile(
                role_id=a.get("role_id", f"actor_{i}"),
                name=a.get("name", ""),
                type=a.get("type", "user"),
                description=a.get("description", ""),
                security_awareness=float(a.get("security_awareness", 0.5)),
                privilege_level=a.get("privilege_level", "normal"),
            )
            for i, a in enumerate(data.get("actors", []))
        ]

        assets = [
            AssetProfile(
                asset_id=a.get("asset_id", f"asset_{i}"),
                name=a.get("name", ""),
                asset_type=a.get("asset_type", "server"),
                ip=a.get("ip"),
                services=a.get("services", []),
                criticality=float(a.get("criticality", 0.5)),
                data_sensitivity=float(a.get("data_sensitivity", 0.5)),
            )
            for i, a in enumerate(data.get("assets", []))
        ]

        log_sources = [
            LogSourceProfile(
                name=ls.get("name", f"log_{i}"),
                format=ls.get("format", "json"),
                volume_factor=float(ls.get("volume_factor", 1.0)),
                enabled=bool(ls.get("enabled", True)),
            )
            for i, ls in enumerate(data.get("log_sources", []))
        ]

        eval_data = data.get("evaluation", {})
        evaluation = EvaluationProfile(
            metrics=eval_data.get("metrics", []),
            business_impact_weight=float(eval_data.get("business_impact_weight", 0.5)),
            detection_weight=float(eval_data.get("detection_weight", 0.5)),
            continuity_weight=float(eval_data.get("continuity_weight", 0.5)),
        )

        return ScenarioSpec(
            scenario_id=data.get("scenario_id", ""),
            name=data.get("name", ""),
            domain=data.get("domain", "unknown"),
            description=data.get("description", ""),
            organization_size=int(data.get("organization_size", 50)),
            actors=actors,
            assets=assets,
            services=data.get("services", []),
            attack_tactics=data.get("attack_tactics", []),
            defense_layers=data.get("defense_layers", []),
            log_sources=log_sources,
            evaluation=evaluation,
            threat_intel_iocs=data.get("threat_intel_iocs", []),
            defense_maturity=float(data.get("defense_maturity", 0.5)),
            user_security_awareness=float(data.get("user_security_awareness", 0.5)),
            business_criticality=float(data.get("business_criticality", 0.5)),
            strategy_hint=data.get("strategy_hint", ""),
        )


if __name__ == "__main__":
    print("=" * 60)
    print("D03 Scenario Loader — 自检")
    print("=" * 60)

    print("\n可用场景:")
    for s in ScenarioLoader.list_scenarios():
        print(f"  [{s['domain']:12s}] {s['id']:35s} {s['name']}")

    print("\n加载 enterprise_default...")
    spec = ScenarioLoader.load("enterprise_default")
    print(f"  场景: {spec.name} ({spec.domain})")
    print(f"  资产: {len(spec.assets)} 个")
    print(f"  角色: {len(spec.actors)} 个")
    print(f"  日志源: {spec.get_enabled_log_sources()}")
    print(f"  指标: {list(spec.get_scenario_metrics().keys())}")
    print(f"  target_profile keys: {list(spec.to_target_profile().keys())}")
