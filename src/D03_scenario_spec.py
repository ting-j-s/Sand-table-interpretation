"""
D03 Scenario Specification — 通用安全场景数据模型

将原先偏企业安全沙盘的设计抽象为通用安全场景，
支持企业、高校、医院、工控、云原生、电商、IoT 等多类安全场景自定义。
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class ActorProfile:
    """场景参与者画像"""
    role_id: str
    name: str
    type: str                          # employee / student / doctor / operator / admin / attacker / defender
    description: str = ""
    security_awareness: float = 0.5    # 安全意识水平 0-1
    privilege_level: str = "normal"    # normal / elevated / admin


@dataclass
class AssetProfile:
    """场景资产画像"""
    asset_id: str
    name: str
    asset_type: str                    # server / database / endpoint / iot / medical_device / plc / container
    ip: Optional[str] = None
    services: List[str] = field(default_factory=list)
    criticality: float = 0.5           # 资产关键性 0-1
    data_sensitivity: float = 0.5      # 数据敏感性 0-1


@dataclass
class LogSourceProfile:
    """日志源配置"""
    name: str                          # auth / dns / firewall / ids / siem / medical_system / scada ...
    format: str = "json"               # json / syslog / csv
    volume_factor: float = 1.0         # 日志量系数
    enabled: bool = True


@dataclass
class EvaluationProfile:
    """评估指标配置"""
    metrics: List[str] = field(default_factory=list)
    business_impact_weight: float = 0.5
    detection_weight: float = 0.5
    continuity_weight: float = 0.5


@dataclass
class ScenarioSpec:
    """通用安全场景规格"""
    scenario_id: str
    name: str
    domain: str                        # enterprise / campus / hospital / ics / cloud / ecommerce
    description: str = ""
    organization_size: int = 50

    actors: List[ActorProfile] = field(default_factory=list)
    assets: List[AssetProfile] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    defense_layers: List[str] = field(default_factory=list)
    log_sources: List[LogSourceProfile] = field(default_factory=list)
    evaluation: EvaluationProfile = field(default_factory=EvaluationProfile)

    threat_intel_iocs: List[str] = field(default_factory=list)
    defense_maturity: float = 0.5
    user_security_awareness: float = 0.5
    business_criticality: float = 0.5

    # 场景化策略提示（供编排器 prompt 使用）
    strategy_hint: str = ""

    def to_target_profile(self) -> Dict[str, Any]:
        """转换为 target profile（兼容现有多智能体和编排器接口）"""
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "domain": self.domain,
            "description": self.description,
            "organization_size": self.organization_size,
            "assets": [{
                "asset_id": a.asset_id,
                "name": a.name,
                "asset_type": a.asset_type,
                "ip": a.ip,
                "services": a.services,
                "criticality": a.criticality,
                "data_sensitivity": a.data_sensitivity,
            } for a in self.assets],
            "services": self.services,
            "attack_tactics": self.attack_tactics,
            "defense_layers": self.defense_layers,
            "defense_maturity": self.defense_maturity,
            "user_security_awareness": self.user_security_awareness,
            "business_criticality": self.business_criticality,
            "strategy_hint": self.strategy_hint,
        }

    def get_scenario_metrics(self) -> Dict[str, Any]:
        """返回场景特定的评估指标键"""
        defaults = {
            "enterprise": ["data_leakage_risk", "business_downtime", "alert_response_time", "detection_rate"],
            "campus": ["compromised_accounts", "academic_system_risk", "lab_server_exposure", "campus_network_availability"],
            "hospital": ["medical_service_continuity", "patient_record_risk", "medical_device_availability", "emergency_response_delay"],
            "ics": ["abnormal_control_command_rate", "production_interruption_risk", "physical_impact_risk", "ot_it_segmentation_effectiveness"],
            "cloud": ["privilege_escalation_paths", "container_escape_risk", "api_abuse_rate", "object_storage_exposure"],
            "ecommerce": ["payment_fraud_risk", "order_anomaly_rate", "user_data_leakage_risk", "business_availability"],
        }
        if self.evaluation.metrics:
            return {m: 0.0 for m in self.evaluation.metrics}
        return {m: 0.0 for m in defaults.get(self.domain, defaults["enterprise"])}

    def get_enabled_log_sources(self) -> List[str]:
        """返回启用的日志源名称列表"""
        return [ls.name for ls in self.log_sources if ls.enabled]
