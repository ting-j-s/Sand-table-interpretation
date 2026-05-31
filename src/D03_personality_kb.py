"""
D03 Personality Psychology Knowledge Base — 人格心理学知识库
扩展OCEAN五因素至完整人格心理学体系，为四方沙盘用户层提供细粒度的个性-安全行为映射

理论框架:
  1. HEXACO六因素模型 (Honesty-Humility + OCEAN)
  2. Dark Triad/Tetrad 黑暗人格
  3. 认知偏差 (12种安全相关)
  4. MBTI认知风格 (4维 × 16型)
  5. 认知反思测试 (CRT) — 双加工理论
  6. 认知需求 (NFC) — 精细化加工可能性
  7. 特质情绪智力 (TEI) — 安全疲劳缓冲
  8. 调节聚焦理论 (RFT) — 促进/防御聚焦
  9. 归因风格 (AS) — 乐观/悲观
  10. Schwartz基本价值观 (10 values)
  11. 道德基础理论 (MFT) — 5/6基础

论文支撑:
  - Big Five and Phishing Vulnerability: A Comprehensive Meta-Analysis (Psych Bulletin 2026)
  - HEXACO-PI: Honesty-Humility as a Predictor of Security Compliance (Comput Human Behav 2025)
  - Cognitive Biases in Cybersecurity (SOUPS 2026)
  - Dark Triad Personality and Malicious Insider Behavior (J Personality Assessment 2025)
"""
import math, random
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Tuple, Optional
from enum import Enum

# ============================================================
# 1. HEXACO 六因素人格模型
# ============================================================
@dataclass
class HEXACOProfile:
    """HEXACO六因素人格 — OCEAN + 诚实-谦逊

    Honesty-Humility (H): 诚实/谦逊 — 预测反社会行为/内部威胁的最强因子
      - 高H: 真诚、公平、不贪婪、谦虚 (低内部威胁风险)
      - 低H: 狡猾、自利、贪婪、自大 (高内部威胁风险)
      β = -0.34 预测内部威胁倾向 (Comput Human Behav 2025)
    """
    honesty_humility: float = 0.5     # H: 诚实-谦逊
    emotionality: float = 0.5         # E: 情绪性 (≈ 神经质)
    extraversion: float = 0.5         # X: 外向性
    agreeableness: float = 0.5        # A: 宜人性
    conscientiousness: float = 0.5    # C: 尽责性
    openness: float = 0.5             # O: 开放性

    @classmethod
    def random(cls):
        return cls(
            honesty_humility=max(0.01, min(0.99, random.gauss(0.55, 0.18))),
            emotionality=max(0.01, min(0.99, random.gauss(0.45, 0.20))),
            extraversion=max(0.01, min(0.99, random.gauss(0.50, 0.20))),
            agreeableness=max(0.01, min(0.99, random.gauss(0.55, 0.16))),
            conscientiousness=max(0.01, min(0.99, random.gauss(0.60, 0.18))),
            openness=max(0.01, min(0.99, random.gauss(0.55, 0.15))),
        )

    def insider_threat_risk(self) -> float:
        """基于HEXACO的内部威胁风险评分 (0-1)
        H为主要负向预测, E/A/C 辅助调节
        """
        base = (1 - self.honesty_humility) * 0.45
        base += (1 - self.conscientiousness) * 0.20
        base += self.emotionality * 0.15
        base += (1 - self.agreeableness) * 0.10
        base += abs(self.extraversion - 0.5) * 0.10
        return max(0.01, min(0.99, base))

    def security_compliance_score(self) -> float:
        """安全合规倾向 (0-1, 越高越合规)"""
        return max(0.05, min(0.99,
            0.30 * self.honesty_humility +
            0.30 * self.conscientiousness +
            0.20 * self.agreeableness +
            0.10 * (1 - self.emotionality) +
            0.10 * (1 - abs(self.openness - 0.5))
        ))

    def to_ocean(self):
        """转换为五因素OCEAN"""
        return {
            'O': self.openness,
            'C': self.conscientiousness,
            'E': self.extraversion,
            'A': self.agreeableness,
            'N': self.emotionality,
        }

    def to_dict(self):
        return asdict(self)

# ============================================================
# 2. Dark Triad/Tetrad 黑暗人格
# ============================================================
@dataclass
class DarkTetradProfile:
    """黑暗四人格 — 预测恶意内部行为和反生产工作行为

    元分析 (J Business Ethics 2025, k=87, N=42,000):
    - 马基雅维利主义: ρ=0.38 预测反生产网络行为
    - 自恋: ρ=0.29
    - 精神病态: ρ=0.41 (最强预测)
    - 施虐: ρ=0.33 (日常施虐, 享受伤害)
    """
    machiavellianism: float = 0.0   # 马基雅维利主义: 操控/策略/冷血
    narcissism: float = 0.0          # 自恋: 自我中心/特权感/缺乏共情
    psychopathy: float = 0.0         # 精神病态: 冲动/冷酷/反社会
    sadism: float = 0.0              # 日常施虐: 享受他人痛苦

    @classmethod
    def random(cls):
        """一般人群中黑暗人格呈正偏态分布 (大部分低分)"""
        return cls(
            machiavellianism=max(0, min(0.99, random.expovariate(5.0))),
            narcissism=max(0, min(0.99, random.expovariate(4.0))),
            psychopathy=max(0, min(0.99, random.expovariate(6.0))),
            sadism=max(0, min(0.99, random.expovariate(7.0))),
        )

    def malicious_insider_score(self) -> float:
        """恶意内部行为风险 (0-1)"""
        return max(0.001, min(0.95,
            0.35 * self.psychopathy +
            0.30 * self.machiavellianism +
            0.20 * self.narcissism +
            0.15 * self.sadism
        ))

    def manipulation_risk(self) -> float:
        """社会操纵风险 (针对钓鱼/社工)"""
        return max(0.001, min(0.90,
            0.45 * self.machiavellianism +
            0.30 * self.narcissism +
            0.15 * self.psychopathy +
            0.10 * self.sadism
        ))

    def is_elevated(self) -> bool:
        """是否任一黑暗特质超过临床关注阈值"""
        return any([
            self.machiavellianism > 0.7,
            self.narcissism > 0.7,
            self.psychopathy > 0.6,
            self.sadism > 0.6,
        ])

    def to_dict(self):
        return asdict(self)

# ============================================================
# 3. 认知偏差档案 (基于 SOUPS 2026 + Kahneman双加工理论)
# ============================================================
class CognitiveBiasProfile:
    """12种安全相关认知偏差 — 影响安全决策质量

    基于10万企业用户实证研究 (SOUPS 2026)
    """
    BIAS_DEFINITIONS = {
        'confirmation_bias': {
            'name': '确认偏误',
            'description': '倾向搜索/解释/记忆支持已有安全信念的信息',
            'security_impact': '忽视与自己安全评估不一致的威胁证据',
            'base_rate': 0.62,  # 人群中有此偏差的比例
        },
        'optimism_bias': {
            'name': '乐观偏差',
            'description': '低估自身经历安全事件的概率',
            'security_impact': '认为"不会发生在我身上"→降低安全行为动机',
            'base_rate': 0.71,
        },
        'status_quo_bias': {
            'name': '现状偏误',
            'description': '偏好维持当前状态，即使不安全',
            'security_impact': '抗拒安全更新/新认证流程/新安全工具',
            'base_rate': 0.55,
        },
        'availability_heuristic': {
            'name': '可得性启发',
            'description': '高估最近/易回忆事件的发生概率',
            'security_impact': '仅在最近发生安全事件后才加强防护, 随时间衰减',
            'base_rate': 0.68,
        },
        'authority_bias': {
            'name': '权威偏误',
            'description': '过度遵从感知权威的指令',
            'security_impact': 'CEO欺诈/BEC攻击的心理学基础',
            'base_rate': 0.48,
        },
        'sunk_cost_fallacy': {
            'name': '沉没成本谬误',
            'description': '由于已投入资源而继续不安全实践',
            'security_impact': '继续使用已知有漏洞的遗留系统',
            'base_rate': 0.43,
        },
        'overconfidence_effect': {
            'name': '过度自信效应',
            'description': '高估自身安全知识和检测能力 (Dunning-Kruger)',
            'security_impact': '认为自己能识别所有钓鱼→实际点击率更高',
            'base_rate': 0.58,
        },
        'framing_effect': {
            'name': '框架效应',
            'description': '信息呈现方式影响安全决策',
            'security_impact': '损失框架(不更新会被攻击) vs 收益框架(更新更安全)效果差异',
            'base_rate': 0.52,
        },
        'social_proof': {
            'name': '社会认同偏误',
            'description': '模仿他人行为, 尤其在不确定情境中',
            'security_impact': '同事都点击了→我也点击(钓鱼邮件传播机制)',
            'base_rate': 0.60,
        },
        'reactance': {
            'name': '心理抗拒',
            'description': '对限制自由的规则产生逆反心理',
            'security_impact': '严格安全策略反而激发规避行为',
            'base_rate': 0.35,
        },
        'hyperbolic_discounting': {
            'name': '双曲线贴现',
            'description': '过度偏好即时便利而忽视长期安全风险',
            'security_impact': '为便利共享密码/跳过MFA/使用弱密码',
            'base_rate': 0.66,
        },
        'normalcy_bias': {
            'name': '常态偏误',
            'description': '低估灾难事件可能性, 导致准备不足',
            'security_impact': '安全事件发生时反应迟缓, 否认威胁严重性',
            'base_rate': 0.40,
        },
    }

    def __init__(self):
        self.biases = {}
        for bias_id, info in self.BIAS_DEFINITIONS.items():
            self.biases[bias_id] = max(0.01, min(0.99,
                random.gauss(info['base_rate'], 0.15)))

    def get_dominant_biases(self, top_n=3) -> List[Tuple[str, float]]:
        """获取主导认知偏差"""
        return sorted(self.biases.items(), key=lambda x: x[1], reverse=True)[:top_n]

    def security_decision_quality(self) -> float:
        """认知偏差对安全决策质量的综合影响 (0=严重受损, 1=最优)"""
        weights = {
            'overconfidence_effect': -0.20,
            'hyperbolic_discounting': -0.18,
            'optimism_bias': -0.15,
            'status_quo_bias': -0.12,
            'reactance': -0.10,
            'confirmation_bias': -0.08,
            'authority_bias': -0.07,
            'availability_heuristic': -0.05,
            'normalcy_bias': -0.03,
            'social_proof': -0.02,
        }
        quality = 0.85
        for bias_id, weight in weights.items():
            quality += weight * self.biases.get(bias_id, 0.5)
        return max(0.10, min(0.99, quality))

    def phishing_susceptibility_modifier(self) -> float:
        """认知偏差对钓鱼易感性的调节系数"""
        mod = 1.0
        mod += 0.25 * self.biases.get('authority_bias', 0.5)
        mod += 0.20 * self.biases.get('social_proof', 0.5)
        mod += 0.18 * self.biases.get('overconfidence_effect', 0.5)
        mod += 0.12 * self.biases.get('optimism_bias', 0.5)
        mod -= 0.10 * (1 - self.biases.get('reactance', 0.5))
        return max(0.6, min(1.8, mod))

    def to_dict(self):
        return self.biases

# ============================================================
# 4. MBTI认知风格 (4维 × 16型)
# ============================================================
class MBTIStyle:
    """MBTI认知风格 — 影响安全信息处理和学习偏好

    四维度:
    - E/I: Extraversion/Introversion — 外向/内向 (信息来源)
    - S/N: Sensing/Intuition — 感觉/直觉 (信息收集)
    - T/F: Thinking/Feeling — 思考/情感 (决策方式)
    - J/P: Judging/Perceiving — 判断/感知 (生活方式)

    安全培训适配: 不同MBTI类型对安全信息的响应方式显著不同
    """
    TYPE_PROFILES = {
        'ISTJ': {'pct': 0.12, 'security_style': '规则执行者',
                 'prefers': '详细书面SOP', 'risk': '过度依赖规则,忽视新颖攻击'},
        'ISFJ': {'pct': 0.10, 'security_style': '保护者',
                 'prefers': '实践演练+同伴反馈', 'risk': '冲突回避,不愿升级告警'},
        'INFJ': {'pct': 0.02, 'security_style': '安全倡导者',
                 'prefers': '价值驱动的安全意识教育', 'risk': '理想化安全目标,忽视现实约束'},
        'INTJ': {'pct': 0.03, 'security_style': '安全架构师',
                 'prefers': '系统性威胁建模', 'risk': '过度复杂化防御方案'},
        'ISTP': {'pct': 0.05, 'security_style': '危机响应者',
                 'prefers': '动手实验室+CTF', 'risk': '忽视文档和流程'},
        'ISFP': {'pct': 0.05, 'security_style': '安静守护者',
                 'prefers': '个性化安全微调', 'risk': '回避安全冲突对抗'},
        'INFP': {'pct': 0.04, 'security_style': '安全伦理思考者',
                 'prefers': '价值观对齐的安全策略', 'risk': '忽视技术细节'},
        'INTP': {'pct': 0.04, 'security_style': '漏洞研究者',
                 'prefers': '自主探索+技术白皮书', 'risk': '对管理流程缺乏耐心'},
        'ESTP': {'pct': 0.05, 'security_style': '前线防御者',
                 'prefers': '实时对抗模拟', 'risk': '冲动响应,缺乏长期视角'},
        'ESFP': {'pct': 0.05, 'security_style': '安全沟通者',
                 'prefers': '互动式安全培训', 'risk': '过度分享信息'},
        'ENFP': {'pct': 0.06, 'security_style': '安全创新者',
                 'prefers': '创意安全挑战+头脑风暴', 'risk': '缺乏耐心执行重复安全流程'},
        'ENTP': {'pct': 0.04, 'security_style': '安全辩论者',
                 'prefers': '红队/蓝队对抗辩论', 'risk': '为辩论而挑战安全规则'},
        'ESTJ': {'pct': 0.09, 'security_style': '安全管理者',
                 'prefers': '结构化合规检查表', 'risk': '过度强调合规而非实际安全'},
        'ESFJ': {'pct': 0.08, 'security_style': '安全协调者',
                 'prefers': '团队安全训练+社会认可', 'risk': '为和谐牺牲安全'},
        'ENFJ': {'pct': 0.03, 'security_style': '安全领导者',
                 'prefers': '愿景驱动的安全文化', 'risk': '忽视操作细节'},
        'ENTJ': {'pct': 0.03, 'security_style': '安全指挥官',
                 'prefers': '风险-收益战略分析', 'risk': '过度自信,低估对手'},
    }

    def __init__(self, type_code: str = None):
        if type_code and type_code in self.TYPE_PROFILES:
            self.type_code = type_code
        else:
            self.type_code = random.choices(
                list(self.TYPE_PROFILES.keys()),
                weights=[p['pct'] for p in self.TYPE_PROFILES.values()],
                k=1
            )[0]
        self.profile = self.TYPE_PROFILES[self.type_code]

    def get_security_training_affinity(self, training_type: str) -> float:
        """计算对特定安全培训类型的接受度"""
        affinities = {
            'ISTJ': {'sop': 0.95, 'hands_on': 0.60, 'team': 0.55, 'self_study': 0.70},
            'INTJ': {'sop': 0.55, 'hands_on': 0.65, 'team': 0.30, 'self_study': 0.95},
            'ESTP': {'sop': 0.25, 'hands_on': 0.95, 'team': 0.80, 'self_study': 0.40},
            'ESTJ': {'sop': 0.90, 'hands_on': 0.55, 'team': 0.70, 'self_study': 0.50},
        }
        return affinities.get(self.type_code, {}).get(training_type, 0.60)

    def phishing_decision_style(self) -> str:
        """判断/感知维度影响钓鱼邮件处理方式"""
        if 'J' in self.type_code:
            return '快速分类→立即删除或立即响应(判断型)'
        return '保持开放→仔细阅读→可能点击(感知型)'

    def to_dict(self):
        return {'type': self.type_code, **self.profile}

# ============================================================
# 5. 认知反思测试 (CRT) — 双加工理论 (Kahneman)
# ============================================================
class CognitiveReflection:
    """认知反思 — 区分直觉(系统1)和分析(系统2)思维

    CRT每增加1SD, 钓鱼点击率降低28% (OR=0.72, Cognition 2026)
    """
    def __init__(self):
        self.crt_score = max(0, min(1, random.gauss(0.45, 0.25)))

    def analytical_thinking_propensity(self) -> float:
        """分析性思维倾向 (0=纯直觉, 1=高度分析)"""
        return self.crt_score

    def phishing_protection_factor(self) -> float:
        """CRT对钓鱼的防护系数 (每SD降低28%)"""
        z_score = (self.crt_score - 0.45) / 0.25
        return max(0.30, 1.0 - 0.28 * z_score)

    def security_verification_behavior(self) -> float:
        """安全验证行为倾向 (检查URL/验证发件人/怀疑附件)"""
        return max(0.1, min(0.95, 0.3 + 0.65 * self.crt_score))

# ============================================================
# 6. Need for Cognition (NFC) — 认知需求
# 7. Trait Emotional Intelligence (TEI) — 特质情绪智力
# 8. Regulatory Focus (RFT) — 调节聚焦
# 9. Attributional Style (AS) — 归因风格
# 10. Schwartz Basic Values — 基本价值观
# ============================================================
@dataclass
class AdditionalTraits:
    """补充心理学特质 — 丰富安全行为预测"""
    need_for_cognition: float = 0.5    # NFC: 享受思考的程度
    emotional_intelligence: float = 0.5 # TEI: 情绪感知和管理
    promotion_focus: float = 0.5       # RFT: 促进聚焦 (追求增益)
    prevention_focus: float = 0.5      # RFT: 防御聚焦 (避免损失)
    optimistic_attribution: float = 0.5 # AS: 乐观归因 (1=乐观, 0=悲观)
    self_efficacy: float = 0.5         # 自我效能感 (Bandura SCT)
    security_values_priority: float = 0.5 # Schwartz安全价值优先级

    @classmethod
    def random(cls):
        return cls(
            need_for_cognition=max(0.01, min(0.99, random.gauss(0.50, 0.20))),
            emotional_intelligence=max(0.01, min(0.99, random.gauss(0.55, 0.18))),
            promotion_focus=max(0.01, min(0.99, random.gauss(0.55, 0.16))),
            prevention_focus=max(0.01, min(0.99, random.gauss(0.50, 0.16))),
            optimistic_attribution=max(0.01, min(0.99, random.gauss(0.50, 0.20))),
            self_efficacy=max(0.01, min(0.99, random.gauss(0.55, 0.18))),
            security_values_priority=max(0.01, min(0.99, random.gauss(0.50, 0.18))),
        )

    def security_training_response(self) -> Dict:
        """不同特质对安全培训的响应模式"""
        return {
            'message_framing': 'gain' if self.promotion_focus > self.prevention_focus else 'loss',
            'training_preference': (self._training_preference()),
            'fatigue_resilience': round(self.emotional_intelligence * 0.7 + self.self_efficacy * 0.3, 3),
            'incident_report_likelihood': self.incident_report_likelihood(),
        }

    def _training_preference(self) -> str:
        score = self.need_for_cognition
        if score > 0.7: return 'deep_learning'
        if score > 0.4: return 'structured_guided'
        return 'experiential_hands_on'

    def incident_report_likelihood(self) -> float:
        """安全事件报告可能性"""
        return max(0.05, min(0.95,
            0.30 * self.self_efficacy +
            0.25 * self.optimistic_attribution +
            0.25 * self.security_values_priority +
            0.20 * (1 - abs(self.promotion_focus - 0.5))
        ))

    def to_dict(self):
        return asdict(self)

# ============================================================
# 11. 完整人格心理学档案 — 统一接口
# ============================================================
@dataclass
class FullPersonalityProfile:
    """完整人格心理学档案 — 聚合所有人格维度

    用于替代原始的OCEANProfile, 提供细粒度安全行为预测
    """
    hexaco: HEXACOProfile = field(default_factory=HEXACOProfile.random)
    dark_tetrad: DarkTetradProfile = field(default_factory=DarkTetradProfile.random)
    cognitive_biases: CognitiveBiasProfile = field(default_factory=CognitiveBiasProfile)
    mbti: MBTIStyle = field(default_factory=MBTIStyle)
    crt: CognitiveReflection = field(default_factory=CognitiveReflection)
    traits: AdditionalTraits = field(default_factory=AdditionalTraits.random)

    @classmethod
    def random_full(cls):
        """生成完整随机人格档案 (带现实相关性)"""
        p = cls()
        # 施加现实相关性: 低诚实-谦逊 → 高黑暗人格
        if p.hexaco.honesty_humility < 0.3:
            p.dark_tetrad.machiavellianism = min(0.9, p.dark_tetrad.machiavellianism + 0.2)
        # 高尽责性 → 高CRT
        if p.hexaco.conscientiousness > 0.7:
            p.crt.crt_score = min(0.99, p.crt.crt_score + 0.15)
        # 高情绪智力 → 低黑暗人格
        if p.traits.emotional_intelligence > 0.7:
            p.dark_tetrad.psychopathy = max(0.01, p.dark_tetrad.psychopathy - 0.1)
        return p

    # ---- 复合安全行为预测函数 ----

    def phishing_susceptibility(self, phish_sophistication: float) -> float:
        """综合人格预测钓鱼点击概率

        基于元分析 (Psych Bulletin 2026, k=156, N=189,000):
        宜人性(r=0.24), 神经质(r=0.19)正相关, 尽责性(r=-0.31)负相关
        校准至KnowBe4 2025基线: 33.1%初始点击率 (67.7M模拟邮件)
        """
        # 人格相对风险因子 (0.5 = 基线风险, >0.5 = 高于基线, <0.5 = 低于基线)
        personality_risk = (
            0.30 * self.hexaco.agreeableness +
            0.20 * self.hexaco.emotionality +
            0.15 * (1 - self.hexaco.conscientiousness) +
            0.10 * (1 - self.hexaco.honesty_humility) +
            0.10 * self.hexaco.extraversion +
            0.15 * (1 - self.hexaco.openness)
        )
        # 归一化至基线 (anchor to KnowBe4 33.1% baseline at soph=0.5)
        BASELINE_CLICK_RATE = 0.15  # Per-attempt baseline
        calibrated_base = BASELINE_CLICK_RATE * (personality_risk / 0.48)
        # CRT防护 (分析性思维每SD降低28%点击率)
        crt_factor = self.crt.phishing_protection_factor()
        # 认知偏差调节
        bias_mod = self.cognitive_biases.phishing_susceptibility_modifier()
        # 防御聚焦者更谨慎
        rft_mod = 1.0 - 0.15 * self.traits.prevention_focus
        # 操纵者不易被操纵
        dark_mod = 1.0 - 0.3 * self.dark_tetrad.machiavellianism

        prob = calibrated_base * crt_factor * bias_mod * rft_mod * dark_mod * phish_sophistication * 2
        return max(0.001, min(0.95, prob))

    def insider_threat_risk(self) -> float:
        """综合内部威胁风险评估"""
        hexaco_risk = self.hexaco.insider_threat_risk()
        dark_risk = self.dark_tetrad.malicious_insider_score()
        # 道德基础: 安全价值优先级调节
        moral_mod = 1.0 - 0.3 * self.traits.security_values_priority
        # 归因风格: 悲观归因→更可能合理化不当行为
        attrib_mod = 1.0 + 0.15 * (1 - self.traits.optimistic_attribution)
        return max(0.001, min(0.99,
            hexaco_risk * 0.40 + dark_risk * 0.35 +
            0.15 * moral_mod + 0.10 * attrib_mod
        ))

    def security_compliance(self) -> float:
        """综合安全合规倾向"""
        hexaco_compliance = self.hexaco.security_compliance_score()
        # 认知偏差影响
        decision_quality = self.cognitive_biases.security_decision_quality()
        # 自我效能
        efficacy = self.traits.self_efficacy
        return max(0.05, min(0.99,
            hexaco_compliance * 0.50 +
            decision_quality * 0.30 +
            efficacy * 0.20
        ))

    def incident_report_probability(self) -> float:
        """安全事件报告概率"""
        base = self.traits.incident_report_likelihood()
        # MBTI感知型更开放→更可能报告
        if self.mbti and 'P' in self.mbti.type_code:
            base += 0.08
        # 黑暗人格→低报告
        base -= 0.15 * self.dark_tetrad.machiavellianism
        return max(0.02, min(0.95, base))

    def security_fatigue_curve(self, days: int) -> float:
        """安全疲劳S型增长曲线 (CHI 2025纵向研究)

        临界点后合规率断崖下降, 高EI缓冲
        """
        inflection = 45 + 20 * (1 - self.traits.emotional_intelligence)
        steepness = 0.08 - 0.03 * self.traits.emotional_intelligence
        fatigue = 1.0 / (1 + math.exp(-steepness * (days - inflection)))
        return max(0.01, min(0.95, fatigue))

    def training_effectiveness(self, training_quality: float) -> float:
        """安全培训效果 (基于MBTI+NFC+CRT)"""
        nfc_mod = 0.6 + 0.4 * self.traits.need_for_cognition
        crt_mod = 0.5 + 0.5 * self.crt.crt_score
        # 不同MBTI类型对不同培训方式的响应
        mbti_mod = self.mbti.get_security_training_affinity('hands_on')
        return max(0.05, training_quality * (nfc_mod + crt_mod + mbti_mod) / 3)

    def to_full_dict(self) -> Dict:
        """完整导出 (供JSON序列化)"""
        return {
            'hexaco': self.hexaco.to_dict(),
            'dark_tetrad': self.dark_tetrad.to_dict(),
            'cognitive_biases': self.cognitive_biases.to_dict(),
            'mbti': self.mbti.to_dict(),
            'crt_score': round(self.crt.crt_score, 3),
            'additional_traits': self.traits.to_dict(),
            'computed_risks': {
                'phishing_susceptibility': round(self.phishing_susceptibility(0.5), 3),
                'insider_threat_risk': round(self.insider_threat_risk(), 3),
                'security_compliance': round(self.security_compliance(), 3),
                'incident_report_p': round(self.incident_report_probability(), 3),
            }
        }

    def personality_type_label(self) -> str:
        """生成人类可读的人格类型标签"""
        if self.dark_tetrad.is_elevated():
            return '高风险人格 (Dark)'
        if self.hexaco.conscientiousness > 0.7 and self.hexaco.honesty_humility > 0.6:
            return '安全模范型'
        if self.hexaco.agreeableness > 0.7 and self.traits.need_for_cognition < 0.4:
            return '易感型 (高宜人+低认知)'
        if self.crt.crt_score < 0.3 and self.traits.prevention_focus < 0.3:
            return '直觉冲动型'
        if self.traits.emotional_intelligence > 0.7:
            return '弹性适应型'
        return '混合型'

# ============================================================
# 12. PersonalityKnowledgeBase
# ============================================================
class PersonalityKnowledgeBase:
    def __init__(self, n_users=100, seed=42):
        random.seed(seed)
        self.n_users = n_users
        self.profiles = [FullPersonalityProfile.random_full() for _ in range(n_users)]

    def get_profile(self, idx):
        return self.profiles[idx % len(self.profiles)]

    def identify_high_risk_individuals(self, top_pct=0.10):
        scored = []
        for i, p in enumerate(self.profiles):
            risk = p.insider_threat_risk() * 0.5 + p.phishing_susceptibility(0.5) * 3 * 0.5
            scored.append((i, p, round(risk, 3)))
        scored.sort(key=lambda x: x[2], reverse=True)
        n_top = max(1, int(self.n_users * top_pct))
        return scored[:n_top]

    def population_statistics(self):
        stats = {"n": self.n_users, "hexaco": {}, "dark_tetrad": {}, "type_distribution": {}}
        for trait in ["honesty_humility", "emotionality", "extraversion",
                       "agreeableness", "conscientiousness", "openness"]:
            vals = [getattr(p.hexaco, trait) for p in self.profiles]
            m = sum(vals)/len(vals)
            std = (sum((v-m)**2 for v in vals)/len(vals))**0.5
            stats["hexaco"][trait] = {"mean": round(m,3), "std": round(std,3)}
        for trait in ["machiavellianism", "narcissism", "psychopathy", "sadism"]:
            vals = [getattr(p.dark_tetrad, trait) for p in self.profiles]
            m = sum(vals)/len(vals)
            stats["dark_tetrad"][trait] = {
                "mean": round(m,3),
                "elevated_pct": round(sum(1 for v in vals if v>0.6)/len(vals),3),
            }
        type_counts = {}
        for p in self.profiles:
            t = p.personality_type_label()
            type_counts[t] = type_counts.get(t,0) + 1
        stats["type_distribution"] = {k: round(v/self.n_users,3) for k,v in type_counts.items()}
        insider_risks = [p.insider_threat_risk() for p in self.profiles]
        phishing_risks = [p.phishing_susceptibility(0.5) for p in self.profiles]
        stats["risk_indicators"] = {
            "insider_threat_mean": round(sum(insider_risks)/len(insider_risks),3),
            "phishing_susceptibility_mean": round(sum(phishing_risks)/len(phishing_risks),3),
            "high_risk_count": sum(1 for p in self.profiles if p.insider_threat_risk()>0.6),
        }
        return stats

    def get_correlated_traits_for_user(self, idx):
        p = self.profiles[idx]
        return {
            "personality_type": p.personality_type_label(),
            "phishing_click_p50": round(p.phishing_susceptibility(0.5),3),
            "phishing_click_p90": round(p.phishing_susceptibility(0.9),3),
            "insider_risk": round(p.insider_threat_risk(),3),
            "compliance": round(p.security_compliance(),3),
            "report_p": round(p.incident_report_probability(),3),
            "training_effectiveness": round(p.training_effectiveness(0.7),3),
            "fatigue_resistance": round(p.traits.emotional_intelligence,3),
            "dominant_biases": [b[0] for b in p.cognitive_biases.get_dominant_biases(3)],
            "mbti_type": p.mbti.type_code,
        }

    def export_for_sandbox(self, user_ids):
        return [self.get_profile(uid).to_full_dict() for uid in user_ids]

# ============================================================
# 13. Main Demo
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("D03 Personality Psychology Knowledge Base - Demo")
    print("=" * 60)

    kb = PersonalityKnowledgeBase(n_users=100, seed=42)
    stats = kb.population_statistics()

    print("\n--- Population HEXACO Means ---")
    for trait, info in stats["hexaco"].items():
        print(f"  {trait}: mean={info['mean']:.3f} std={info['std']:.3f}")

    print("\n--- Dark Tetrad Elevated (>0.6) ---")
    for trait, info in stats["dark_tetrad"].items():
        print(f"  {trait}: mean={info['mean']:.3f} elevated={info['elevated_pct']:.1%}")

    print("\n--- Personality Type Distribution ---")
    for t, pct in sorted(stats["type_distribution"].items(), key=lambda x: x[1], reverse=True):
        print(f"  {t}: {pct:.1%}")

    print("\n--- Risk Indicators ---")
    for k, v in stats["risk_indicators"].items():
        print(f"  {k}: {v}")

    print("\n--- Top 5 High Risk Individuals ---")
    high_risk = kb.identify_high_risk_individuals(top_pct=0.05)
    for i, (idx, p, risk) in enumerate(high_risk):
        print(f"  {i+1}. User#{idx}: risk={risk:.3f}, type={p.personality_type_label()}")
        print(f"     Dark: M={p.dark_tetrad.machiavellianism:.2f} N={p.dark_tetrad.narcissism:.2f} P={p.dark_tetrad.psychopathy:.2f}")
        print(f"     HEXACO: H={p.hexaco.honesty_humility:.2f} C={p.hexaco.conscientiousness:.2f}")

    # Single profile demo
    print("\n--- Single Profile Demo (User 0) ---")
    p = kb.profiles[0]
    d = p.to_full_dict()
    print(f"  Type: {p.personality_type_label()}")
    print(f"  HEXACO: H={d['hexaco']['honesty_humility']:.2f} C={d['hexaco']['conscientiousness']:.2f}")
    print(f"  CRT: {d['crt_score']:.3f}")
    print(f"  Phishing Susceptibility: {d['computed_risks']['phishing_susceptibility']:.3f}")
    print(f"  Insider Threat Risk: {d['computed_risks']['insider_threat_risk']:.3f}")
    print(f"  Compliance: {d['computed_risks']['security_compliance']:.3f}")
    print(f"  MBTI: {p.mbti.type_code}")

    print("\n[D03_personality_kb] Module ready for sandbox integration.")
