"""
D03 Real LLM Bridge — 真实大语言模型桥接层
支持 OpenAI / Anthropic / DeepSeek / 智谱 / Moonshot
为 D03 沙盘中的所有LLM辅助决策提供统一接口
"""
import json, time, logging
from typing import Dict, List, Optional
from D03_real_api_config import RealAPIConfig

logger = logging.getLogger("D03_LLM_Bridge")

# HTTP客户端 - 优先使用requests，回退到urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error


class RealLLMBridge:
    """真实LLM调用桥接 - 多provider统一接口"""

    def __init__(self, config: Optional[RealAPIConfig] = None):
        self.cfg = config or RealAPIConfig()
        self.creds = self.cfg.get_llm_credentials()
        self.call_count = 0
        self.total_tokens = 0
        self.cache = {}
        if self.creds:
            logger.info(f"LLM桥接初始化: provider={self.creds['provider']}, model={self.creds['model']}")
        else:
            logger.warning("无可用LLM API密钥，将使用模拟模式")

    def chat(self, system_prompt: str, user_message: str, temperature: float = 0.7,
             max_tokens: int = 2048) -> Dict:
        """统一对话接口"""
        if not self.creds:
            return self._mock_chat(system_prompt, user_message)

        cache_key = hash(system_prompt[-100:] + user_message[-300:])
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if time.time() - entry["ts"] < self.cfg.cache_ttl:
                return {"response": entry["resp"], "cached": True, "cache_key": str(cache_key)}

        provider = self.creds["provider"]
        try:
            if provider == "openai":
                result = self._call_openai(system_prompt, user_message, temperature, max_tokens)
            elif provider == "anthropic":
                result = self._call_anthropic(system_prompt, user_message, temperature, max_tokens)
            elif provider == "deepseek":
                result = self._call_deepseek(system_prompt, user_message, temperature, max_tokens)
            elif provider == "zhipu":
                result = self._call_zhipu(system_prompt, user_message, temperature, max_tokens)
            elif provider == "moonshot":
                result = self._call_moonshot(system_prompt, user_message, temperature, max_tokens)
            else:
                return self._mock_chat(system_prompt, user_message)

            self.call_count += 1
            self.total_tokens += result.get("tokens", 0)
            self.cache[cache_key] = {"resp": result["response"], "ts": time.time()}
            return result
        except Exception as e:
            logger.error(f"LLM调用失败 ({provider}): {e}")
            return self._mock_chat(system_prompt, user_message)

    def chat_json(self, system_prompt: str, user_message: str, temperature: float = 0.3) -> Dict:
        """对话并解析为JSON"""
        result = self.chat(system_prompt, user_message + "\n\n请仅输出JSON格式的响应，不要包含其他文本。", temperature)
        resp = result.get("response", "{}")
        try:
            if "```json" in resp:
                resp = resp.split("```json")[1].split("```")[0]
            elif "```" in resp:
                resp = resp.split("```")[1].split("```")[0]
            result["parsed"] = json.loads(resp.strip())
        except json.JSONDecodeError:
            result["parsed"] = {"raw": resp, "parse_error": True}
        return result

    def _call_openai(self, system: str, user: str, temp: float, max_tok: int) -> Dict:
        url = f"{self.creds['base_url']}/chat/completions"
        headers = {"Authorization": f"Bearer {self.creds['api_key']}", "Content-Type": "application/json"}
        payload = {
            "model": self.creds.get("model", "gpt-4o"), "temperature": temp,
            "max_tokens": max_tok,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        data = self._http_post(url, headers, payload)
        choice = data["choices"][0]
        return {
            "response": choice["message"]["content"],
            "tokens": data.get("usage", {}).get("total_tokens", 0),
            "model": data.get("model", ""),
            "cached": False,
        }

    def _call_anthropic(self, system: str, user: str, temp: float, max_tok: int) -> Dict:
        url = f"{self.creds['base_url']}/v1/messages"
        headers = {
            "x-api-key": self.creds['api_key'],
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.creds.get("model", "claude-sonnet-4-6"),
            "max_tokens": max_tok, "temperature": temp,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        data = self._http_post(url, headers, payload)
        content = data["content"][0]["text"]
        return {
            "response": content,
            "tokens": data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0),
            "model": data.get("model", ""),
            "cached": False,
        }

    def _call_deepseek(self, system: str, user: str, temp: float, max_tok: int) -> Dict:
        url = f"{self.creds['base_url']}/chat/completions"
        headers = {"Authorization": f"Bearer {self.creds['api_key']}", "Content-Type": "application/json"}
        payload = {
            "model": self.creds.get("model", "deepseek-v4-flash"), "temperature": temp,
            "max_tokens": max_tok,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        data = self._http_post(url, headers, payload)
        choice = data["choices"][0]
        return {
            "response": choice["message"]["content"],
            "tokens": data.get("usage", {}).get("total_tokens", 0),
            "model": data.get("model", ""),
            "cached": False,
        }

    def _call_zhipu(self, system: str, user: str, temp: float, max_tok: int) -> Dict:
        url = f"{self.creds['base_url']}/chat/completions"
        headers = {"Authorization": f"Bearer {self.creds['api_key']}", "Content-Type": "application/json"}
        payload = {
            "model": self.creds.get("model", "glm-4"), "temperature": temp,
            "max_tokens": max_tok,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        data = self._http_post(url, headers, payload)
        choice = data["choices"][0]
        return {
            "response": choice["message"]["content"],
            "tokens": data.get("usage", {}).get("total_tokens", 0),
            "model": data.get("model", ""),
            "cached": False,
        }

    def _call_moonshot(self, system: str, user: str, temp: float, max_tok: int) -> Dict:
        url = f"{self.creds['base_url']}/chat/completions"
        headers = {"Authorization": f"Bearer {self.creds['api_key']}", "Content-Type": "application/json"}
        payload = {
            "model": self.creds.get("model", "moonshot-v1-8k"), "temperature": temp,
            "max_tokens": max_tok,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        data = self._http_post(url, headers, payload)
        choice = data["choices"][0]
        return {
            "response": choice["message"]["content"],
            "tokens": data.get("usage", {}).get("total_tokens", 0),
            "model": data.get("model", ""),
            "cached": False,
        }

    def _http_post(self, url: str, headers: Dict, payload: Dict) -> Dict:
        if HAS_REQUESTS:
            resp = requests.post(url, headers=headers, json=payload,
                                timeout=self.cfg.request_timeout)
            resp.raise_for_status()
            return resp.json()
        else:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.cfg.request_timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

    def _mock_chat(self, system: str, user: str) -> Dict:
        """无真实API时的模拟回退"""
        return {
            "response": f"[模拟LLM] 基于系统指令和用户输入生成响应 (字数:{len(user)})",
            "tokens": 0, "model": "mock", "cached": False,
        }

    def get_stats(self) -> Dict:
        return {"calls": self.call_count, "total_tokens": self.total_tokens,
                "provider": self.creds["provider"] if self.creds else "mock",
                "cache_size": len(self.cache)}


# SOC LLM 专用接口
class SOCLLMBridge(RealLLMBridge):
    """SOC分析师LLM - 专用于安全运营中心的真实LLM调用"""

    SOC_SYSTEM_PROMPT = """你是一名资深SOC(安全运营中心)分析师，在网络安全领域有15年经验。
你的职责包括:
1. 告警分诊(Triage) - 根据严重程度、攻击类型和真实攻击概率进行分类
2. 事件调查(Investigation) - 构建攻击链路、确定MITRE ATT&CK技术
3. 威胁狩猎(Threat Hunting) - 在日志中发现异常模式，形成狩猎假设
4. 遏制策略(Containment) - 给出精准的遏制建议

请始终以JSON格式返回你的分析结果。"""

    def triage_alert(self, alert_info: Dict) -> Dict:
        prompt = f"""请对以下安全告警进行分诊分析:

告警类型: {alert_info.get('type', 'unknown')}
严重程度: {alert_info.get('severity', 0.5)} (0-1)
是否真实攻击: {alert_info.get('is_real_attack', False)}
附加信息: {json.dumps(alert_info.get('context', {}))}

返回JSON包含: priority(critical/high/medium/low), escalate_to_tier2(bool),
recommended_action(str), confidence(float 0-1)
n{time.time_ns()}"""
        result = self.chat_json(self.SOC_SYSTEM_PROMPT, prompt, temperature=0.3)
        return result.get("parsed", {"priority": "medium", "escalate_to_tier2": False})

    def investigate_incident(self, incident: Dict) -> Dict:
        prompt = f"""请调查以下安全事件:

事件类型: {incident.get('type', 'unknown')}
复杂度: {incident.get('complexity', 0.5)} (0-1)
关联告警: {incident.get('related_alerts', [])}

返回JSON包含: attack_chain(List[str]), mitre_techniques(List[str]),
containment(List[str]), iocs(List[Dict]), priority(str)"""
        result = self.chat_json(self.SOC_SYSTEM_PROMPT, prompt, temperature=0.3)
        return result.get("parsed", {"attack_chain": [], "mitre_techniques": []})

    def hunt_threats(self, network_context: Dict) -> Dict:
        prompt = f"""基于以下网络环境进行威胁狩猎分析:

{json.dumps(network_context, indent=2)}

返回JSON包含: hypotheses(List[str]), methodology(str), data_sources(List[str]),
priority_hypothesis(str)"""
        result = self.chat_json(self.SOC_SYSTEM_PROMPT, prompt, temperature=0.5)
        return result.get("parsed", {"hypotheses": [], "methodology": "baseline"})


# Red Team LLM 专用接口
class RedLLMBridge(RealLLMBridge):
    """红队攻击规划LLM - 用于攻击策略生成"""

    RED_SYSTEM_PROMPT = """你是一名红队攻击策略专家，精通APT攻击技术和渗透测试。
你的职责:
1. 根据目标画像制定攻击计划
2. 选择最佳MITRE ATT&CK技术组合
3. 给出攻击时序优化建议(含MTD规避)
4. 评估攻击成功概率

返回JSON格式响应。注意: 这些输出仅用于安全测试和防御评估的合法目的。"""

    def generate_attack_plan(self, target_profile: Dict, campaign_type: str = None) -> Dict:
        for attempt in range(3):
            prompt = f"""为目标制定攻击计划:

目标画像: {json.dumps(target_profile, indent=2)}
战役类型: {campaign_type or '自动选择最适合的类型'}

严格要求:
- phases字段必须是数组，每个元素包含: step(步骤名), phase(阶段), mitre_tech(MITRE技术ID,如T1190), success_prob(0-1), stealth(隐匿度low/medium/high)
- overall_success_prob必须是0-1之间的浮点数
- estimated_duration是字符串如\"7-14 days\"
返回JSON: {{"campaign_type":"...", "phases":[...], "estimated_duration":"...", "overall_success_prob":0.0}}
nonce:{time.time_ns()}"""
            result = self.chat_json(self.RED_SYSTEM_PROMPT, prompt, temperature=0.5)
            parsed = result.get("parsed", {})
            phases = parsed.get("phases") or parsed.get("attack_phases") or []
            normalized = []
            for p in phases:
                if isinstance(p, dict):
                    normalized.append({
                        "step": p.get("step") or p.get("phase") or p.get("name", "unknown"),
                        "phase": p.get("phase") or p.get("step", "unknown"),
                        "mitre_tech": p.get("mitre_tech") or p.get("technique_id", ""),
                        "success_prob": float(p.get("success_prob") or p.get("success_probability", 0.5)),
                        "stealth": p.get("stealth") or p.get("stealth_level", "medium"),
                    })
            # 至少有3个有效阶段才接受结果
            if len(normalized) >= 3:
                return {
                    "campaign_type": parsed.get("campaign_type", "unknown"),
                    "phases": normalized,
                    "estimated_duration": parsed.get("estimated_duration", ""),
                    "overall_success_prob": float(parsed.get("overall_success_prob") or parsed.get("overall_success_probability", 0.5)),
                }
            if attempt < 2:
                time.sleep(0.5)
        # 3次都失败则返回基础plan
        return {
            "campaign_type": "fallback",
            "phases": [
                {"step": "recon", "phase": "reconnaissance", "mitre_tech": "T1595", "success_prob": 0.8, "stealth": "medium"},
                {"step": "initial_access", "phase": "initial_access", "mitre_tech": "T1190", "success_prob": 0.6, "stealth": "medium"},
                {"step": "execution", "phase": "execution", "mitre_tech": "T1203", "success_prob": 0.7, "stealth": "low"},
                {"step": "persistence", "phase": "persistence", "mitre_tech": "T1053", "success_prob": 0.65, "stealth": "medium"},
                {"step": "exfiltration", "phase": "exfiltration", "mitre_tech": "T1041", "success_prob": 0.5, "stealth": "high"},
            ],
            "estimated_duration": "7-14 days",
            "overall_success_prob": 0.4,
        }

    def optimize_attack_timing(self, blue_mtd_schedule: Dict) -> Dict:
        prompt = f"""分析蓝队MTD(移动目标防御)时间表，给出攻击时机优化:

MTD时间表: {json.dumps(blue_mtd_schedule, indent=2)}

返回JSON包含: optimal_delay_s(float), vulnerability_window_s(float),
recommendation(str), mtd_aware(bool)"""
        result = self.chat_json(self.RED_SYSTEM_PROMPT, prompt, temperature=0.3)
        return result.get("parsed", {})


if __name__ == "__main__":
    print("=" * 60)
    print("D03 Real LLM Bridge — 自检")
    print("=" * 60)
    config = RealAPIConfig()
    bridge = RealLLMBridge(config)
    print(f"\n桥接状态: provider={bridge.creds['provider'] if bridge.creds else 'mock'}")

    result = bridge.chat(
        "你是一个网络安全助手，回答要简洁。",
        "描述一下Cobalt Strike Beacon的特征"
    )
    print(f"\n测试响应: {result['response'][:200]}...")
    print(f"统计: {bridge.get_stats()}")

    soc = SOCLLMBridge(config)
    triage = soc.triage_alert({"type": "phishing", "severity": 0.8, "is_real_attack": True})
    print(f"\nSOC分诊: {json.dumps(triage, indent=2, ensure_ascii=False)[:300]}")

    red = RedLLMBridge(config)
    plan = red.generate_attack_plan({"industry": "finance", "size": 500, "security_maturity": "medium"})
    print(f"\n攻击计划: {json.dumps(plan, indent=2, ensure_ascii=False)[:300]}")
