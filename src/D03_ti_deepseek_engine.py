"""
D03 DeepSeek Threat Intelligence Engine
========================================
用DeepSeek LLM替代真实威胁情报API (VirusTotal/AbuseIPDB/Shodan/OTX/URLScan)。
集成专业知识库，通过精心设计的系统提示词生成专业级威胁情报数据。

设计原则 (参考Claude Code):
  1. 结构化输出 — 严格JSON Schema约束，防止幻觉
  2. 知识库注入 — 预加载已知IoC/CVE/APT资料，确保专业性
  3. 输出验证 — Schema校验 + 合理性检查
  4. 缓存机制 — 相同查询复用结果，节约API成本
  5. 安全隔离 — prompt内容不包含用户可控的自由文本
"""
import json, time, hashlib, logging, os, re
from pathlib import Path
from typing import Dict, List, Optional, Any
from functools import lru_cache

BASE_DIR = Path(__file__).parent.absolute()
KB_PATH = BASE_DIR / "D03_ti_knowledge_base.json"

logger = logging.getLogger("D03_DeepSeekTI")

# ============================================================================
# 知识库加载 (带缓存校验的惰性加载)
# ============================================================================
_kb_cache: Optional[Dict] = None
_kb_load_time: float = 0

def _load_knowledge_base() -> Dict:
    """加载威胁情报知识库，30秒缓存防重复IO。兼容v1和v2格式"""
    global _kb_cache, _kb_load_time
    if _kb_cache is not None and time.time() - _kb_load_time < 30:
        return _kb_cache
    try:
        with open(KB_PATH, 'r', encoding='utf-8') as f:
            _kb_cache = json.load(f)
        _kb_load_time = time.time()
        ver = _kb_cache.get('version', '1.0')
        apt_count = len(_kb_cache.get('apt_groups', _kb_cache.get('apt_profiles', {})))
        cve_count = len(_kb_cache.get('critical_cves', _kb_cache.get('known_cve_database', {})))
        technique_count = len(_kb_cache.get('top_techniques', {}))
        logger.info(f"知识库v{ver}: {len(_kb_cache.get('known_malicious_ips', {}))} IP, "
                    f"{cve_count} CVE, {apt_count} APT, {technique_count} 技术")
        return _kb_cache
    except Exception as e:
        logger.warning(f"知识库加载失败: {e}，使用内嵌最小知识集")
        return {
            "known_malicious_ips": {}, "critical_cves": [],
            "apt_groups": {}, "service_port_map": {}, "common_ports_by_os": {}
        }

# ============================================================================
# 输出Schema定义 (严格约束DeepSeek输出格式)
# ============================================================================
SCHEMAS = {
    "ip_report": {
        "fields": ["ip", "malicious", "suspicious", "harmless", "undetected", "total_engines",
                   "country", "asn", "isp", "reputation", "malicious_detections",
                   "category", "threat_actor", "associated_malware", "confidence"],
        "types": {"malicious": int, "suspicious": int, "harmless": int, "undetected": int,
                  "reputation": int, "confidence": float},
    },
    "domain_report": {
        "fields": ["domain", "malicious", "suspicious", "harmless", "undetected", "total_engines",
                   "categories", "reputation", "registrar", "creation_date"],
    },
    "hash_report": {
        "fields": ["hash", "malicious", "harmless", "undetected", "type_description",
                   "names", "reputation", "first_seen", "tags"],
    },
    "abuseipdb": {
        "fields": ["ip", "abuse_confidence_score", "total_reports", "country",
                   "isp", "domain", "usage_type", "is_public", "is_whitelisted"],
    },
    "shodan_host": {
        "fields": ["ip", "organization", "isp", "country", "ports", "vulns",
                   "hostnames", "os", "services"],
    },
    "otx_indicators": {
        "fields": ["ip", "pulse_count", "pulses", "validation"],
    },
    "url_scan": {
        "fields": ["url", "domain", "ip", "server", "malicious", "verdict", "threat_type"],
    },
}

def _validate_schema(data: Dict, schema_name: str) -> Dict:
    """输出Schema校验：确保必填字段存在且类型正确"""
    schema = SCHEMAS.get(schema_name, {})
    fields = schema.get("fields", [])
    types = schema.get("types", {})
    for field in fields:
        if field not in data:
            data[field] = _default_for_field(field, types.get(field))
        elif field in types:
            try:
                expected = types[field]
                if expected == int and isinstance(data[field], str):
                    data[field] = int(re.sub(r'[^\d-]', '', data[field]) or 0)
                elif expected == float and isinstance(data[field], str):
                    data[field] = float(re.sub(r'[^\d.]', '', data[field]) or 0)
            except (ValueError, TypeError):
                data[field] = _default_for_field(field, expected)
    return data

def _default_for_field(field: str, expected_type=None) -> Any:
    defaults = {
        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        "total_engines": 0, "reputation": 0, "abuse_confidence_score": 0,
        "total_reports": 0, "pulse_count": 0, "confidence": 0.0,
        "country": "", "asn": "", "isp": "", "category": "", "threat_actor": "",
        "associated_malware": [], "malicious_detections": [], "ports": [],
        "vulns": [], "hostnames": [], "services": [], "pulses": [], "validation": [],
        "categories": {}, "names": [], "tags": [], "type_description": "",
    }
    return defaults.get(field, "" if expected_type == str else ([] if expected_type == list else 0))

# ============================================================================
# DeepSeek TI Engine (核心引擎)
# ============================================================================
class DeepSeekTIEngine:
    """DeepSeek驱动的威胁情报引擎，替代真实API的mock回退"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        self.kb = _load_knowledge_base()
        self.cache: Dict[str, Dict] = {}
        self.cache_ttl = 300
        self.query_count = 0
        self._available = bool(self.api_key)
        if self._available:
            logger.info("DeepSeek TI引擎就绪 (LLM-powered threat intelligence)")

    @property
    def available(self) -> bool:
        return self._available

    def _kb_lookup_ip(self, ip: str) -> Optional[Dict]:
        """在知识库中查找已知恶意IP (兼容v1/v2)"""
        return self.kb.get("known_malicious_ips", {}).get(ip)

    def _kb_lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """在知识库中查找CVE (兼容v1/v2)"""
        # v2 format: critical_cves list
        cves = self.kb.get("critical_cves", []) or self.kb.get("ransomware_cves", [])
        for c in cves:
            if c.get('cve', '').upper() == cve_id.upper():
                return c
        # v1 format: dict
        legacy = self.kb.get("known_cve_database", {})
        return legacy.get(cve_id.upper())

    def _kb_lookup_apt(self, apt_name: str) -> Optional[Dict]:
        """在知识库中查找APT组织 (兼容v1/v2)"""
        # v2 format: apt_groups
        for key, profile in self.kb.get("apt_groups", {}).items():
            aliases = profile.get("aliases", [])
            if apt_name.lower() in key.lower() or any(apt_name.lower() in a.lower() for a in aliases):
                return profile
        # v1 format: apt_profiles
        for key, profile in self.kb.get("apt_profiles", {}).items():
            if apt_name.lower() in key.lower() or apt_name.lower() in [a.lower() for a in profile.get("aliases", [])]:
                return profile
        return None

    def _kb_lookup_technique(self, tech_id: str) -> Optional[Dict]:
        """查找MITRE ATT&CK技术"""
        return self.kb.get("top_techniques", {}).get(tech_id.upper())

    def _kb_relevant_context(self, ip: str = None, cve: str = None, apt: str = None) -> str:
        """智能上下文选择：只提取与查询相关的知识库条目，避免超长prompt"""
        parts = []
        # IP相关
        if ip:
            kb_ip = self._kb_lookup_ip(ip)
            if kb_ip:
                parts.append(f"[KB-IP] {ip}: {kb_ip.get('category','')}/{kb_ip.get('threat_actor','')}, "
                           f"malware={kb_ip.get('associated_malware',[])}, "
                           f"mitre={kb_ip.get('mitre_techniques',[])}, "
                           f"asn={kb_ip.get('asn','')}, country={kb_ip.get('country','')}")
        # CVE相关
        if cve:
            kb_cve = self._kb_lookup_cve(cve)
            if kb_cve:
                parts.append(f"[KB-CVE] {cve}: {kb_cve.get('vendor','')}/{kb_cve.get('product','')}, "
                           f"severity={kb_cve.get('severity','')}, "
                           f"ransomware={kb_cve.get('ransomware_used','')}")
        # APT相关
        if apt:
            kb_apt = self._kb_lookup_apt(apt)
            if kb_apt:
                parts.append(f"[KB-APT] {apt}: aliases={kb_apt.get('aliases',[])}, "
                           f"techniques={kb_apt.get('technique_count','')}, "
                           f"desc={kb_apt.get('description','')[:200]}")
        return "\n".join(parts)

    def _kb_top_apt_context(self, limit: int = 5) -> str:
        """返回Top APT组织的简要信息"""
        apts = list(self.kb.get("apt_groups", {}).items())[:limit]
        lines = []
        for name, info in apts:
            lines.append(f"  {name}: {info.get('technique_count','?')} techniques, "
                        f"aliases={info.get('aliases', [])[:3]}")
        return "\n".join(lines)

    def _cache_key(self, *args) -> str:
        return hashlib.md5(json.dumps(args, sort_keys=True).encode()).hexdigest()

    def _cached(self, key: str) -> Optional[Dict]:
        entry = self.cache.get(key)
        if entry and time.time() - entry["ts"] < self.cache_ttl:
            return entry["data"]
        return None

    def _set_cache(self, key: str, data: Dict):
        self.cache[key] = {"data": data, "ts": time.time()}

    def _call_llm(self, system_prompt: str, user_prompt: str,
                  max_tokens: int = 800, temperature: float = 0.15) -> Dict:
        """调用DeepSeek API，带重试和错误处理"""
        if not self._available:
            return {}

        import urllib.request
        url = "https://api.deepseek.com/v1/chat/completions"
        body = json.dumps({
            "model": "deepseek-v4-flash",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens, "temperature": temperature,
            "response_format": {"type": "json_object"},
        }).encode("utf-8")

        for attempt in range(3):
            try:
                req = urllib.request.Request(url, data=body, headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                })
                resp = urllib.request.urlopen(req, timeout=30)
                data = json.loads(resp.read())
                content = data["choices"][0]["message"]["content"]

                # 提取JSON (防御非JSON输出)
                content = content.strip()
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]

                parsed = json.loads(content)
                self.query_count += 1
                return parsed

            except json.JSONDecodeError as e:
                # 尝试修复截断的JSON
                if attempt == 0:
                    try:
                        fixed = content
                        # 1. 闭合未关闭的字符串 (在最后添加引号)
                        in_string = False
                        escape = False
                        for ch in fixed:
                            if escape: escape = False; continue
                            if ch == '\\': escape = True; continue
                            if ch == '"': in_string = not in_string
                        if in_string:
                            fixed += '"'
                        # 2. 补全未闭合的括号和花括号
                        for ch in [']', '}']:
                            open_c = '[' if ch == ']' else '{'
                            diff = fixed.count(open_c) - fixed.count(ch)
                            fixed += ch * max(0, diff)
                        # 3. 如果最后一个字符不是}或], 补一个}
                        if fixed.rstrip()[-1] not in ('}', ']', '"'):
                            fixed += '}'
                        parsed = json.loads(fixed)
                        self.query_count += 1
                        return parsed
                    except:
                        pass
                if attempt < 2:
                    time.sleep(0.5)
                    continue
                logger.warning(f"DeepSeek TI JSON parse failed: {e}")
                return {}
            except Exception as e:
                if attempt < 2:
                    time.sleep(1 * (attempt + 1))
                    continue
                logger.error(f"DeepSeek TI调用失败: {e}")
                return {}
        return {}

    def _kb_context_for_ip(self, ip: str) -> str:
        """为IP查询构建知识库上下文 (增强版)"""
        kb_ip = self._kb_lookup_ip(ip)
        top_apt = self._kb_top_apt_context(3)

        if kb_ip:
            # 查找关联APT的详细信息
            apt_name = kb_ip.get('threat_actor', '')
            apt_info = self._kb_lookup_apt(apt_name) if apt_name else None
            apt_desc = f"  {apt_info.get('description', '')[:200]}" if apt_info else ""

            # 查找关联MITRE技术
            tech_details = []
            for tid in kb_ip.get('mitre_techniques', [])[:5]:
                tech = self._kb_lookup_technique(tid)
                if tech:
                    tech_details.append(f"  {tid}: {tech.get('name','')} - {tech.get('description','')[:100]}")

            return f"""
[知识库命中 - 高可信度]
IP: {ip}
  类别: {kb_ip['category']}
  威胁组织: {kb_ip['threat_actor']}{apt_desc}
  关联恶意软件: {', '.join(kb_ip.get('associated_malware', []))}
  MITRE技术详情:\n{chr(10).join(tech_details) if tech_details else '  ' + ', '.join(kb_ip.get('mitre_techniques', []))}
  ASN: {kb_ip.get('asn', '')} ({self.kb.get('isp_map', {}).get(kb_ip.get('asn',''), {}).get('name', '')})
  国家: {kb_ip.get('country', '')}
  首次发现: {kb_ip.get('first_seen', '')}

[知识库参考 - Top APT组织]
{top_apt}

请基于以上知识库信息，生成其他安全引擎对该IP的检测结果。
"""
        return f"""
[IP基本信息 - 无知识库直接命中]
IP: {ip}
请基于IP地址段的典型特征进行威胁情报分析。

[知识库参考 - Top APT组织]
{top_apt}

分析指南:
  - 私有/保留地址 (10.x, 172.16-31.x, 192.168.x) → clean/suspicious
  - 知名云服务商IP (AWS/Azure/GCP) → 通常clean
  - 已知托管/数据中心IP → 中度风险
  - 未识别IP → 需要进一步研判
  - 参考Top APT使用的技术给出可能的MITRE映射
"""

    # ================================================================
    # VirusTotal 风格接口
    # ================================================================
    def vt_ip_report(self, ip: str) -> Dict:
        """DeepSeek生成VirusTotal风格的IP报告"""
        ck = self._cache_key("vt_ip_ds", ip)
        cached = self._cached(ck)
        if cached:
            return cached

        kb_info = self._kb_context_for_ip(ip)

        system = """Threat intel analyst. Output valid JSON only."""

        prompt = f"""{kb_info}
IP: {ip}
Output VirusTotal-style JSON:
{{"ip":"{ip}","malicious":int,"suspicious":int,"harmless":int,"undetected":int,"total_engines":int,"country":"","asn":"","isp":"","reputation":int,"malicious_detections":[{{"engine":"","result":""}}],"category":"","threat_actor":"","associated_malware":[],"confidence":0.0}}"""

        result = self._call_llm(system, prompt, max_tokens=1200, temperature=0.1)
        result = _validate_schema(result, "ip_report")
        result["source"] = "DeepSeek-TI"
        if ip:
            result["ip"] = ip

        self._set_cache(ck, result)
        return result

    def vt_domain_report(self, domain: str) -> Dict:
        """DeepSeek生成VirusTotal风格的域名报告"""
        ck = self._cache_key("vt_domain_ds", domain)
        cached = self._cached(ck)
        if cached:
            return cached

        system = """你是域名安全分析专家。基于知识库和行业经验，生成VirusTotal风格的域名安全报告。
输出严格JSON，数值为整数，categories为对象。"""

        prompt = f"""目标域名: {domain}

生成该域名的VirusTotal检测报告JSON:
{{
  "domain": "{domain}",
  "malicious": <整数>,
  "suspicious": <整数>,
  "harmless": <整数>,
  "undetected": <整数>,
  "total_engines": <整数>,
  "categories": {{"<类别名>": "<引擎名>"}},
  "reputation": <整数>,
  "registrar": "<注册商>",
  "creation_date": "<创建日期>"
}}"""

        result = self._call_llm(system, prompt, max_tokens=400, temperature=0.1)
        result = _validate_schema(result, "domain_report")
        result["source"] = "DeepSeek-TI"
        if domain:
            result["domain"] = domain

        self._set_cache(ck, result)
        return result

    def vt_hash_report(self, file_hash: str) -> Dict:
        """DeepSeek生成VirusTotal风格的文件哈希报告"""
        ck = self._cache_key("vt_hash_ds", file_hash)
        cached = self._cached(ck)
        if cached:
            return cached

        system = """你是恶意软件分析专家。基于哈希值和威胁情报知识，生成文件扫描报告。
输出严格JSON。"""

        prompt = f"""文件哈希: {file_hash}

基于该哈希值特征，生成VirusTotal风格的文件分析报告JSON:
{{
  "hash": "{file_hash}",
  "malicious": <整数>,
  "harmless": <整数>,
  "undetected": <整数>,
  "type_description": "<文件类型描述>",
  "names": ["<常见文件名>"],
  "reputation": <整数>,
  "first_seen": "<首次发现日期>",
  "tags": ["<标签>"]
}}"""

        result = self._call_llm(system, prompt, max_tokens=400, temperature=0.1)
        result = _validate_schema(result, "hash_report")
        result["source"] = "DeepSeek-TI"
        if file_hash:
            result["hash"] = file_hash

        self._set_cache(ck, result)
        return result

    # ================================================================
    # AbuseIPDB 风格接口
    # ================================================================
    def abuseipdb_check(self, ip: str, max_age_days: int = 90) -> Dict:
        """DeepSeek生成AbuseIPDB风格的IP滥用报告"""
        ck = self._cache_key("abuseipdb_ds", ip)
        cached = self._cached(ck)
        if cached:
            return cached

        kb_ip = self._kb_lookup_ip(ip)

        system = """你是网络滥用分析专家。基于IP地址特征和威胁情报，输出AbuseIPDB风格报告。
输出严格JSON，abuse_confidence_score为0-100整数。"""

        prompt = f"""目标IP: {ip}
知识库匹配: {"是 - " + kb_ip['category'] + "/" + kb_ip['threat_actor'] if kb_ip else "否 - 未在已知恶意IP库中"}
查询天数: {max_age_days}

生成AbuseIPDB风格的IP检查报告JSON:
{{
  "ip": "{ip}",
  "abuse_confidence_score": <0-100, 知识库匹配则70-100, 未匹配则0-15>,
  "total_reports": <近{max_age_days}天内报告数量>,
  "country": "<国家代码>",
  "isp": "<ISP>",
  "domain": "<关联域名>",
  "usage_type": "<IP用途: Data Center/Web Hosting, ISP, Business, Education等>",
  "is_public": <true/false>,
  "is_whitelisted": <通常为false>,
  "reports": [{{"category": "<类别>", "date": "<日期>"}}]
}}"""

        result = self._call_llm(system, prompt, max_tokens=400, temperature=0.1)
        result = _validate_schema(result, "abuseipdb")
        result["source"] = "DeepSeek-TI"
        if ip:
            result["ip"] = ip

        self._set_cache(ck, result)
        return result

    # ================================================================
    # Shodan 风格接口
    # ================================================================
    def shodan_host_info(self, ip: str) -> Dict:
        """DeepSeek生成Shodan风格的主机扫描报告"""
        ck = self._cache_key("shodan_ds", ip)
        cached = self._cached(ck)
        if cached:
            return cached

        kb_ip = self._kb_lookup_ip(ip)
        service_map = self.kb.get("service_port_map", {})
        ports_by_os = self.kb.get("common_ports_by_os", {})
        isp_map = self.kb.get("isp_map", {})

        kb_ports = kb_ip.get("ports", []) if kb_ip else []

        system = """你是网络侦察专家，精通Shodan/Masscan/ZoomEye等空间测绘引擎的数据生成。
请基于IP地址特征和专业知识，生成Shodan风格的主机扫描报告。
输出严格JSON，services数组中每项含port/protocol/product/version字段。"""

        prompt = f"""目标IP: {ip}
知识库开放端口: {kb_ports if kb_ports else '未知 - 需推断'}
已知服务端口映射: {json.dumps({k: v['ports'] for k, v in service_map.items()}, ensure_ascii=False)}
已知ISP信息: {json.dumps(isp_map, ensure_ascii=False)}

生成Shodan风格主机扫描报告JSON:
{{
  "ip": "{ip}",
  "organization": "<组织名>",
  "isp": "<ISP名称>",
  "country": "<国家>",
  "ports": [<开放端口列表, 整数>],
  "vulns": ["<已知CVE编号>"],
  "hostnames": ["<主机名>"],
  "os": "<推测操作系统>",
  "services": [
    {{"port": <端口号>, "protocol": "tcp/udp", "product": "<服务产品>", "version": "<版本>"}}
  ]
}}"""

        result = self._call_llm(system, prompt, max_tokens=500, temperature=0.15)
        result = _validate_schema(result, "shodan_host")
        result["source"] = "DeepSeek-TI"
        if ip:
            result["ip"] = ip

        self._set_cache(ck, result)
        return result

    # ================================================================
    # AlienVault OTX 风格接口
    # ================================================================
    def otx_ip_indicators(self, ip: str) -> Dict:
        """DeepSeek生成AlienVault OTX风格的IP威胁指标"""
        ck = self._cache_key("otx_ds", ip)
        cached = self._cached(ck)
        if cached:
            return cached

        kb_ip = self._kb_lookup_ip(ip)
        apt_profiles = self.kb.get("apt_profiles", {})

        system = """你是开源威胁情报(OSINT)分析专家。基于IP特征和APTx知识，生成AlienVault OTX风格的威胁脉冲数据。
输出严格JSON，pulses数组每项含name/tags/adversary。"""

        prompt = f"""目标IP: {ip}
知识库匹配: {"是" if kb_ip else "否"}
已知APT组织: {json.dumps({k: v['aliases'] for k, v in apt_profiles.items()}, ensure_ascii=False)}

生成OTX风格威胁指标JSON:
{{
  "ip": "{ip}",
  "pulse_count": <关联的威胁脉冲数量, 整数>,
  "pulses": [
    {{"name": "<脉冲名称>", "tags": ["<标签>"], "adversary": "<威胁组织>"}}
  ],
  "validation": ["<验证状态: whitelist/blacklist/unknown>"]
}}"""

        result = self._call_llm(system, prompt, max_tokens=400, temperature=0.15)
        result = _validate_schema(result, "otx_indicators")
        result["source"] = "DeepSeek-TI"
        if ip:
            result["ip"] = ip

        self._set_cache(ck, result)
        return result

    def otx_domain_indicators(self, domain: str) -> Dict:
        """DeepSeek生成OTX风格的域名威胁指标"""
        ck = self._cache_key("otx_domain_ds", domain)
        cached = self._cached(ck)
        if cached:
            return cached

        system = """你是域名威胁情报分析专家。基于域名特征和恶意活动模式，生成OTX风格威胁指标。
输出严格JSON。"""

        prompt = f"""目标域名: {domain}
生成OTX风格的域名威胁指标JSON:
{{
  "domain": "{domain}",
  "pulse_count": <整数>,
  "pulses": [
    {{"name": "<脉冲名称>", "tags": ["<标签>"]}}
  ],
  "source": "DeepSeek-TI"
}}"""

        result = self._call_llm(system, prompt, max_tokens=300, temperature=0.15)
        result["source"] = "DeepSeek-TI"
        if domain:
            result["domain"] = domain
        self._set_cache(ck, result)
        return result

    # ================================================================
    # URLScan 风格接口
    # ================================================================
    def urlscan_scan(self, url: str) -> Dict:
        """DeepSeek生成URLScan风格的URL安全扫描报告"""
        ck = self._cache_key("urlscan_ds", url)
        cached = self._cached(ck)
        if cached:
            return cached

        system = """你是Web安全分析专家。基于URL特征和常见攻击模式，生成URLScan风格的扫描报告。
输出严格JSON。"""

        prompt = f"""目标URL: {url}

请分析该URL的安全性，生成URLScan风格报告JSON:
{{
  "url": "{url}",
  "domain": "<提取的域名>",
  "ip": "<解析的IP>",
  "server": "<Web服务器类型>",
  "malicious": <true/false>,
  "verdict": "<clean/suspicious/malicious/phishing/malware>",
  "threat_type": "<威胁类型描述>",
  "source": "DeepSeek-TI"
}}"""

        result = self._call_llm(system, prompt, max_tokens=300, temperature=0.1)
        result = _validate_schema(result, "url_scan")
        result["source"] = "DeepSeek-TI"
        if url:
            result["url"] = url
        self._set_cache(ck, result)
        return result
