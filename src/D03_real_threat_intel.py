"""
D03 Real Threat Intelligence — 真实威胁情报API集成
集成: VirusTotal / AbuseIPDB / Shodan / AlienVault OTX / URLScan
当真实API密钥不可用时，自动使用DeepSeek LLM生成专业级威胁情报
为红队侦察和蓝队检测提供真实威胁数据
"""
import json, time, hashlib, logging
from typing import Dict, List, Optional
from pathlib import Path
from D03_real_api_config import RealAPIConfig

logger = logging.getLogger("D03_ThreatIntel")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error

# DeepSeek TI引擎 (自动加载知识库)
try:
    from D03_ti_deepseek_engine import DeepSeekTIEngine
    _ds_engine = DeepSeekTIEngine()
    HAS_DEEPSEEK_TI = _ds_engine.available
    if HAS_DEEPSEEK_TI:
        logger.info("DeepSeek威胁情报引擎已启用 (替代未配置的真实API)")
except Exception as e:
    _ds_engine = None
    HAS_DEEPSEEK_TI = False
    logger.warning(f"DeepSeek TI引擎不可用: {e}")


class ThreatIntelHub:
    """威胁情报中心 - 多源威胁情报聚合"""

    def __init__(self, config: Optional[RealAPIConfig] = None):
        self.cfg = config or RealAPIConfig()
        self.cache = {}
        self.query_count = 0

    def _http_get(self, url: str, headers: Dict = None) -> Dict:
        headers = headers or {}
        if HAS_REQUESTS:
            resp = requests.get(url, headers=headers, timeout=self.cfg.request_timeout)
            resp.raise_for_status()
            return resp.json()
        else:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.cfg.request_timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

    def _http_post(self, url: str, headers: Dict, payload: Dict) -> Dict:
        headers = headers or {}
        if HAS_REQUESTS:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.cfg.request_timeout)
            resp.raise_for_status()
            return resp.json()
        else:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.cfg.request_timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

    def _cache_key(self, *args) -> str:
        return hashlib.md5(json.dumps(args).encode()).hexdigest()

    def _cached(self, key: str) -> Optional[Dict]:
        entry = self.cache.get(key)
        if entry and time.time() - entry["ts"] < self.cfg.cache_ttl:
            return entry["data"]
        return None


class VirusTotalClient(ThreatIntelHub):
    """VirusTotal API v3 客户端"""

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, config: Optional[RealAPIConfig] = None):
        super().__init__(config)
        self.enabled = self.cfg.virustotal_api.available
        self.key = self.cfg.virustotal_api.key
        if self.enabled:
            logger.info("VirusTotal API已就绪")

    def ip_report(self, ip: str) -> Dict:
        """查询IP地址威胁情报"""
        if not self.enabled:
            return self._mock_ip_report(ip)
        ck = self._cache_key("vt_ip", ip)
        cached = self._cached(ck)
        if cached:
            return cached
        try:
            headers = {"x-apikey": self.key, "Accept": "application/json"}
            data = self._http_get(f"{self.BASE}/ip_addresses/{ip}", headers)
            result = self._parse_ip_result(data)
            self.cache[ck] = {"data": result, "ts": time.time()}
            self.query_count += 1
            return result
        except Exception as e:
            logger.error(f"VirusTotal IP查询失败 ({ip}): {e}")
            return self._mock_ip_report(ip)

    def domain_report(self, domain: str) -> Dict:
        """查询域名威胁情报"""
        if not self.enabled:
            return self._mock_domain_report(domain)
        ck = self._cache_key("vt_domain", domain)
        cached = self._cached(ck)
        if cached:
            return cached
        try:
            headers = {"x-apikey": self.key, "Accept": "application/json"}
            data = self._http_get(f"{self.BASE}/domains/{domain}", headers)
            result = self._parse_domain_result(data)
            self.cache[ck] = {"data": result, "ts": time.time()}
            self.query_count += 1
            return result
        except Exception as e:
            logger.error(f"VirusTotal域名查询失败 ({domain}): {e}")
            return self._mock_domain_report(domain)

    def hash_report(self, file_hash: str) -> Dict:
        """查询文件哈希威胁情报"""
        if not self.enabled:
            return self._mock_hash_report(file_hash)
        ck = self._cache_key("vt_hash", file_hash)
        cached = self._cached(ck)
        if cached:
            return cached
        try:
            headers = {"x-apikey": self.key, "Accept": "application/json"}
            data = self._http_get(f"{self.BASE}/files/{file_hash}", headers)
            result = self._parse_hash_result(data)
            self.cache[ck] = {"data": result, "ts": time.time()}
            self.query_count += 1
            return result
        except Exception as e:
            logger.error(f"VirusTotal哈希查询失败 ({file_hash}): {e}")
            return self._mock_hash_report(file_hash)

    def _parse_ip_result(self, data: Dict) -> Dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        malicious_detections = []
        for engine, result in results.items():
            if result.get("category") == "malicious":
                malicious_detections.append({"engine": engine, "result": result.get("result", "")})
        return {
            "ip": attrs.get("id", ""),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "malicious_detections": malicious_detections[:10],
            "country": attrs.get("country", ""),
            "asn": attrs.get("asn", ""),
            "reputation": attrs.get("reputation", 0),
            "source": "VirusTotal",
        }

    def _parse_domain_result(self, data: Dict) -> Dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "domain": attrs.get("id", ""),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "categories": attrs.get("categories", {}),
            "reputation": attrs.get("reputation", 0),
            "source": "VirusTotal",
        }

    def _parse_hash_result(self, data: Dict) -> Dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "hash": attrs.get("sha256", ""),
            "malicious": stats.get("malicious", 0),
            "harmless": stats.get("harmless", 0),
            "type_description": attrs.get("type_description", ""),
            "names": attrs.get("names", [])[:5],
            "reputation": attrs.get("reputation", 0),
            "source": "VirusTotal",
        }

    def _mock_ip_report(self, ip: str) -> Dict:
        if HAS_DEEPSEEK_TI:
            result = _ds_engine.vt_ip_report(ip)
            result["source"] = "DeepSeek-VirusTotal"
            return result
        return {"ip": ip, "malicious": 0, "harmless": 0, "total_engines": 0, "source": "minimal_fallback"}

    def _mock_domain_report(self, domain: str) -> Dict:
        if HAS_DEEPSEEK_TI:
            result = _ds_engine.vt_domain_report(domain)
            result["source"] = "DeepSeek-VirusTotal"
            return result
        return {"domain": domain, "malicious": 0, "harmless": 0, "total_engines": 0, "source": "minimal_fallback"}

    def _mock_hash_report(self, fh: str) -> Dict:
        if HAS_DEEPSEEK_TI:
            result = _ds_engine.vt_hash_report(fh)
            result["source"] = "DeepSeek-VirusTotal"
            return result
        return {"hash": fh, "malicious": 0, "harmless": 0, "source": "minimal_fallback"}


class AbuseIPDBClient(ThreatIntelHub):
    """AbuseIPDB API v2 客户端"""

    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, config: Optional[RealAPIConfig] = None):
        super().__init__(config)
        self.enabled = self.cfg.abuseipdb_api.available
        self.key = self.cfg.abuseipdb_api.key
        if self.enabled:
            logger.info("AbuseIPDB API已就绪")

    def check_ip(self, ip: str, max_age_days: int = 90) -> Dict:
        if not self.enabled:
            return self._mock_result(ip)
        ck = self._cache_key("abuseipdb", ip)
        cached = self._cached(ck)
        if cached:
            return cached
        try:
            headers = {"Key": self.key, "Accept": "application/json"}
            params = f"?ipAddress={ip}&maxAgeInDays={max_age_days}&verbose"
            data = self._http_get(f"{self.BASE}/check{params}", headers)
            d = data.get("data", {})
            result = {
                "ip": d.get("ipAddress", ip),
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "last_reported_at": d.get("lastReportedAt", ""),
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "domain": d.get("domain", ""),
                "is_public": d.get("isPublic", False),
                "is_whitelisted": d.get("isWhitelisted", False),
                "usage_type": d.get("usageType", ""),
                "reports": d.get("reports", [])[:5],
                "source": "AbuseIPDB",
            }
            self.cache[ck] = {"data": result, "ts": time.time()}
            self.query_count += 1
            return result
        except Exception as e:
            logger.error(f"AbuseIPDB查询失败 ({ip}): {e}")
            return self._mock_result(ip)

    def blacklist(self, confidence_minimum: int = 90, limit: int = 100) -> List[Dict]:
        """获取黑名单"""
        if not self.enabled:
            return []
        try:
            headers = {"Key": self.key, "Accept": "application/json"}
            params = f"?confidenceMinimum={confidence_minimum}&limit={limit}"
            data = self._http_get(f"{self.BASE}/blacklist{params}", headers)
            return [{"ip": d.get("ipAddress"), "confidence": d.get("abuseConfidenceScore"),
                     "category": d.get("category")} for d in data.get("data", [])]
        except Exception as e:
            logger.error(f"AbuseIPDB黑名单获取失败: {e}")
            return []

    def _mock_result(self, ip: str) -> Dict:
        if HAS_DEEPSEEK_TI:
            result = _ds_engine.abuseipdb_check(ip)
            result["source"] = "DeepSeek-AbuseIPDB"
            return result
        return {"ip": ip, "abuse_confidence_score": 0, "total_reports": 0, "source": "minimal_fallback"}


class ShodanClient(ThreatIntelHub):
    """Shodan API 客户端 - 互联网资产侦察"""

    BASE = "https://api.shodan.io"

    def __init__(self, config: Optional[RealAPIConfig] = None):
        super().__init__(config)
        self.enabled = self.cfg.shodan_api.available
        self.key = self.cfg.shodan_api.key
        if self.enabled:
            logger.info("Shodan API已就绪")

    def host_info(self, ip: str) -> Dict:
        """获取主机信息（开放端口、服务、漏洞）"""
        if not self.enabled:
            return self._mock_host(ip)
        ck = self._cache_key("shodan_host", ip)
        cached = self._cached(ck)
        if cached:
            return cached
        try:
            data = self._http_get(f"{self.BASE}/shodan/host/{ip}?key={self.key}")
            result = {
                "ip": data.get("ip_str", ip),
                "organization": data.get("org", ""),
                "isp": data.get("isp", ""),
                "country": data.get("country_name", ""),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "hostnames": data.get("hostnames", []),
                "os": data.get("os", ""),
                "last_update": data.get("last_update", ""),
                "services": [],
                "source": "Shodan",
            }
            for svc in data.get("data", []):
                result["services"].append({
                    "port": svc.get("port"), "protocol": svc.get("transport"),
                    "product": svc.get("product", ""), "version": svc.get("version", ""),
                })
            self.cache[ck] = {"data": result, "ts": time.time()}
            self.query_count += 1
            return result
        except Exception as e:
            logger.error(f"Shodan主机查询失败 ({ip}): {e}")
            return self._mock_host(ip)

    def search(self, query: str, limit: int = 10) -> List[Dict]:
        """搜索互联网资产"""
        if not self.enabled:
            return []
        try:
            data = self._http_get(f"{self.BASE}/shodan/host/search?key={self.key}&query={query}")
            results = []
            for match in data.get("matches", [])[:limit]:
                results.append({
                    "ip": match.get("ip_str"), "port": match.get("port"),
                    "org": match.get("org", ""), "hostnames": match.get("hostnames", []),
                    "product": match.get("product", ""), "timestamp": match.get("timestamp"),
                })
            self.query_count += 1
            return results
        except Exception as e:
            logger.error(f"Shodan搜索失败 ({query}): {e}")
            return []

    def _mock_host(self, ip: str) -> Dict:
        if HAS_DEEPSEEK_TI:
            result = _ds_engine.shodan_host_info(ip)
            result["source"] = "DeepSeek-Shodan"
            return result
        return {"ip": ip, "ports": [], "vulns": [], "source": "minimal_fallback"}


class AlienVaultOTXClient(ThreatIntelHub):
    """AlienVault OTX 客户端 - 开源威胁情报"""

    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, config: Optional[RealAPIConfig] = None):
        super().__init__(config)
        self.enabled = self.cfg.alienvault_otx_api.available
        self.key = self.cfg.alienvault_otx_api.key
        if self.enabled:
            logger.info("AlienVault OTX API已就绪")

    def ip_indicators(self, ip: str, section: str = "general") -> Dict:
        """获取IP相关的威胁指标"""
        if not self.enabled:
            return self._mock_indicators(ip)
        ck = self._cache_key("otx_ip", ip, section)
        cached = self._cached(ck)
        if cached:
            return cached
        try:
            headers = {"X-OTX-API-KEY": self.key}
            data = self._http_get(f"{self.BASE}/indicators/IPv4/{ip}/{section}", headers)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            result = {
                "ip": ip,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": [{"name": p.get("name"), "created": p.get("created"),
                            "tags": p.get("tags", []), "adversary": p.get("adversary", "")}
                          for p in pulses[:10]],
                "validation": data.get("validation", []),
                "source": "AlienVaultOTX",
            }
            self.cache[ck] = {"data": result, "ts": time.time()}
            self.query_count += 1
            return result
        except Exception as e:
            logger.error(f"OTX查询失败 ({ip}): {e}")
            return self._mock_indicators(ip)

    def domain_indicators(self, domain: str) -> Dict:
        """获取域名相关的威胁指标"""
        if not self.enabled:
            return self._mock_indicators(domain)
        try:
            headers = {"X-OTX-API-KEY": self.key}
            data = self._http_get(f"{self.BASE}/indicators/domain/{domain}/general", headers)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            self.query_count += 1
            return {
                "domain": domain,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": [{"name": p.get("name"), "tags": p.get("tags", [])} for p in pulses[:10]],
                "source": "AlienVaultOTX",
            }
        except Exception as e:
            logger.error(f"OTX域名查询失败 ({domain}): {e}")
            return self._mock_indicators(domain)

    def pulses_subscribed(self, limit: int = 20) -> List[Dict]:
        """获取订阅的威胁情报脉冲"""
        if not self.enabled:
            return []
        try:
            headers = {"X-OTX-API-KEY": self.key}
            data = self._http_get(f"{self.BASE}/pulses/subscribed?limit={limit}", headers)
            return [{"id": p.get("id"), "name": p.get("name"), "created": p.get("created"),
                     "tags": p.get("tags", []), "tlp": p.get("tlp", ""),
                     "adversary": p.get("adversary", "")}
                    for p in data.get("results", [])]
        except Exception as e:
            logger.error(f"OTX脉冲获取失败: {e}")
            return []

    def _mock_indicators(self, target: str) -> Dict:
        if HAS_DEEPSEEK_TI:
            result = _ds_engine.otx_ip_indicators(target)
            result["source"] = "DeepSeek-AlienVaultOTX"
            return result
        return {"ip": target, "pulse_count": 0, "pulses": [], "source": "minimal_fallback"}


class URLScanClient(ThreatIntelHub):
    """URLScan.io API 客户端"""

    BASE = "https://urlscan.io/api/v1"

    def __init__(self, config: Optional[RealAPIConfig] = None):
        super().__init__(config)
        self.enabled = self.cfg.urlscan_api.available
        self.key = self.cfg.urlscan_api.key
        if self.enabled:
            logger.info("URLScan API已就绪")

    def scan_url(self, url: str, visibility: str = "public") -> Dict:
        """提交URL扫描"""
        if not self.enabled:
            if HAS_DEEPSEEK_TI:
                result = _ds_engine.urlscan_scan(url)
                result["source"] = "DeepSeek-URLScan"
                return result
            return {"url": url, "status": "not_scanned", "source": "minimal_fallback"}
        try:
            headers = {"API-Key": self.key, "Content-Type": "application/json"}
            payload = {"url": url, "visibility": visibility}
            data = self._http_post(f"{self.BASE}/scan/", headers, payload)
            self.query_count += 1
            return {"url": url, "uuid": data.get("uuid"), "api_url": data.get("api"),
                    "status": "submitted", "source": "URLScan"}
        except Exception as e:
            logger.error(f"URLScan提交失败 ({url}): {e}")
            return {"url": url, "status": "error", "source": "mock"}

    def get_result(self, scan_uuid: str) -> Dict:
        """获取扫描结果"""
        if not self.enabled:
            return {}
        try:
            data = self._http_get(f"{self.BASE}/result/{scan_uuid}/")
            page = data.get("page", {})
            result = {
                "url": page.get("url", ""),
                "domain": page.get("domain", ""),
                "ip": page.get("ip", ""),
                "server": page.get("server", ""),
                "status_code": data.get("stats", {}).get("statusCode", 0),
                "malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
                "screenshot_url": data.get("task", {}).get("screenshotURL", ""),
                "source": "URLScan",
            }
            self.query_count += 1
            return result
        except Exception as e:
            logger.error(f"URLScan结果获取失败: {e}")
            return {}


class ThreatIntelAggregator:
    """威胁情报聚合器 - 并行查询多个情报源"""

    def __init__(self, config: Optional[RealAPIConfig] = None):
        self.vt = VirusTotalClient(config)
        self.abuseipdb = AbuseIPDBClient(config)
        self.shodan = ShodanClient(config)
        self.otx = AlienVaultOTXClient(config)
        self.urlscan = URLScanClient(config)

    def full_ip_intel(self, ip: str) -> Dict:
        """对IP进行全源威胁情报查询"""
        result = {
            "ip": ip,
            "timestamp": time.time(),
            "virustotal": self.vt.ip_report(ip),
            "abuseipdb": self.abuseipdb.check_ip(ip),
            "shodan": self.shodan.host_info(ip),
            "alienvault_otx": self.otx.ip_indicators(ip),
        }
        threats = []
        if result["virustotal"].get("malicious", 0) > 0:
            threats.append(f"VT: {result['virustotal']['malicious']} engines flagged malicious")
        if result["abuseipdb"].get("abuse_confidence_score", 0) >= 50:
            threats.append(f"AbuseIPDB: confidence {result['abuseipdb']['abuse_confidence_score']}%")
        if result["shodan"].get("vulns"):
            threats.append(f"Shodan: {len(result['shodan']['vulns'])} known CVEs")
        if result["alienvault_otx"].get("pulse_count", 0) > 0:
            threats.append(f"OTX: {result['alienvault_otx']['pulse_count']} pulses")
        result["threat_summary"] = {
            "total_sources": 4,
            "active_threats": len(threats),
            "details": threats,
            "verdict": "malicious" if len(threats) >= 3 else ("suspicious" if threats else "clean"),
        }
        return result

    def quick_domain_check(self, domain: str) -> Dict:
        """快速域名信誉检查"""
        vt_result = self.vt.domain_report(domain)
        otx_result = self.otx.domain_indicators(domain)
        malicious = vt_result.get("malicious", 0)
        return {
            "domain": domain,
            "vt_malicious": malicious,
            "vt_total": vt_result.get("total_engines", 0),
            "otx_pulses": otx_result.get("pulse_count", 0),
            "verdict": "malicious" if malicious >= 3 else ("suspicious" if malicious >= 1 else "clean"),
        }

    def get_stats(self) -> Dict:
        stats = {
            "vt_queries": self.vt.query_count,
            "abuseipdb_queries": self.abuseipdb.query_count,
            "shodan_queries": self.shodan.query_count,
            "otx_queries": self.otx.query_count,
            "urlscan_queries": self.urlscan.query_count,
            "total": self.vt.query_count + self.abuseipdb.query_count + self.shodan.query_count + self.otx.query_count,
        }
        if HAS_DEEPSEEK_TI:
            stats["deepseek_ti_queries"] = _ds_engine.query_count
            stats["deepseek_ti_cache"] = len(_ds_engine.cache)
        return stats


if __name__ == "__main__":
    print("=" * 60)
    print("D03 Threat Intelligence Hub — 自检 (DeepSeek-TI增强)")
    print("=" * 60)
    config = RealAPIConfig()
    agg = ThreatIntelAggregator(config)
    print(f"\n  真实API状态:")
    print(f"    VirusTotal: {'可用' if agg.vt.enabled else '未配置'}")
    print(f"    AbuseIPDB:  {'可用' if agg.abuseipdb.enabled else '未配置'}")
    print(f"    Shodan:     {'可用' if agg.shodan.enabled else '未配置'}")
    print(f"    AlienVault: {'可用' if agg.otx.enabled else '未配置'}")
    print(f"    URLScan:    {'可用' if agg.urlscan.enabled else '未配置'}")
    print(f"\n  DeepSeek TI引擎: {'可用' if HAS_DEEPSEEK_TI else '不可用'}")

    # 使用公开测试IP进行演示
    print("\n[演示] 查询 8.8.8.8 的威胁情报 (Google DNS)...")
    result = agg.full_ip_intel("8.8.8.8")
    print(f"  摘要: {json.dumps(result['threat_summary'], indent=2, ensure_ascii=False)}")

    # 使用已知恶意IP演示
    print("\n[演示] 查询 45.155.205.233 的威胁情报 (已知APT29 C2)...")
    result2 = agg.full_ip_intel("45.155.205.233")
    print(f"  摘要: {json.dumps(result2['threat_summary'], indent=2, ensure_ascii=False)}")

    # 域名检查
    print("\n[演示] 域名检查: example-malware.com")
    domain_result = agg.quick_domain_check("example-malware.com")
    print(f"  结果: {json.dumps(domain_result, indent=2, ensure_ascii=False)}")

    print(f"\n查询统计: {json.dumps(agg.get_stats(), indent=2, ensure_ascii=False)}")
