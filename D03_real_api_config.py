"""
D03 Real API Configuration — 真实API密钥管理与连接池
所有API密钥通过环境变量管理，不硬编码任何凭证
"""
import os, time, logging
from dataclasses import dataclass, field
from typing import Dict, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='[D03_API] %(levelname)s: %(message)s')
logger = logging.getLogger("D03_RealAPI")


@dataclass
class APICredential:
    env_var: str
    key: Optional[str] = None
    available: bool = False
    last_checked: float = 0.0

    def resolve(self):
        self.key = os.getenv(self.env_var, "")
        self.available = bool(self.key)
        self.last_checked = time.time()
        return self.available


@dataclass
class RealAPIConfig:
    """D03所有真实API的配置中心"""

    # LLM APIs
    openai_api: APICredential = field(default_factory=lambda: APICredential("OPENAI_API_KEY"))
    anthropic_api: APICredential = field(default_factory=lambda: APICredential("ANTHROPIC_API_KEY"))
    deepseek_api: APICredential = field(default_factory=lambda: APICredential("DEEPSEEK_API_KEY"))
    zhipu_api: APICredential = field(default_factory=lambda: APICredential("ZHIPU_API_KEY"))
    moonshot_api: APICredential = field(default_factory=lambda: APICredential("MOONSHOT_API_KEY"))

    # Threat Intelligence APIs
    virustotal_api: APICredential = field(default_factory=lambda: APICredential("VIRUSTOTAL_API_KEY"))
    abuseipdb_api: APICredential = field(default_factory=lambda: APICredential("ABUSEIPDB_API_KEY"))
    shodan_api: APICredential = field(default_factory=lambda: APICredential("SHODAN_API_KEY"))
    alienvault_otx_api: APICredential = field(default_factory=lambda: APICredential("ALIENVAULT_OTX_KEY"))
    urlscan_api: APICredential = field(default_factory=lambda: APICredential("URLSCAN_API_KEY"))

    # Security Tools
    docker_host: APICredential = field(default_factory=lambda: APICredential("DOCKER_HOST"))
    elasticsearch_url: APICredential = field(default_factory=lambda: APICredential("ELASTICSEARCH_URL"))

    # Settings
    llm_provider: str = "openai"  # openai / anthropic / deepseek / zhipu
    llm_model: str = "gpt-4o"
    request_timeout: int = 30
    max_retries: int = 3
    cache_ttl: int = 300

    def __post_init__(self):
        self.refresh_all()

    def refresh_all(self) -> Dict[str, bool]:
        status = {}
        for field_name in self.__dataclass_fields__:
            val = getattr(self, field_name)
            if isinstance(val, APICredential):
                status[field_name] = val.resolve()
        available_count = sum(status.values())
        total = len(status)
        logger.info(f"API状态: {available_count}/{total} 可用")
        for name, ok in status.items():
            if ok:
                logger.info(f"  [OK] {name} -> {getattr(self, name).env_var}")
            else:
                logger.info(f"  [--] {name} -> {getattr(self, name).env_var} (未设置)")
        return status

    def get_available_llm(self) -> Optional[str]:
        for provider in ["openai_api", "anthropic_api", "deepseek_api", "zhipu_api", "moonshot_api"]:
            cred = getattr(self, provider)
            if cred.available:
                return provider.replace("_api", "")
        return None

    def get_llm_credentials(self) -> Optional[Dict]:
        cred_map = {
            "openai": ("openai_api", "https://api.openai.com/v1", "gpt-4o"),
            "anthropic": ("anthropic_api", "https://api.anthropic.com", "claude-sonnet-4-6"),
            "deepseek": ("deepseek_api", "https://api.deepseek.com/v1", "deepseek-v4-flash"),
            "zhipu": ("zhipu_api", "https://open.bigmodel.cn/api/paas/v4", "glm-4"),
            "moonshot": ("moonshot_api", "https://api.moonshot.cn/v1", "moonshot-v1-8k"),
        }
        # 优先使用配置的provider，如果不可用则自动选择第一个可用的
        preferred = self.llm_provider
        if preferred in cred_map:
            field_name, base_url, default_model = cred_map[preferred]
            cred = getattr(self, field_name)
            if cred.available:
                model = self.llm_model if self.llm_model != "gpt-4o" else default_model
                return {"api_key": cred.key, "base_url": base_url, "provider": preferred, "model": model}
        # 回退：自动选择任意可用provider
        for provider, (field_name, base_url, default_model) in cred_map.items():
            cred = getattr(self, field_name)
            if cred.available:
                logger.info(f"LLM provider自动选择: {provider} (配置的{preferred}不可用)")
                model = self.llm_model if self.llm_model != "gpt-4o" else default_model
                return {"api_key": cred.key, "base_url": base_url, "provider": provider, "model": model}
        return None


# 环境变量设置向导
ENV_SETUP_GUIDE = """
============================================================
D03 Real API — 环境变量配置指南
============================================================

在终端中设置以下环境变量（或在 .env 文件中）:

--- LLM APIs (至少设置一个) ---
set OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx
set DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set ZHIPU_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set MOONSHOT_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

--- 威胁情报 APIs ---
set VIRUSTOTAL_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set ABUSEIPDB_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set SHODAN_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set ALIENVAULT_OTX_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set URLSCAN_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

--- 安全工具 ---
set DOCKER_HOST=tcp://localhost:2375
set ELASTICSEARCH_URL=http://localhost:9200

免费API获取链接:
  - VirusTotal:  https://www.virustotal.com/gui/my-apikey
  - AbuseIPDB:   https://www.abuseipdb.com/account/api
  - Shodan:      https://account.shodan.io/
  - AlienVault:  https://otx.alienvault.com/api
  - URLScan:     https://urlscan.io/user/profile/
============================================================
"""

if __name__ == "__main__":
    config = RealAPIConfig()
    print(ENV_SETUP_GUIDE)
    print("\n当前API状态:")
    status = config.refresh_all()
    llm = config.get_available_llm()
    print(f"\n可用LLM: {llm or '无 (请设置至少一个LLM API密钥)'}")
