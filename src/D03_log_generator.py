"""
D03 Company-Level Log Generator
================================
基于沙盘对抗事件生成企业级安全日志，覆盖9大日志源。
格式参考真实企业SIEM (Splunk/ELK/Suricata/Sysmon风格)。
"""
import json, time, random
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

LOG_DIR = Path(__file__).parent / "company_logs"

USERS = [f"user_{i:02d}" for i in range(1, 31)]
WORKSTATIONS = [f"WKS{i:04d}" for i in range(1, 26)]
SERVERS = {
    "DC01": "10.0.0.1", "FS01": "10.0.0.2", "EX01": "10.0.0.3",
    "SQL01": "10.0.0.4", "WEB01": "10.0.1.10", "WEB02": "10.0.1.11",
    "SCADA": "172.16.1.10",
}
EXTERNAL_IPS = ["203.0.113.1", "203.0.113.2", "203.0.113.3", "45.155.205.233",
                "194.26.29.114", "185.130.5.253"]

class CompanyLogGenerator:
    """企业级安全日志生成器"""

    def __init__(self, org_size: int = 50):
        self.org_size = org_size
        self.base_time = datetime.now().replace(microsecond=0)
        self.event_counters = defaultdict(int)
        LOG_DIR.mkdir(exist_ok=True)

    def _ts(self, offset_s: float = 0) -> str:
        return (self.base_time + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def generate_round_logs(self, round_num: int, attack: dict, defense: dict,
                            org: dict, security_score: int) -> dict:
        """生成一轮沙盘对应的完整企业日志"""
        logs = {}
        t_base = round_num * 3600  # 每轮模拟1小时

        # === 1. auth.log — 认证事件 ===
        auth_lines = []
        # 正常用户登录
        for _ in range(self.org_size):
            u = random.choice(USERS)
            srv = random.choice(list(SERVERS.keys()))
            success = random.random() < 0.95
            eid = 4624 if success else 4625
            auth_lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} {srv} Security '
                f'EventID={eid} Account={u} SrcIP=10.0.2.{random.randint(1,50)} '
                f'AuthPackage=Kerberos Status={"SUCCESS" if success else "FAILED"}'
            )
        # 如果检测到攻击，加入可疑认证
        if defense.get("attack_detected"):
            att_vectors = attack.get("attack_vectors", [])
            if any("T1078" in v or "T1110" in v for v in att_vectors):
                for _ in range(random.randint(3, 8)):
                    auth_lines.append(
                        f'{self._ts(t_base + random.uniform(1800, 3600))} DC01 Security '
                        f'EventID=4625 Account=Administrator SrcIP=10.0.2.{random.randint(50,99)} '
                        f'AuthPackage=NTLM Status=FAILED Reason=UnknownUser'
                    )
        logs["auth"] = auth_lines

        # === 2. dns.log — DNS查询 ===
        dns_lines = []
        normal_domains = ["google.com", "microsoft.com", "github.com", "amazon.com",
                          "corp.local", "outlook.office365.com", "update.windows.com"]
        suspicious_domains = ["c2-beacon.xyz", "exfil-dns.net", "phish-login.net",
                              "emotet-malware.xyz", "cobalt-strike-beacon.xyz"]
        for _ in range(self.org_size * 3):
            dom = random.choice(normal_domains)
            dns_lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} DNS-01 query A {dom} '
                f'from 10.0.2.{random.randint(1,50)} response=NOERROR'
            )
        # 攻击相关DNS
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 5)):
                dom = random.choice(suspicious_domains)
                dns_lines.append(
                    f'{self._ts(t_base + random.uniform(1800, 3600))} DNS-01 query AAAA {dom} '
                    f'from 10.0.2.{random.randint(1,50)} response=NOERROR'
                )
        logs["dns"] = dns_lines

        # === 3. email.log — 邮件网关 ===
        email_lines = []
        normal_senders = ["noreply@corp.com", "hr@corp.com", "it@corp.com",
                          "notifications@github.com", "alerts@splunk.corp.com"]
        phish_senders = ["urgent@ceo-phish.com", "invoice@fake-bill.net",
                         "support@micosoft-secure.com", "admin@corp-portal.xyz"]
        for _ in range(self.org_size):
            sender = random.choice(normal_senders)
            u = random.choice(USERS)
            email_lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} EMAIL-GW '
                f'from={sender} to={u}@corp.com verdict=CLEAN spf=PASS'
            )
        # 钓鱼邮件
        att_vectors = attack.get("attack_vectors", [])
        if any("T1566" in v for v in att_vectors):
            for _ in range(random.randint(3, 6)):
                sender = random.choice(phish_senders)
                u = random.choice(USERS)
                clicked = random.random() < 0.3
                verdict = "PHISH_CLICKED" if clicked else "PHISH"
                email_lines.append(
                    f'{self._ts(t_base + random.uniform(600, 2400))} EMAIL-GW '
                    f'from={sender} to={u}@corp.com verdict={verdict} spf=FAIL'
                )
        logs["email"] = email_lines

        # === 4. endpoint.log — 终端事件 (Sysmon) ===
        ep_lines = []
        for _ in range(self.org_size // 2):
            wk = random.choice(WORKSTATIONS)
            u = random.choice(USERS)
            eid = random.choice([1, 3, 11, 22])
            if eid == 1:
                detail = random.choice(["cmd.exe /c whoami", "powershell.exe -enc ...",
                                        "wmic process list brief", "reg query HKLM\\Software"])
            elif eid == 3:
                detail = f"outbound to {random.choice(EXTERNAL_IPS)}"
            elif eid == 11:
                detail = f"FileCreate C:\\Users\\{u}\\Downloads\\{random.choice(['invoice','report','update'])}.exe"
            else:
                detail = f"DNS query suspicious-domain.xyz"
            ep_lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} {wk} Sysmon '
                f'EventID={eid} ProcessCreate User=CORP/{u} Details="{detail}"'
            )
        # 攻击端点事件
        if attack.get("initial_access_success"):
            compromised = random.sample(WORKSTATIONS, min(3, len(WORKSTATIONS)))
            for wk in compromised:
                u = random.choice(USERS)
                ep_lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} {wk} Sysmon '
                    f'EventID=8 CreateRemoteThread User=CORP/{u} '
                    f'Details="powershell.exe -> lsass.exe"'
                )
                ep_lines.append(
                    f'{self._ts(t_base + random.uniform(2600, 3600))} {wk} Sysmon '
                    f'EventID=3 NetworkConnect User=CORP/{u} '
                    f'Details="outbound to {random.choice(EXTERNAL_IPS[:3])}"'
                )
        logs["endpoint"] = ep_lines

        # === 5. firewall.log — 防火墙流量 ===
        fw_lines = []
        for _ in range(self.org_size * 5):
            src = f"10.0.{random.randint(0,2)}.{random.randint(1,50)}"
            dst_srv = random.choice(list(SERVERS.values()))
            port = random.choice([80, 443, 22, 3389, 445, 8080, 1433, 3306, 53])
            proto = "tcp" if port != 53 else "udp"
            b = random.randint(100, 500000)
            action = "ALLOW" if random.random() < 0.92 else "DENY"
            fw_lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} FW-01 TRAFFIC {action} '
                f'{src}:{random.randint(30000,60000)} -> {dst_srv}:{port} proto={proto} bytes={b}'
            )
        # 攻击流量
        if attack.get("initial_access_success"):
            for _ in range(random.randint(5, 10)):
                dst = random.choice(list(SERVERS.values()))
                fw_lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} FW-01 TRAFFIC ALLOW '
                    f'{random.choice(EXTERNAL_IPS[:3])}:{random.randint(40000,60000)} '
                    f'-> {dst}:445 proto=tcp bytes={random.randint(1000, 200000)}'
                )
        logs["firewall"] = fw_lines

        # === 6. ids.log — IDS/IPS (Suricata风格) ===
        ids_lines = []
        ids_rules = [
            ("2032158", "ET EXPLOIT EternalBlue SMB", 1),
            ("2809154", "ET CNC Sliver C2 Traffic", 3),
            ("2024366", "ET TROJAN CobaltStrike Beacon", 3),
            ("2017910", "ET SCAN OpenSSL Heartbleed", 1),
            ("2028915", "ET MALWARE Emotet C2 Communication", 2),
            ("2045123", "ET WEB SQL Injection Attempt", 2),
            ("2809120", "ET POLICY DNS Query to Dynamic DNS", 2),
        ]
        for _ in range(len(ids_rules) * 2):
            rid, desc, pri = random.choice(ids_rules)
            src = random.choice(EXTERNAL_IPS)
            dst = random.choice(list(SERVERS.values()))
            port = random.choice([80, 443, 445, 3389, 8080, 53])
            status = "DETECTED" if random.random() < 0.7 else "MISSED"
            ids_lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} SURICATA [{rid}] '
                f'{desc} [Priority:{pri}] {src}:{random.randint(30000,60000)} '
                f'-> {dst}:{port} [{status}]'
            )
        # 攻击期间IDS命中增加
        if attack.get("initial_access_success"):
            for _ in range(random.randint(4, 8)):
                rid, desc, pri = random.choice(ids_rules[:4])
                src = random.choice(EXTERNAL_IPS[:3])
                dst = random.choice(list(SERVERS.values()))
                ids_lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} SURICATA [{rid}] '
                    f'{desc} [Priority:{pri}] {src}:{random.randint(40000,60000)} '
                    f'-> {dst}:{random.choice([445,443,80])} [DETECTED]'
                )
        logs["ids"] = ids_lines

        # === 7. netflow.log — 网络流摘要 ===
        total_flows = random.randint(50000, 100000)
        anomaly = round(random.uniform(0.5, 3.0), 1)
        if attack.get("initial_access_success"):
            anomaly += random.uniform(5.0, 15.0)
        logs["netflow"] = [
            f'{self._ts(t_base + 3599)} NETFLOW total_flows={total_flows} '
            f'anomaly_score={anomaly:.1f} top_talkers='
            f'{",".join(f"{ip}:{random.randint(100,2000)}MB" for ip in random.sample(list(SERVERS.values()), 3))}'
        ]

        # === 8. proxy.log — Web代理 ===
        proxy_lines = []
        categories = ["Business/IT", "Social", "Cloud", "News", "Shopping", "Unknown"]
        urls = ["https://github.com/corp/repo", "https://docs.microsoft.com",
                "https://outlook.office365.com", "https://slack.com",
                "https://dropbox.com/path", "https://drive.google.com"]
        for _ in range(self.org_size * 2):
            u = random.choice(USERS)
            url = random.choice(urls)
            cat = random.choice(categories)
            proxy_lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} PROXY-01 10.0.2.{random.randint(1,50)} '
                f'CORP/{u} GET {url} 200 category={cat}'
            )
        # 可疑代理流量
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 4)):
                u = random.choice(USERS)
                proxy_lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} PROXY-01 10.0.2.{random.randint(1,50)} '
                    f'CORP/{u} POST https://{random.choice(["pastebin.com","webhook.site","ngrok.io"])}/data '
                    f'200 category=Unknown bytes={random.randint(10000, 500000)}'
                )
        logs["proxy"] = proxy_lines

        # === 9. siem.log — SIEM关联告警 ===
        siem_lines = []
        baseline_alerts = [
            ("MEDIUM", "Multiple Failed Logins", "INVESTIGATING", "SOC-Tier2"),
            ("LOW", "Unusual DNS Query Volume", "MONITORING", "SOC-Tier1"),
        ]
        for sev, desc, status, assigned in baseline_alerts:
            siem_lines.append(
                f'{self._ts(t_base + random.uniform(0, 1800))} SIEM-ALERT [{sev}] '
                f'{desc} Status={status} Assigned={assigned}'
            )
        # 攻击相关SIEM告警
        if defense.get("attack_detected"):
            att_vectors = attack.get("attack_vectors", [])
            if any("T1566" in v for v in att_vectors):
                siem_lines.append(
                    f'{self._ts(t_base + random.uniform(600, 1200))} SIEM-ALERT [HIGH] '
                    f'Phishing Campaign Detected Status=INVESTIGATING Assigned=SOC-Tier3 '
                    f'Details="Multiple users clicked phishing email from urgent@ceo-phish.com"'
                )
            if any("T1059" in v or "T1204" in v for v in att_vectors):
                siem_lines.append(
                    f'{self._ts(t_base + random.uniform(1800, 2700))} SIEM-ALERT [HIGH] '
                    f'Lateral Movement Detected Status=INVESTIGATING Assigned=SOC-Tier3 '
                    f'Details="Suspicious SMB traffic from compromised workstation"'
                )
            siem_lines.append(
                f'{self._ts(t_base + random.uniform(2700, 3500))} SIEM-ALERT [CRITICAL] '
                f'C2 Beacon Detected Status=INVESTIGATING Assigned=SOC-Tier2 '
                f'Details="JA3 fingerprint anomaly + periodic beacon to {random.choice(EXTERNAL_IPS[:3])}"'
            )
        logs["siem"] = siem_lines

        return logs

    def write_logs(self, round_num: int, logs: dict, session_id: str):
        """写入日志文件"""
        round_dir = LOG_DIR / session_id / f"round_{round_num:02d}"
        round_dir.mkdir(parents=True, exist_ok=True)
        for name, lines in logs.items():
            path = round_dir / f"{name}.log"
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(lines)) + '\n')
        return round_dir

    def generate_summary(self, all_round_logs: list, session_id: str) -> dict:
        """生成跨轮次日志摘要"""
        summary = {
            "session_id": session_id,
            "total_rounds": len(all_round_logs),
            "total_events": sum(
                sum(len(v) for v in r.values()) for r in all_round_logs),
            "by_source": {},
            "attack_timeline": [],
        }
        for r in all_round_logs:
            for src, lines in r.items():
                summary["by_source"][src] = summary["by_source"].get(src, 0) + len(lines)
        return summary


if __name__ == "__main__":
    # 演示: 生成3轮日志
    gen = CompanyLogGenerator(org_size=40)
    attack = {
        "attack_vectors": ["T1566.001", "T1204.002", "T1059.001", "T1021.002"],
        "initial_access_success": True,
    }
    defense = {"attack_detected": True, "mtd_triggered": True}
    org = {"mfa_enforced": True, "network_segmentation": "moderate"}

    for r in range(1, 4):
        attack["initial_access_success"] = (r >= 2)
        logs = gen.generate_round_logs(r, attack, defense, org, 50 + r * 10)
        gen.write_logs(r, logs, "demo_session")
        print(f"Round {r}: {sum(len(v) for v in logs.values())} events across {len(logs)} sources")

    print(f"\nLogs written to: {LOG_DIR / 'demo_session'}")
    for logfile in sorted((LOG_DIR / "demo_session" / "round_01").iterdir()):
        lines = logfile.read_text(encoding='utf-8').count('\n')
        print(f"  {logfile.name}: {lines} events")
