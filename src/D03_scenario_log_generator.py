"""
D03 Scenario Log Generator — 通用安全场景日志生成器

根据 ScenarioSpec 动态生成多场景安全日志。
支持 20+ 种日志源，覆盖企业/高校/医院/工控/云原生/电商等场景。
保持与 CompanyLogGenerator 接口兼容。
"""
import json, time, random
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional

from D03_scenario_spec import ScenarioSpec


LOG_DIR = Path(__file__).parent.parent / "output" / "scenario_logs"


class ScenarioLogGenerator:
    """通用场景安全日志生成器"""

    def __init__(self, scenario: ScenarioSpec = None, org_size: int = None):
        """
        初始化日志生成器。
        可通过 scenario 或 org_size 两种方式初始化，保持向下兼容。
        """
        self.org_size = org_size or (scenario.organization_size if scenario else 50)
        self.scenario = scenario
        self.base_time = datetime.now().replace(microsecond=0)
        self.event_counters = defaultdict(int)
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        # 从场景提取角色/资产/IP
        self._users = self._extract_users()
        self._assets = self._extract_assets()
        self._internal_ips = [a.get("ip", "") for a in self._assets if a.get("ip")]
        self._external_ips = ["203.0.113.1", "203.0.113.2", "203.0.113.3",
                              "45.155.205.233", "194.26.29.114", "185.130.5.253"]

    def _extract_users(self) -> List[str]:
        """从场景 actors 提取用户名"""
        if not self.scenario or not self.scenario.actors:
            return [f"user_{i:02d}" for i in range(1, max(self.org_size // 5, 10) + 1)]
        users = []
        for a in self.scenario.actors:
            if a.type in ("user", "admin"):
                users.append(f"{a.role_id}_{random.randint(1, max(self.org_size // 5, 5))}")
        return users or [f"user_{i:02d}" for i in range(1, max(self.org_size // 5, 10) + 1)]

    def _extract_assets(self) -> List[Dict]:
        """从场景 assets 提取资产信息"""
        if not self.scenario or not self.scenario.assets:
            return [
                {"name": "DC01", "ip": "10.0.0.1", "type": "server"},
                {"name": "FS01", "ip": "10.0.0.2", "type": "server"},
                {"name": "SQL01", "ip": "10.0.0.4", "type": "database"},
                {"name": "WEB01", "ip": "10.0.1.10", "type": "server"},
            ]
        return [
            {"name": a.name.replace(" ", "_")[:15],
             "ip": a.ip or f"10.0.0.{100 + i}",
             "type": a.asset_type}
            for i, a in enumerate(self.scenario.assets)
        ]

    def _ts(self, offset_s: float = 0) -> str:
        return (self.base_time + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _domain(self) -> str:
        if not self.scenario:
            return "corp.local"
        return f"{self.scenario.domain}.local"

    def _org_prefix(self) -> str:
        if not self.scenario:
            return "CORP"
        return self.scenario.domain.upper()[:8]

    def generate_round_logs(self, round_num: int, attack: dict, defense: dict,
                            org: dict, security_score: int) -> dict:
        """生成一轮沙盘对应的完整日志"""
        logs = {}
        t_base = round_num * 3600
        enabled = self.scenario.get_enabled_log_sources() if self.scenario else [
            "auth", "dns", "email", "endpoint", "firewall", "ids", "netflow", "proxy", "siem"
        ]

        # 根据启用的日志源分发
        for source in enabled:
            method = getattr(self, f"_gen_{source}", None)
            if method:
                logs[source] = method(t_base, attack, defense, org, security_score)

        return logs

    # ================================================================
    # 各日志源生成方法
    # ================================================================

    def _gen_auth(self, t_base, attack, defense, org, score):
        lines = []
        prefix = self._org_prefix()
        assets = self._assets
        for _ in range(self.org_size):
            u = random.choice(self._users)
            srv = random.choice(assets) if assets else {"name": "SRV01"}
            success = random.random() < 0.95
            eid = 4624 if success else 4625
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} {srv["name"]} Security '
                f'EventID={eid} Account={u} SrcIP=10.0.{random.randint(1,3)}.{random.randint(1,50)} '
                f'AuthPackage=Kerberos Status={"SUCCESS" if success else "FAILED"}'
            )
        if defense.get("attack_detected"):
            for _ in range(random.randint(3, 6)):
                srv = random.choice(assets) if assets else {"name": "SRV01"}
                lines.append(
                    f'{self._ts(t_base + random.uniform(1800, 3600))} {srv["name"]} Security '
                    f'EventID=4625 Account=Administrator SrcIP=10.0.{random.randint(1,3)}.{random.randint(50,99)} '
                    f'AuthPackage=NTLM Status=FAILED Reason=UnknownUser'
                )
        return lines

    def _gen_sso(self, t_base, attack, defense, org, score):
        """SSO/SAML 单点登录日志 — 高校等场景"""
        lines = []
        for _ in range(self.org_size // 3):
            u = random.choice(self._users)
            success = random.random() < 0.93
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} SSO-SERVER SAML AuthRequest '
                f'user={u} SP="https://portal.{self._domain()}" Status={"OK" if success else "FAILED"} '
                f'Assertion={"VALID" if success else "EXPIRED"}'
            )
        if defense.get("attack_detected"):
            for _ in range(random.randint(2, 4)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2000, 3600))} SSO-SERVER SAML AuthRequest '
                    f'user=admin SP="https://admin.{self._domain()}" Status=FAILED Assertion=FORGED'
                )
        return lines

    def _gen_dns(self, t_base, attack, defense, org, score):
        domain = self._domain()
        normal_domains = ["google.com", "microsoft.com", "github.com", "amazon.com",
                          domain, "outlook.office365.com", "update.windows.com"]
        suspicious_domains = ["c2-beacon.xyz", "exfil-dns.net", "phish-login.net",
                              "emotet-malware.xyz", "cobalt-strike-beacon.xyz"]
        lines = []
        for _ in range(self.org_size * 3):
            dom = random.choice(normal_domains)
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} DNS-01 query A {dom} '
                f'from 10.0.{random.randint(1,5)}.{random.randint(1,50)} response=NOERROR'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 5)):
                dom = random.choice(suspicious_domains)
                lines.append(
                    f'{self._ts(t_base + random.uniform(1800, 3600))} DNS-01 query AAAA {dom} '
                    f'from 10.0.{random.randint(1,5)}.{random.randint(1,50)} response=NOERROR'
                )
        return lines

    def _gen_email(self, t_base, attack, defense, org, score):
        domain = self._domain()
        normal_senders = [f"noreply@{domain}", f"hr@{domain}", f"it@{domain}",
                          "notifications@github.com", f"alerts@{domain}"]
        phish_senders = ["urgent@ceo-phish.com", "invoice@fake-bill.net",
                         "support@micosoft-secure.com", f"admin@{domain}-portal.xyz"]
        lines = []
        for _ in range(self.org_size):
            sender = random.choice(normal_senders)
            u = random.choice(self._users)
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} EMAIL-GW '
                f'from={sender} to={u}@{domain} verdict=CLEAN spf=PASS'
            )
        if any("T1566" in v or "phishing" in str(v).lower() for v in attack.get("attack_vectors", [])):
            for _ in range(random.randint(3, 6)):
                sender = random.choice(phish_senders)
                u = random.choice(self._users)
                clicked = random.random() < 0.3
                verdict = "PHISH_CLICKED" if clicked else "PHISH"
                lines.append(
                    f'{self._ts(t_base + random.uniform(600, 2400))} EMAIL-GW '
                    f'from={sender} to={u}@{domain} verdict={verdict} spf=FAIL'
                )
        return lines

    def _gen_endpoint(self, t_base, attack, defense, org, score):
        prefix = self._org_prefix()
        lines = []
        workstations = [a["name"] for a in self._assets if a["type"] == "endpoint"]
        if not workstations:
            workstations = [f"WKS{i:04d}" for i in range(1, 10)]
        for _ in range(self.org_size // 2):
            wk = random.choice(workstations)
            u = random.choice(self._users)
            eid = random.choice([1, 3, 11, 22])
            if eid == 1:
                detail = random.choice(["cmd.exe /c whoami", "powershell.exe -enc ...",
                                        "wmic process list brief", "reg query HKLM\\Software"])
            elif eid == 3:
                detail = f"outbound to {random.choice(self._external_ips)}"
            elif eid == 11:
                detail = f"FileCreate C:\\Users\\{u}\\Downloads\\{random.choice(['invoice','report','update'])}.exe"
            else:
                detail = "DNS query suspicious-domain.xyz"
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} {wk} Sysmon '
                f'EventID={eid} ProcessCreate User={prefix}/{u} Details="{detail}"'
            )
        if attack.get("initial_access_success"):
            for wk in workstations[:3]:
                u = random.choice(self._users)
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} {wk} Sysmon '
                    f'EventID=8 CreateRemoteThread User={prefix}/{u} '
                    f'Details="powershell.exe -> lsass.exe"'
                )
        return lines

    def _gen_firewall(self, t_base, attack, defense, org, score):
        lines = []
        assets = self._assets
        for _ in range(self.org_size * 5):
            src_asset = random.choice(assets) if assets else {"ip": "10.0.1.1"}
            dst_asset = random.choice(assets) if assets else {"ip": "10.0.0.4"}
            src_ip = src_asset.get("ip", "10.0.1.1").split("/")[0]
            dst_ip = dst_asset.get("ip", "10.0.0.4").split("/")[0]
            port = random.choice([80, 443, 22, 3389, 445, 8080, 1433, 3306, 53])
            proto = "tcp" if port != 53 else "udp"
            b = random.randint(100, 500000)
            action = "ALLOW" if random.random() < 0.92 else "DENY"
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} FW-01 TRAFFIC {action} '
                f'{src_ip}:{random.randint(30000,60000)} -> {dst_ip}:{port} proto={proto} bytes={b}'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(5, 10)):
                dst_asset = random.choice(assets) if assets else {"ip": "10.0.0.4"}
                dst_ip = dst_asset.get("ip", "10.0.0.4").split("/")[0]
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} FW-01 TRAFFIC ALLOW '
                    f'{random.choice(self._external_ips[:3])}:{random.randint(40000,60000)} '
                    f'-> {dst_ip}:445 proto=tcp bytes={random.randint(1000, 200000)}'
                )
        return lines

    def _gen_ids(self, t_base, attack, defense, org, score):
        lines = []
        ids_rules = [
            ("2032158", "ET EXPLOIT EternalBlue SMB", 1),
            ("2809154", "ET CNC Sliver C2 Traffic", 3),
            ("2024366", "ET TROJAN CobaltStrike Beacon", 3),
            ("2017910", "ET SCAN OpenSSL Heartbleed", 1),
            ("2028915", "ET MALWARE Emotet C2 Communication", 2),
            ("2045123", "ET WEB SQL Injection Attempt", 2),
        ]
        assets = self._assets
        for _ in range(len(ids_rules) * 2):
            rid, desc, pri = random.choice(ids_rules)
            src = random.choice(self._external_ips)
            dst_asset = random.choice(assets) if assets else {"ip": "10.0.0.4"}
            dst_ip = dst_asset.get("ip", "10.0.0.4").split("/")[0]
            port = random.choice([80, 443, 445, 3389, 8080, 53])
            status = "DETECTED" if random.random() < 0.7 else "MISSED"
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} SURICATA [{rid}] '
                f'{desc} [Priority:{pri}] {src}:{random.randint(30000,60000)} '
                f'-> {dst_ip}:{port} [{status}]'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(4, 8)):
                rid, desc, pri = random.choice(ids_rules[:4])
                dst_asset = random.choice(assets) if assets else {"ip": "10.0.0.4"}
                dst_ip = dst_asset.get("ip", "10.0.0.4").split("/")[0]
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} SURICATA [{rid}] '
                    f'{desc} [Priority:{pri}] {random.choice(self._external_ips[:3])}:{random.randint(40000,60000)} '
                    f'-> {dst_ip}:{random.choice([445,443,80])} [DETECTED]'
                )
        return lines

    def _gen_netflow(self, t_base, attack, defense, org, score):
        assets = self._assets
        ips = [a["ip"].split("/")[0] for a in assets if a.get("ip")]
        if not ips:
            ips = ["10.0.0.1", "10.0.0.2", "10.0.1.10"]
        total_flows = random.randint(50000, 100000)
        anomaly = round(random.uniform(0.5, 3.0), 1)
        if attack.get("initial_access_success"):
            anomaly += random.uniform(5.0, 15.0)
        top_talkers = ",".join(f"{ip}:{random.randint(100,2000)}MB" for ip in random.sample(ips, min(3, len(ips))))
        return [
            f'{self._ts(t_base + 3599)} NETFLOW total_flows={total_flows} '
            f'anomaly_score={anomaly:.1f} top_talkers={top_talkers}'
        ]

    def _gen_siem(self, t_base, attack, defense, org, score):
        lines = []
        baseline_alerts = [
            ("MEDIUM", f"Multiple Failed Logins on {self._domain()}", "INVESTIGATING", "SOC-Tier2"),
            ("LOW", "Unusual DNS Query Volume", "MONITORING", "SOC-Tier1"),
        ]
        for sev, desc, status, assigned in baseline_alerts:
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 1800))} SIEM-ALERT [{sev}] '
                f'{desc} Status={status} Assigned={assigned}'
            )
        if defense.get("attack_detected"):
            lines.append(
                f'{self._ts(t_base + random.uniform(600, 1200))} SIEM-ALERT [HIGH] '
                f'Phishing Campaign Detected Status=INVESTIGATING Assigned=SOC-Tier3'
            )
            lines.append(
                f'{self._ts(t_base + random.uniform(1800, 2700))} SIEM-ALERT [CRITICAL] '
                f'C2 Beacon Detected Status=INVESTIGATING Assigned=SOC-Tier2 '
                f'Details="Periodic beacon to {random.choice(self._external_ips[:3])}"'
            )
        return lines

    def _gen_proxy(self, t_base, attack, defense, org, score):
        prefix = self._org_prefix()
        lines = []
        categories = ["Business/IT", "Social", "Cloud", "News", "Shopping", "Unknown"]
        urls = ["https://github.com", "https://docs.microsoft.com",
                "https://outlook.office365.com", "https://slack.com"]
        for _ in range(self.org_size * 2):
            u = random.choice(self._users)
            url = random.choice(urls)
            cat = random.choice(categories)
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} PROXY-01 10.0.{random.randint(1,5)}.{random.randint(1,50)} '
                f'{prefix}/{u} GET {url} 200 category={cat}'
            )
        return lines

    # --- 扩展日志源 ---

    def _gen_database(self, t_base, attack, defense, org, score):
        """数据库审计日志 — 医院/电商/企业"""
        lines = []
        assets = [a for a in self._assets if a["type"] == "database"]
        if not assets:
            assets = [{"name": "DB01", "ip": "10.0.0.4"}]
        for _ in range(self.org_size):
            db = random.choice(assets)
            u = random.choice(self._users)
            op = random.choice(["SELECT", "INSERT", "UPDATE", "DELETE"])
            table = random.choice(["patients", "orders", "users", "inventory", "records"])
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} DB-AUDIT {db["name"]} '
                f'User={u} Operation={op} Table={table} Rows={random.randint(1,100)} Status=OK'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 5)):
                db = random.choice(assets)
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} DB-AUDIT {db["name"]} '
                    f'User=elevated_user Operation=SELECT Table=* Rows={random.randint(1000,50000)} Status=ANOMALY'
                )
        return lines

    def _gen_medical_system(self, t_base, attack, defense, org, score):
        """医疗系统日志 — 医院场景"""
        lines = []
        med_assets = [a["name"] for a in self._assets if "his" in a["name"].lower() or "pacs" in a["name"].lower() or "emr" in a["name"].lower()]
        if not med_assets:
            med_assets = ["HIS", "PACS", "EMR"]
        roles = ["Doctor", "Nurse", "Admin"]
        for _ in range(self.org_size // 2):
            sys = random.choice(med_assets)
            role = random.choice(roles)
            action = random.choice(["PatientRecordAccess", "OrderEntry", "LabResultView", "PrescriptionCreate"])
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} MED-SYS {sys} '
                f'User={random.choice(self._users)} Role={role} Action={action} Status=OK'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 4)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} MED-SYS {random.choice(med_assets)} '
                    f'User=unknown Role=UNKNOWN Action=MassRecordExport Records={random.randint(100,1000)} Status=ALERT'
                )
        return lines

    def _gen_scada(self, t_base, attack, defense, org, score):
        """SCADA 日志 — 工控场景"""
        lines = []
        points = ["TEMP_SENSOR_01", "PRESSURE_VALVE_A", "MOTOR_SPEED_B", "FLOW_METER_03", "LEVEL_SENSOR_TK01"]
        for _ in range(self.org_size // 2):
            pt = random.choice(points)
            val = round(random.uniform(20.0, 120.0), 2)
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} SCADA TAG:{pt} '
                f'Value={val} Quality=GOOD Timestamp={self._ts(t_base + random.uniform(0, 3599))}'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(3, 6)):
                pt = random.choice(points)
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} SCADA TAG:{pt} '
                    f'Value={random.choice([999.9,0.0,-99.9])} Quality=BAD Timestamp={self._ts(t_base)} ABNORMAL'
                )
        return lines

    def _gen_plc(self, t_base, attack, defense, org, score):
        """PLC 控制器日志 — 工控场景"""
        lines = []
        plcs = [a["name"] for a in self._assets if a["type"] == "plc"] or ["PLC_01", "PLC_02"]
        for plc in plcs:
            for _ in range(random.randint(5, 10)):
                cmd = random.choice(["START", "STOP", "RESET", "SPEED_SET", "READ_STATUS"])
                reg = random.choice(["MW100", "DB1.DBW0", "I0.0", "Q0.1", "MW200"])
                lines.append(
                    f'{self._ts(t_base + random.uniform(0, 3600))} {plc} MODBUS '
                    f'Command={cmd} Register={reg} Value={random.randint(0,65535)} Status=OK'
                )
        if attack.get("initial_access_success"):
            plc = random.choice(plcs)
            for _ in range(random.randint(2, 4)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} {plc} MODBUS '
                    f'Command=FORCE_STOP Register=Q0.0 Value=0 Status=UNAUTHORIZED'
                )
        return lines

    def _gen_cloud_audit(self, t_base, attack, defense, org, score):
        """云审计日志 — 云原生场景"""
        lines = []
        actions = ["CreateInstance", "DeleteBucket", "ModifyIAMPolicy", "AssumeRole",
                   "PutObject", "CreateContainer", "UpdateSecret", "DescribeInstances"]
        for _ in range(self.org_size):
            u = random.choice(self._users)
            act = random.choice(actions)
            resource = f"arn:aws:{random.choice(['ec2','s3','iam','k8s','lambda'])}::{random.randint(10000,99999)}"
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} CLOUD-TRAIL '
                f'User={u} Action={act} Resource={resource} SourceIP=10.4.{random.randint(1,3)}.{random.randint(1,50)} Status=OK'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 4)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} CLOUD-TRAIL '
                    f'User=temp_creds Action=ModifyIAMPolicy Resource=arn:aws:iam::* '
                    f'SourceIP={random.choice(self._external_ips[:3])} Status=PRIVILEGE_ESCALATION'
                )
        return lines

    def _gen_k8s_audit(self, t_base, attack, defense, org, score):
        """Kubernetes 审计日志 — 云原生场景"""
        lines = []
        verbs = ["create", "get", "list", "delete", "patch", "update"]
        resources = ["pods", "secrets", "configmaps", "deployments", "serviceaccounts", "roles"]
        namespaces = ["default", "kube-system", "production", "staging", "monitoring"]
        for _ in range(self.org_size):
            u = random.choice(self._users)
            verb = random.choice(verbs)
            res = random.choice(resources)
            ns = random.choice(namespaces)
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} K8S-AUDIT '
                f'User={u} Verb={verb} Resource={res} Namespace={ns} Status=Allowed'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 5)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} K8S-AUDIT '
                    f'User=compromised-sa Verb=create Resource=privileged-pod Namespace=kube-system Status=BLOCKED'
                )
        return lines

    def _gen_api_gateway(self, t_base, attack, defense, org, score):
        """API Gateway 日志 — 云原生/电商场景"""
        lines = []
        endpoints = ["/api/v1/orders", "/api/v1/users", "/api/v1/products",
                     "/api/v1/payments", "/api/v1/health", "/api/v1/auth/login"]
        methods = ["GET", "POST", "PUT", "DELETE"]
        for _ in range(self.org_size * 3):
            ep = random.choice(endpoints)
            method = random.choice(methods)
            status = random.choice([200, 200, 200, 200, 201, 400, 401, 403, 500])
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} API-GW '
                f'{method} {ep} Status={status} Latency={random.randint(5,200)}ms '
                f'Client={random.choice(self._external_ips)}'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(3, 8)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} API-GW '
                    f'POST /api/v1/auth/login Status=401 Latency=5ms '
                    f'Client={random.choice(self._external_ips[:3])} RateLimit=EXCEEDED'
                )
        return lines

    def _gen_payment(self, t_base, attack, defense, org, score):
        """支付系统日志 — 电商场景"""
        lines = []
        statuses = ["APPROVED", "DECLINED", "PENDING", "REFUNDED"]
        for _ in range(self.org_size // 2):
            status = random.choice(statuses)
            amount = round(random.uniform(9.99, 999.99), 2)
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} PAYMENT '
                f'TxnID=TXN{random.randint(100000,999999)} Amount=${amount:.2f} '
                f'Status={status} RiskScore={random.randint(0,100)}'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 5)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} PAYMENT '
                    f'TxnID=TXN{random.randint(100000,999999)} Amount=$0.01 '
                    f'Status=APPROVED RiskScore=95 FRAUD_FLAG=TRUE'
                )
        return lines

    def _gen_vpn(self, t_base, attack, defense, org, score):
        """VPN 日志 — 高校/企业场景"""
        lines = []
        for _ in range(self.org_size // 3):
            u = random.choice(self._users)
            success = random.random() < 0.9
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} VPN-GW '
                f'User={u} SrcIP={random.choice(["203.0.113.100","203.0.113.101","198.51.100.10"])} '
                f'AssignedIP=10.0.{random.randint(5,10)}.{random.randint(1,99)} '
                f'Auth={"OK" if success else "FAILED"}'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(2, 3)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} VPN-GW '
                    f'User=admin SrcIP={random.choice(self._external_ips[:3])} '
                    f'AssignedIP=10.0.1.1 Auth=OK ALERT=GEO_ANOMALY'
                )
        return lines

    def _gen_web(self, t_base, attack, defense, org, score):
        """Web 服务器访问日志 — 通用场景"""
        lines = []
        paths = ["/", "/login", "/api/data", "/images/logo.png", "/css/style.css",
                 "/dashboard", "/profile", "/search", "/docs", "/health"]
        ua = "Mozilla/5.0"
        for _ in range(self.org_size * 3):
            path = random.choice(paths)
            status = random.choice([200, 200, 200, 200, 200, 301, 404, 500])
            lines.append(
                f'{self._ts(t_base + random.uniform(0, 3600))} WEB {random.choice(self._external_ips)} '
                f'GET {path} HTTP/1.1 {status} {random.randint(100,50000)} "{ua}"'
            )
        if attack.get("initial_access_success"):
            for _ in range(random.randint(3, 6)):
                lines.append(
                    f'{self._ts(t_base + random.uniform(2400, 3600))} WEB {random.choice(self._external_ips[:3])} '
                    f'POST /api/admin/shell HTTP/1.1 200 {random.randint(100,500)} "{ua}" ALERT=CMD_INJECTION'
                )
        return lines

    def _gen_iot_device(self, t_base, attack, defense, org, score):
        """IoT 设备日志 — 医疗/工控场景"""
        lines = []
        devices = [a["name"] for a in self._assets if a["type"] in ("iot", "plc")]
        if not devices:
            devices = ["DEVICE_01", "DEVICE_02"]
        for dev in devices[:5]:
            for _ in range(random.randint(2, 5)):
                metric = random.choice(["temperature", "pressure", "rpm", "flow_rate", "battery"])
                val = round(random.uniform(20, 80), 1)
                lines.append(
                    f'{self._ts(t_base + random.uniform(0, 3600))} IOT {dev} '
                    f'Metric={metric} Value={val} Battery={random.randint(30,100)}% Status=ONLINE'
                )
        if attack.get("initial_access_success"):
            dev = random.choice(devices)
            lines.append(
                f'{self._ts(t_base + random.uniform(2400, 3600))} IOT {dev} '
                f'Metric=firmware_version Value=999.0 Status=TAMPERED'
            )
        return lines

    def write_logs(self, round_num: int, logs: dict, session_id: str):
        """写入日志文件"""
        round_dir = LOG_DIR / session_id / f"round_{round_num:02d}"
        round_dir.mkdir(parents=True, exist_ok=True)
        for name, lines in logs.items():
            path = round_dir / f"{name}.log"
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(str(l) for l in lines)) + '\n')
        return round_dir

    def generate_summary(self, all_round_logs: list, session_id: str) -> dict:
        """生成跨轮次日志摘要"""
        summary = {
            "session_id": session_id,
            "total_rounds": len(all_round_logs),
            "total_events": sum(
                sum(len(v) for v in r.values()) for r in all_round_logs),
            "by_source": {},
        }
        for r in all_round_logs:
            for src, lines in r.items():
                summary["by_source"][src] = summary["by_source"].get(src, 0) + len(lines)
        if self.scenario:
            summary["scenario_id"] = self.scenario.scenario_id
            summary["domain"] = self.scenario.domain
        return summary
