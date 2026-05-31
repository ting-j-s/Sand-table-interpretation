"""D03 Security Logger v2 - Enhanced realism based on real enterprise log comparison.
Fixes: IP diversity, EventID variety, port distribution, severity curve, log length variance.
"""
import random, json, time, os, math
from datetime import datetime
from collections import defaultdict, deque

class EnterpriseSecurityLoggerV2:
    """ 企业安全日志生成器v2：增强真实性。扩大的IP池(多网段)/11种Windows EventID/业务端口分布/严重度分级/realistic格式。 """
    def __init__(self, log_dir="production_logs/security_logs_v2", n_users=200):
        self.log_dir = log_dir; os.makedirs(log_dir, exist_ok=True)
        self.n_users = n_users; self.ep_counter = 0

        # Expanded network topology matching real enterprise
        self.servers = {
            "dc01": "10.0.1.10", "dc02": "10.0.1.11", "web01": "172.16.1.10",
            "web02": "172.16.1.11", "sql01": "10.0.3.10", "sql02": "10.0.3.11",
            "dns01": "10.0.0.53", "file01": "10.0.2.10", "mail01": "10.0.4.10",
            "jump01": "10.0.5.10", "mon01": "10.0.6.10", "k8s01": "10.0.7.10",
        }

        # Diverse external IPs (multiple ranges, not just one /24)
        self.external_ips = []
        # Cloud provider ranges
        for i in range(1, 50): self.external_ips.append("203.0.113.{}".format(i))
        for i in range(1, 30): self.external_ips.append("198.51.100.{}".format(i))
        for i in range(1, 25): self.external_ips.append("192.0.2.{}".format(i))
        # Residential/office ranges
        for i in range(1, 40): self.external_ips.append("{}.{}.{}.{}".format(
            random.randint(45, 200), random.randint(1, 250),
            random.randint(1, 250), random.randint(1, 250)))

        # User IPs with /24 subnets
        self.user_ips = {}
        for i in range(n_users):
            subnet = 2 + (i // 200)
            self.user_ips[i] = "10.0.{0}.{1}".format(subnet, 1 + (i % 200))

        # Realistic domain pool (business + malicious)
        self.domains = [
            "github.com", "office.com", "google.com", "amazonaws.com",
            "dropbox.com", "pastebin.com", "discord.com", "slack.com",
            "microsoft.com", "oracle.com", "salesforce.com", "zoom.us",
            "okta.com", "crowdstrike.com", "splunk.com", "servicenow.com",
            "atlassian.net", "cloudflare.com", "fastly.com", "akamai.net",
            "evil-c2.xyz", "phish-login.net", "malware-cdn.biz", "exfil-data.ru",
            "beacon-c2.co", "ransom-encrypt.cc", "cred-phish.top", "dropper-cdn.xyz",
        ]
        self.malicious = self.domains[-8:]

        # Expanded port pool matching real enterprise
        self.common_ports = [
            80, 443, 22, 3389, 445, 8080, 8443,  # web/RDP/SMB
            53, 25, 587, 993,  # DNS/mail
            3306, 5432, 1433,  # databases
            6379, 27017, 9090, 3000,  # NoSQL/monitoring
            5000, 8000, 9000,  # app servers
            389, 636, 3268,  # LDAP
            123, 161, 514,  # NTP/SNMP/syslog
        ]

        # Realistic EventID pool (Windows Security Log)
        self.auth_event_ids = [
            (4624, 0.45, "Logon"), (4625, 0.15, "LogonFailure"),
            (4634, 0.10, "Logoff"), (4648, 0.05, "ExplicitLogon"),
            (4672, 0.05, "SpecialLogon"), (4688, 0.08, "ProcessCreate"),
            (4768, 0.03, "TGTRequest"), (4776, 0.04, "CredentialValidate"),
            (5140, 0.02, "ShareAccess"), (5156, 0.02, "FilteringPlatform"),
            (1102, 0.01, "AuditLogClear"),
        ]

        # Sysmon-style event IDs
        self.endpoint_event_ids = [
            (1, 0.40, "ProcessCreate"), (3, 0.25, "NetworkConnect"),
            (7, 0.10, "ImageLoad"), (8, 0.08, "CreateRemoteThread"),
            (11, 0.05, "FileCreate"), (13, 0.05, "RegistrySet"),
            (22, 0.04, "DNSEvent"), (15, 0.03, "FileCreateStreamHash"),
        ]

        # Realistic log length distribution (bytes)
        self.log_len_dist = [
            (60, 0.10), (80, 0.15), (100, 0.25), (120, 0.20),
            (150, 0.12), (200, 0.08), (300, 0.05), (500, 0.03), (800, 0.02),
        ]

        self.log_files = {}
        for name in ["firewall", "auth", "dns", "ids", "endpoint", "proxy", "email", "siem", "netflow"]:
            path = os.path.join(log_dir, "{0}.log".format(name))
            self.log_files[name] = open(path, "w", encoding="utf-8", buffering=8192)

    def _ts(self):
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.") + "{0:03d}Z".format(random.randint(0, 999))

    def _wchoice(self, items):
        """Returns first element from weighted items=[(val, weight, ...), ...]"""
        total = sum(v[1] for v in items)
        r = random.uniform(0, total)
        cum = 0
        for v in items:
            cum += v[1]
            if r <= cum:
                return v[0]
        return items[-1][0]

    def _vary_len(self, base_str, target_len):
        """Pad or trim to target length with realistic noise."""
        current = len(base_str)
        if current < target_len:
            extra_fields = ["", " proto=TCP", " zone=external", " vsys=1",
                          " app=web-browsing", ' category="business-and-it"',
                          " src_geo=US dst_geo=US", " packets=1"]
            return base_str + random.choice(extra_fields) * ((target_len - current) // 30 + 1)
        return base_str

    def generate_episode_logs(self, orch, metrics, episode):
        self.ep_counter = episode
        ts = self._ts()
        atk = metrics.get("attack_success_rate", 0)
        det = sum(b.detection_rate for b in orch.blue_team) / max(1, len(orch.blue_team))
        nu = len(orch.users)
        self._firewall(ts, atk)
        self._auth(ts, atk)
        self._dns(ts, atk, det)
        self._ids(ts, atk, det)
        self._endpoint(ts, atk, nu)
        self._proxy(ts, nu)
        self._email(ts, metrics)
        self._siem(ts, atk, det, metrics)
        if episode % 10 == 0:
            self._netflow(ts, atk)

    def _firewall(self, ts, atk):
        # Real enterprise firewalls: ~80% ALLOW, ~20% DENY, with time-of-day variation
        n = random.randint(15, 60)
        for _ in range(n):
            src_is_internal = random.random() < 0.6
            if src_is_internal:
                src = random.choice(list(self.user_ips.values()))
            else:
                src = random.choice(self.external_ips)
            dst = random.choice(list(self.servers.values()))
            port = self._wchoice([
                (443, 0.30), (80, 0.20), (22, 0.08), (3389, 0.05),
                (445, 0.05), (8080, 0.04), (53, 0.06), (25, 0.03),
                (3306, 0.03), (8443, 0.03), (9090, 0.02), (5000, 0.02),
            ])

            # Realistic deny rate: higher for external->internal, sensitive ports
            deny_prob = 0.08
            if not src_is_internal:
                deny_prob = 0.25
            if port in [445, 3389, 22] and not src_is_internal:
                deny_prob = 0.60
            if atk > 0.4 and random.random() < atk * 0.3:
                deny_prob = 0.50

            action = "DENY" if random.random() < deny_prob else "ALLOW"
            proto = self._wchoice([("tcp", 0.85), ("udp", 0.12), ("icmp", 0.03)])
            bytes_sent = int(random.expovariate(1.0 / 5000) * 1000)

            log = "{0} FW-01 TRAFFIC {1} {2}:{3} -> {4}:{5} proto={6} bytes={7} src_zone={8} dst_zone=trust app={9}\n".format(
                ts, action, src, random.randint(1024, 65535), dst, port, proto, bytes_sent,
                random.choice(["untrust", "dmz", "vpn"]),
                random.choice(["web-browsing", "ssl", "ssh", "dns", "sql", "custom-app", "unknown-tcp"][:7]))
            self.log_files["firewall"].write(log)

    def _auth(self, ts, atk):
        n = random.randint(20, 80)
        for _ in range(n):
            uid = random.randint(0, self.n_users - 1)
            is_external = atk > 0.3 and random.random() < atk * 0.25
            src = random.choice(self.external_ips[:20]) if is_external else self.user_ips.get(uid, "10.0.5.100")
            eid = self._wchoice(self.auth_event_ids)
            success = eid in [4624, 4672, 4768]
            if is_external:
                success = random.random() < 0.15  # External auth usually fails
                eid = 4625 if not success else 4624

            logon_type = self._wchoice([
                (3, 0.45), (10, 0.20), (2, 0.10), (4, 0.08), (5, 0.07),
                (7, 0.05), (8, 0.03), (9, 0.02),
            ])
            auth_pkg = random.choice(["NTLM", "Kerberos", "Negotiate"])
            workstation = "WKS{0:04d}".format(uid) if random.random() < 0.3 else "-"

            log = "{0} DC01 Security EventID={1} Account=user_{2} SrcIP={3} LogonType={4} AuthPackage={5} Workstation={6} Status={7}\n".format(
                ts, eid, uid, src, logon_type, auth_pkg, workstation,
                "0x0" if success else "0xC000006A")
            self.log_files["auth"].write(log)

    def _dns(self, ts, atk, det):
        n = random.randint(30, 120)
        for _ in range(n):
            src = random.choice(list(self.user_ips.values()))
            domain = random.choice(self.domains)
            if atk > 0.4 and random.random() < 0.12:
                domain = random.choice(self.malicious)
            qtype = self._wchoice([
                ("A", 0.55), ("AAAA", 0.20), ("MX", 0.08), ("TXT", 0.05),
                ("CNAME", 0.05), ("SRV", 0.04), ("PTR", 0.03),
            ])
            resp = random.choice(["NOERROR", "NOERROR", "NOERROR", "NXDOMAIN", "SERVFAIL"])
            log = "{0} DNS-01 query {1} {2} from {3} response={4} ttl={5}\n".format(
                ts, qtype, domain, src, resp, random.randint(60, 86400))
            self.log_files["dns"].write(log)

    def _ids(self, ts, atk, det):
        sigs = [
            ("2017910", "ET SCAN", "OpenSSL Heartbleed", 2),
            ("2024366", "ET TROJAN", "CobaltStrike Beacon", 1),
            ("2809154", "ET CNC", "Sliver C2 Traffic", 1),
            ("2032158", "ET EXPLOIT", "EternalBlue SMB", 1),
            ("2028745", "ET PHISHING", "Credential Harvesting", 3),
            ("2045678", "ET MALWARE", "Emotet Download", 1),
            ("3012345", "ET POLICY", "Suspicious DNS Query", 3),
            ("3023456", "ET WEB", "SQL Injection Attempt", 2),
            ("3034567", "ET DOS", "SYN Flood Detected", 1),
            ("3045678", "ET SCAN", "SSH Brute Force", 2),
        ]
        n = random.randint(0, 2) if atk < 0.1 else random.randint(3, 15)
        for _ in range(n):
            sig_id, sig_cat, sig_desc, sig_pri = random.choice(sigs)
            src = random.choice(self.external_ips[:30])
            dst = random.choice(list(self.servers.values()))
            dst_port = self._wchoice([
                (445, 0.20), (443, 0.25), (80, 0.15), (3389, 0.12),
                (22, 0.10), (8080, 0.05), (53, 0.05), (3306, 0.05), (25, 0.03),
            ])
            detected = det > 0.3 and random.random() < det
            status = "[DETECTED]" if detected else "[MISSED]"
            log = "{0} SURICATA [{1}] {2} {3} [Priority:{4}] {5}:{6} -> {7}:{8} {9}\n".format(
                ts, sig_id, sig_cat, sig_desc, sig_pri, src,
                random.randint(1024, 65535), dst, dst_port, status)
            self.log_files["ids"].write(log)

    def _endpoint(self, ts, atk, nu):
        n = random.randint(10, 40)
        for _ in range(n):
            uid = random.randint(0, nu - 1)
            host = "WKS{0:04d}".format(uid)
            eid = self._wchoice(self.endpoint_event_ids)
            eid_map = {1: "ProcessCreate", 3: "NetworkConnect", 7: "ImageLoad",
                       8: "CreateRemoteThread", 11: "FileCreate", 13: "RegistrySet",
                       22: "DNSEvent", 15: "FileCreateStreamHash"}
            etype = eid_map.get(eid, "Unknown")

            user = "CORP/user_{0}".format(uid)
            details = ""
            if eid == 1:
                proc = random.choice(["cmd.exe", "powershell.exe", "chrome.exe", "outlook.exe", "python.exe"])
                details = 'Image={0} CommandLine="{0} {1}"'.format(proc, random.choice([
                    "/c whoami", "-EncodedCommand ...", "--remote-debugging-port", "/sync"]))
            elif eid == 3:
                dst_ip = random.choice(self.external_ips[:20])
                details = "Protocol=TCP DstIP={0} DstPort={1}".format(dst_ip, random.choice([443, 80, 8080]))
            elif eid == 8:
                details = "SourceImage=powershell.exe TargetImage=lsass.exe"
            elif eid == 13:
                details = "TargetObject=HKLM\\Run\\Malicious Key={0}".format(random.randint(1000, 9999))

            log = "{0} {1} Sysmon EventID={2} {3} User={4} Details=\"{5}\" ParentPID={6}\n".format(
                ts, host, eid, etype, user, details, random.randint(500, 50000))
            self.log_files["endpoint"].write(log)

    def _proxy(self, ts, nu):
        n = random.randint(10, 35)
        for _ in range(n):
            uid = random.randint(0, nu - 1)
            src = self.user_ips.get(uid, "10.0.5.100")
            url = "https://{0}/path".format(random.choice(self.domains))
            resp_code = self._wchoice([(200, 0.60), (301, 0.10), (403, 0.08), (404, 0.10), (500, 0.05), (503, 0.07)])
            category = self._wchoice([
                ("Business", 0.55), ("IT", 0.15), ("Unknown", 0.10),
                ("Social-Media", 0.05), ("Streaming", 0.04), ("Gambling", 0.02),
                ("Malware", 0.03), ("Phishing", 0.02), ("Command-and-Control", 0.04),
            ])
            bytes_sent = int(random.expovariate(1.0 / 10000) * 1000)
            log = "{0} PROXY-01 {1} CORP/user_{2} GET {3} {4} category={5} bytes={6}\n".format(
                ts, src, uid, url[:80], resp_code, category, bytes_sent)
            self.log_files["proxy"].write(log)

    def _email(self, ts, metrics):
        pr = metrics.get("phishing_click_rate", 0.05)
        n = random.randint(15, 45)
        senders = [
            "noreply@corp.com", "hr@corp.com", "it@corp.com",
            "urgent@ceo-phish.com", "invoice@fake-bill.net",
            "shipping@fedex-tracking.info", "support@microsoft-update.cc",
            "recruitment@linkedin-job.xyz",
        ]
        for _ in range(n):
            uid = random.randint(0, self.n_users - 1)
            sender = random.choice(senders)
            is_mal = any(x in sender for x in ["phish", "fake", "tracking", "update", "job", "info"])
            verdict = "PHISH" if is_mal else "CLEAN"
            if is_mal and random.random() < pr * 4:
                verdict = "PHISH_CLICKED"
            spf = "PASS" if not is_mal else random.choice(["FAIL", "SOFTFAIL", "NONE"])
            dkim = "PASS" if not is_mal else random.choice(["FAIL", "NONE"])
            log = "{0} EMAIL-GW from={1} to=user_{2}@corp.com verdict={3} spf={4} dkim={5} size={6}KB\n".format(
                ts, sender, uid, verdict, spf, dkim, random.randint(5, 2048))
            self.log_files["email"].write(log)

    def _siem(self, ts, atk, det, metrics):
        # Only generate SIEM alerts when there's actual activity
        if atk < 0.05:
            return
        alert_pool = [
            ("CRITICAL", "C2 Beacon Detected", "Tier3"),
            ("CRITICAL", "Data Exfiltration", "Tier3"),
            ("CRITICAL", "Ransomware Encryption", "Tier3"),
            ("HIGH", "Lateral Movement", "Tier2"),
            ("HIGH", "Privilege Escalation", "Tier2"),
            ("HIGH", "Suspicious PowerShell", "Tier2"),
            ("MEDIUM", "Brute Force Attempt", "Tier1"),
            ("MEDIUM", "Unusual Login Location", "Tier1"),
            ("MEDIUM", "New Service Installed", "Tier2"),
            ("LOW", "Policy Violation", "Tier1"),
        ]
        n = random.randint(1, 6) if atk > 0.3 else random.randint(0, 2)
        for _ in range(n):
            chosen = self._wchoice([(a, 1.0) for a in alert_pool])
            severity, alert_type, tier = chosen
            status = "INVESTIGATING" if det > 0.4 else "OPEN"
            log = "{0} SIEM-ALERT [{1}] {2} Status={3} Assigned=SOC-{4} RuleID={5}\n".format(
                ts, severity, alert_type, status, tier, random.randint(1000, 99999))
            self.log_files["siem"].write(log)

    def _netflow(self, ts, atk):
        flows = random.randint(50000, 250000)
        anomaly = round(random.expovariate(1.0 / max(atk * 100, 1)), 1)
        log = "{0} NETFLOW total_flows={1} anomaly_score={2} top_talkers={3} unique_ports={4}\n".format(
            ts, flows, anomaly, random.randint(100, 5000), random.randint(50, 300))
        self.log_files["netflow"].write(log)

    def close(self):
        for f in self.log_files.values():
            f.close()