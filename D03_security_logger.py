"""D03 Security Log Generator - Enterprise SIEM telemetry from sandbox state"""
import random, json, time, os, math
from datetime import datetime
from collections import defaultdict

class EnterpriseSecurityLogger:
    def __init__(self, log_dir="production_logs/security_logs", n_users=200):
        self.log_dir = log_dir; os.makedirs(log_dir, exist_ok=True)
        self.n_users = n_users; self.ep_counter = 0
        self.internal_nets = ["10.0.0.0/8","172.16.0.0/12"]
        self.servers = {"dc01":"10.0.1.10","dc02":"10.0.1.11","web01":"172.16.1.10",
                       "sql01":"10.0.3.10","dns01":"10.0.0.53","file01":"10.0.2.10"}
        self.external_ips = [f"203.0.113.{i}" for i in range(1,20)]
        self.user_ips = {i: f"10.0.{2+(i//254)}.{1+(i%254)}" for i in range(n_users)}
        self.domains = ["github.com","office.com","google.com","amazonaws.com",
                       "dropbox.com","pastebin.com","discord.com","evil-c2.xyz",
                       "phish-login.net","malware-cdn.biz","exfil-data.ru"]
        self.malicious = ["evil-c2.xyz","phish-login.net","malware-cdn.biz","exfil-data.ru"]
        self.log_files = {}
        for name in ["firewall","auth","dns","ids","endpoint","proxy","email","siem","netflow"]:
            path = os.path.join(log_dir, f"{name}.log")
            self.log_files[name] = open(path, "w", encoding="utf-8", buffering=8192)

    def _ts(self): return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0,999):03d}Z"

    def generate_episode_logs(self, orch, metrics, episode):
        self.ep_counter = episode; ts = self._ts()
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
        if episode % 10 == 0: self._netflow(ts, atk)

    def _firewall(self, ts, atk):
        for _ in range(random.randint(15,40)):
            src = random.choice(list(self.user_ips.values()))
            dst = random.choice(list(self.servers.values()) + self.external_ips)
            port = random.choice([80,443,22,3389,445,8080,53,25])
            action = "ALLOW"
            if atk > 0.3 and random.random() < atk:
                src = random.choice(self.external_ips[:5])
                dst = random.choice(list(self.servers.values()))
                port = random.choice([445,3389,22])
                action = "ALLOW" if random.random() < 0.4 else "DENY"
            log = (f'{ts} FW-01 TRAFFIC {action} {src}:{random.randint(40000,65535)} '
                   f'-> {dst}:{port} proto=tcp bytes={random.randint(500,500000)}\n')
            self.log_files["firewall"].write(log)

    def _auth(self, ts, atk):
        for _ in range(random.randint(20,60)):
            uid = random.randint(0, self.n_users-1)
            src = self.user_ips.get(uid, "10.0.5.100")
            success = True
            if atk > 0.3 and random.random() < atk * 0.3:
                src = random.choice(self.external_ips[:3])
                success = random.random() < 0.3
            eid = 4624 if success else 4625
            log = (f'{ts} DC01 Security EventID={eid} Account=user_{uid} '
                   f'SrcIP={src} AuthPackage={random.choice(["NTLM","Kerberos"])}\n')
            self.log_files["auth"].write(log)

    def _dns(self, ts, atk, det):
        for _ in range(random.randint(30,80)):
            src = random.choice(list(self.user_ips.values()))
            domain = random.choice(self.domains)
            if atk > 0.4 and random.random() < 0.15:
                domain = random.choice(self.malicious)
            qtype = random.choice(["A","AAAA","MX","TXT"])
            log = (f'{ts} DNS-01 query {qtype} {domain} from {src} '
                   f'response={random.choice(["NOERROR","NXDOMAIN"])}\n')
            self.log_files["dns"].write(log)

    def _ids(self, ts, atk, det):
        n = random.randint(0,2) if atk < 0.1 else random.randint(3,12)
        sigs = [("2017910","ET SCAN","OpenSSL Heartbleed"),
                ("2024366","ET TROJAN","CobaltStrike Beacon"),
                ("2809154","ET CNC","Sliver C2 Traffic"),
                ("2032158","ET EXPLOIT","EternalBlue SMB"),
                ("2028745","ET PHISHING","Credential Harvesting")]
        for _ in range(n):
            sig = random.choice(sigs)
            src = random.choice(self.external_ips[:5])
            dst = random.choice(list(self.servers.values()))
            log = (f'{ts} SURICATA [{sig[0]}] {sig[1]} {sig[2]} '
                   f'[Priority:{random.randint(1,3)}] {src}:{random.randint(40000,65535)} '
                   f'-> {dst}:{random.choice([445,443,80,3389])} '
                   f'{"[DETECTED]" if det>0.4 and random.random()<det else "[MISSED]"}\n')
            self.log_files["ids"].write(log)

    def _endpoint(self, ts, atk, nu):
        for _ in range(random.randint(10,30)):
            uid = random.randint(0, nu-1); host = f"WKS{uid:04d}"
            event = random.choice([
                ("1","ProcessCreate",f"cmd.exe /c whoami"),
                ("3","NetworkConnect",f"outbound to {random.choice(self.external_ips)}")])
            if atk > 0.3 and random.random() < 0.2:
                event = ("8","CreateRemoteThread","powershell.exe -> lsass.exe")
            if atk > 0.5 and random.random() < 0.15:
                event = ("13","RegistrySet","HKLM/Run/MaliciousPersist")
            log = (f'{ts} {host} Sysmon EventID={event[0]} {event[1]} '
                   f'User=CORP/user_{uid} Details="{event[2]}"\n')
            self.log_files["endpoint"].write(log)

    def _proxy(self, ts, nu):
        for _ in range(random.randint(10,25)):
            uid = random.randint(0, nu-1)
            src = self.user_ips.get(uid, "10.0.5.100")
            url = f"https://{random.choice(self.domains)}/path"
            log = (f'{ts} PROXY-01 {src} CORP/user_{uid} '
                   f'GET {url} {random.choice([200,200,403,404])} '
                   f'category={random.choice(["Business","IT","Unknown","Malware"])}\n')
            self.log_files["proxy"].write(log)

    def _email(self, ts, metrics):
        pr = metrics.get("phishing_click_rate", 0.05)
        for _ in range(random.randint(15,40)):
            uid = random.randint(0, self.n_users-1)
            sender = random.choice(["noreply@corp.com","urgent@ceo-phish.com","invoice@fake-bill.net"])
            is_phish = "phish" in sender or "fake" in sender
            verdict = "PHISH" if is_phish else "CLEAN"
            if is_phish and random.random() < pr * 5: verdict = "PHISH_CLICKED"
            log = (f'{ts} EMAIL-GW from={sender} to=user_{uid}@corp.com '
                   f'verdict={verdict} spf={random.choice(["PASS","FAIL"])}\n')
            self.log_files["email"].write(log)

    def _siem(self, ts, atk, det, metrics):
        if atk > 0.3:
            alerts = [("Brute Force Attack","MEDIUM"),("C2 Beacon Detected","CRITICAL"),
                     ("Data Exfiltration","CRITICAL"),("Lateral Movement","HIGH"),
                     ("Privilege Escalation","HIGH")]
            for _ in range(random.randint(1,4)):
                a = random.choice(alerts)
                log = (f'{ts} SIEM-ALERT [{a[1]}] {a[0]} '
                       f'Status={"OPEN" if det<0.5 else "INVESTIGATING"} '
                       f'Assigned=SOC-Tier{random.randint(1,3)}\n')
                self.log_files["siem"].write(log)

    def _netflow(self, ts, atk):
        log = (f'{ts} NETFLOW total_flows={random.randint(50000,200000)} '
               f'anomaly_score={random.uniform(0,atk*100):.1f}\n')
        self.log_files["netflow"].write(log)

    def close(self):
        for f in self.log_files.values(): f.close()
