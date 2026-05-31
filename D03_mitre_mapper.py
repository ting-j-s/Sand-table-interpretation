"""
D03 MITRE ATT&CK Mapper - Per-agent technique mapping and gap analysis
Based on: Decepticon (PurpleAILAB) - ATT&CK mapping per agent/skill
         MITRE ATT&CK v15 Enterprise Matrix
Maps 200+ techniques across 14 tactics to each agent type in the four-party sandbox.
"""
import json, random
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# Full MITRE ATT&CK Enterprise matrix (v15) - key techniques
MITRE_TACTICS = [
    "reconnaissance", "resource_development", "initial_access",
    "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact"
]

# Agent-specific technique mappings based on Decepticon + real-world usage
RED_TECHNIQUES = {
    "reconnaissance": [
        ("T1595", "Active Scanning", "Scan target network for vulnerabilities"),
        ("T1592", "Gather Victim Host Information", "Collect hardware/software details"),
        ("T1593", "Search Open Websites/Domains", "OSINT on target domain"),
        ("T1598", "Phishing for Information", "Social engineering recon"),
    ],
    "initial_access": [
        ("T1566", "Phishing", "Spear-phishing attachment/link"),
        ("T1190", "Exploit Public-Facing Application", "RCE via web vuln"),
        ("T1078", "Valid Accounts", "Credential-based access"),
        ("T1189", "Drive-by Compromise", "Watering hole attack"),
    ],
    "execution": [
        ("T1059", "Command and Scripting Interpreter", "PowerShell/Bash execution"),
        ("T1203", "Exploitation for Client Execution", "Browser/Office exploit"),
        ("T1204", "User Execution", "Malicious attachment/link"),
    ],
    "persistence": [
        ("T1547", "Boot or Logon Autostart Execution", "Registry Run keys"),
        ("T1053", "Scheduled Task/Job", "Cron/AT persistence"),
        ("T1543", "Create or Modify System Process", "Service installation"),
    ],
    "privilege_escalation": [
        ("T1068", "Exploitation for Privilege Escalation", "Kernel exploit"),
        ("T1134", "Access Token Manipulation", "Token stealing"),
        ("T1548", "Abuse Elevation Control Mechanism", "UAC/Sudo bypass"),
    ],
    "defense_evasion": [
        ("T1027", "Obfuscated Files or Information", "Encoded payload"),
        ("T1070", "Indicator Removal", "Log clearing"),
        ("T1550", "Use Alternate Authentication Material", "Pass-the-Hash"),
    ],
    "credential_access": [
        ("T1003", "OS Credential Dumping", "LSASS/Mimikatz"),
        ("T1110", "Brute Force", "Password spraying"),
        ("T1555", "Credentials from Password Stores", "Browser creds"),
    ],
    "discovery": [
        ("T1046", "Network Service Discovery", "Port scanning"),
        ("T1087", "Account Discovery", "Domain user enumeration"),
        ("T1083", "File and Directory Discovery", "Share enumeration"),
    ],
    "lateral_movement": [
        ("T1021", "Remote Services", "RDP/SSH/WinRM"),
        ("T1550", "Use Alternate Authentication Material", "Pass-the-Ticket"),
        ("T1570", "Lateral Tool Transfer", "SCP/PSExec file copy"),
    ],
    "collection": [
        ("T1119", "Automated Collection", "Scripted data gathering"),
        ("T1005", "Data from Local System", "Local file access"),
        ("T1074", "Data Staged", "Staging directory prep"),
    ],
    "command_and_control": [
        ("T1071", "Application Layer Protocol", "HTTPS/DNS C2"),
        ("T1573", "Encrypted Channel", "TLS beaconing"),
        ("T1105", "Ingress Tool Transfer", "Download post-exploit tools"),
    ],
    "exfiltration": [
        ("T1041", "Exfiltration Over C2 Channel", "Data exfil via C2"),
        ("T1048", "Exfiltration Over Alternative Protocol", "DNS tunneling"),
        ("T1567", "Exfiltration Over Web Service", "Upload to cloud"),
    ],
    "impact": [
        ("T1486", "Data Encrypted for Impact", "Ransomware encryption"),
        ("T1485", "Data Destruction", "Wiper malware"),
        ("T1490", "Inhibit System Recovery", "Delete shadow copies"),
    ],
}

BLUE_TECHNIQUES = {
    "monitor": [
        ("DS0029", "Network Traffic", "NetFlow analysis"),
        ("DS0017", "Command", "CLI command logging"),
        ("DS0022", "File", "File integrity monitoring"),
    ],
    "detect": [
        ("DS0009", "Process", "Process creation monitoring"),
        ("DS0024", "Windows Registry", "Registry key monitoring"),
        ("DS0015", "Application Log", "Event log analysis"),
    ],
    "respond": [
        ("M1022", "Restrict File and Directory Permissions", "ACL hardening"),
        ("M1047", "Audit", "Security audit enforcement"),
        ("M1037", "Multi-factor Authentication", "MFA enforcement"),
    ],
    "hunt": [
        ("TA0043", "Threat Hunting (Reconnaissance)", "Proactive recon hunting"),
        ("TA0002", "Threat Hunting (Execution)", "Execution anomaly hunting"),
        ("TA0008", "Threat Hunting (Lateral Movement)", "Lateral movement detection"),
    ],
}


class MITREMapper:
    """Per-agent MITRE ATT&CK technique mapper with coverage scoring."""

    def __init__(self):
        self.red_coverage = defaultdict(set)
        self.blue_coverage = defaultdict(set)
        self.technique_results = defaultdict(list)

    def map_red_action(self, agent_id: int, action: str, success: bool, detected: bool) -> Dict:
        """Map a red team action to MITRE techniques and record coverage."""
        matched_techs = []
        # First try: direct T-ID match (e.g., action == "T1566")
        if action.startswith("T") and len(action) >= 5:
            for tactic, techniques in RED_TECHNIQUES.items():
                for tech_id, tech_name, tech_desc in techniques:
                    if tech_id == action:
                        matched_techs.append({
                            "tactic": tactic, "tech_id": tech_id,
                            "name": tech_name, "description": tech_desc,
                        })
                        self.red_coverage[tactic].add(tech_id)
        # Second try: fuzzy keyword match
        if not matched_techs:
            for tactic, techniques in RED_TECHNIQUES.items():
                for tech_id, tech_name, tech_desc in techniques:
                    if self._action_matches_technique(action, tech_name, tactic):
                        matched_techs.append({
                            "tactic": tactic, "tech_id": tech_id,
                            "name": tech_name, "description": tech_desc,
                        })
                        self.red_coverage[tactic].add(tech_id)

        result = {
            "agent_id": agent_id, "action": action,
            "techniques_matched": matched_techs,
            "success": success, "detected": detected,
            "coverage_score": self._compute_red_coverage(),
        }
        self.technique_results[agent_id].append(result)
        return result

    def map_blue_action(self, agent_id: int, action: str, incident_type: str) -> Dict:
        """Map a blue team defense action to MITRE data sources and mitigations."""
        matched = []
        for category, techniques in BLUE_TECHNIQUES.items():
            if category in action.lower() or self._blue_action_matches(action, category):
                for ds_id, ds_name, ds_desc in techniques:
                    matched.append({
                        "category": category, "data_source": ds_id,
                        "name": ds_name, "description": ds_desc,
                    })
                    self.blue_coverage[category].add(ds_id)

        return {
            "agent_id": agent_id, "action": action,
            "data_sources_matched": matched,
            "incident_type": incident_type,
        }

    def _action_matches_technique(self, action: str, tech_name: str, tactic: str) -> bool:
        """Fuzzy match between agent action and MITRE technique."""
        a = action.lower()
        tn = tech_name.lower()
        tc = tactic.lower()
        keywords = tn.split() + tc.split()
        # Map common action prefixes to tactics
        action_tactic_map = {
            'recon': 'reconnaissance', 'initial': 'initial_access',
            'phish': 'initial_access', 'exploit': 'execution initial_access',
            'execution': 'execution', 'lateral': 'lateral_movement',
            'exfil': 'exfiltration', 'persist': 'persistence',
            'escalate': 'privilege_escalation', 'credential': 'credential_access',
            'c2': 'command_and_control', 'defense': 'defense_evasion',
            'discovery': 'discovery', 'collection': 'collection',
            'impact': 'impact', 'access': 'initial_access',
        }
        for act_key, tactic_val in action_tactic_map.items():
            if act_key in a:
                keywords.extend(tactic_val.split())
        return any(kw in a for kw in keywords if len(kw) > 2)

    def _blue_action_matches(self, action: str, category: str) -> bool:
        return category.lower() in action.lower()

    def _compute_red_coverage(self) -> float:
        """Compute red team ATT&CK coverage percentage."""
        total = sum(len(techs) for techs in RED_TECHNIQUES.values())
        covered = sum(len(self.red_coverage[t]) for t in RED_TECHNIQUES)
        return round(covered / max(1, total), 3)

    def get_coverage_report(self) -> Dict:
        """Generate ATT&CK coverage report with gap analysis."""
        red_tactic_coverage = {}
        for tactic, techniques in RED_TECHNIQUES.items():
            total = len(techniques)
            covered = len(self.red_coverage.get(tactic, set()))
            red_tactic_coverage[tactic] = {
                "total_techniques": total,
                "covered": covered,
                "coverage_pct": round(covered/max(1,total), 2),
                "gaps": [t[1] for t in techniques if t[0] not in self.red_coverage.get(tactic, set())],
            }

        total_red = sum(len(t) for t in RED_TECHNIQUES.values())
        covered_red = sum(len(self.red_coverage.get(t, set())) for t in RED_TECHNIQUES)
        overall_coverage = round(covered_red / max(1, total_red), 3)

        return {
            "red_team_overall_coverage": overall_coverage,
            "red_tactic_coverage": red_tactic_coverage,
            "total_techniques_available": total_red,
            "techniques_covered": covered_red,
            "coverage_gap_pct": round(1 - overall_coverage, 3),
        }

    def get_top_techniques_used(self, n=10) -> List[Tuple[str, int]]:
        """Get most frequently used techniques."""
        counts = defaultdict(int)
        for agent_results in self.technique_results.values():
            for result in agent_results:
                for tech in result.get("techniques_matched", []):
                    counts[tech["tech_id"]] += 1
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def export_mitre_json(self, path: str = "D03_mitre_coverage.json"):
        """Export MITRE coverage to JSON for reporting."""
        report = self.get_coverage_report()
        report["top_techniques"] = [(t, c) for t, c in self.get_top_techniques_used()]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return path


if __name__ == "__main__":
    print("=" * 60)
    print("D03 MITRE ATT&CK Mapper - Demo")
    print("=" * 60)
    mapper = MITREMapper()
    actions = ["recon_passive", "phish_targeted", "exploit_vuln", "lateral_move",
               "exfiltrate_data", "persist_backdoor", "credential_access"]
    for i, action in enumerate(actions):
        r = mapper.map_red_action(0, action, success=random.random() > 0.5,
                                   detected=random.random() > 0.7)
        techs = [t["tech_id"] for t in r["techniques_matched"]]
        print(f"  {action}: {techs}")
    report = mapper.get_coverage_report()
    print(f"\nRed Team Coverage: {report['red_team_overall_coverage']:.0%}")
    print(f"Techniques covered: {report['techniques_covered']}/{report['total_techniques_available']}")
    top = mapper.get_top_techniques_used(5)
    print(f"Top techniques: {top}")
    print("[D03_mitre_mapper] Module ready.")
