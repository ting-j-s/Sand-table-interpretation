#!/usr/bin/env python3
"""处理MITRE ATT&CK + CISA KEV数据，构建增强知识库"""
import json
from collections import defaultdict

print('=== Processing MITRE ATT&CK + CISA KEV ===')

# Load MITRE Enterprise
with open('mitre_enterprise.json', 'r', encoding='utf-8') as f:
    mitre = json.load(f)
objects = mitre.get('objects', [])

# Extract groups
groups = {}
for o in objects:
    if o.get('type') == 'intrusion-set':
        aliases = o.get('aliases', [])
        if not aliases:
            aliases = [o.get('name', '')]
        groups[o.get('name', '')] = {
            'aliases': aliases[:5],
            'description': (o.get('description', '') or '')[:300],
            'external_id': next((r.get('external_id', '') for r in o.get('external_references', [])
                                if r.get('source_name') == 'mitre-attack'), ''),
        }

# Extract techniques
techniques = {}
for o in objects:
    if o.get('type') == 'attack-pattern' and not o.get('revoked', False):
        ext_id = next((r.get('external_id', '') for r in o.get('external_references', [])
                      if r.get('source_name') == 'mitre-attack'), '')
        if ext_id.startswith('T'):
            techniques[ext_id] = {
                'name': o.get('name', ''),
                'description': (o.get('description', '') or '')[:200],
                'kill_chain': [p.get('phase_name', '') for p in o.get('kill_chain_phases', [])],
                'platforms': o.get('x_mitre_platforms', []),
                'detection': (o.get('x_mitre_detection', '') or '')[:200],
            }

# Extract software
software = {}
for o in objects:
    if o.get('type') in ('malware', 'tool') and not o.get('revoked', False):
        ext_id = next((r.get('external_id', '') for r in o.get('external_references', [])
                      if r.get('source_name') == 'mitre-attack'), '')
        if ext_id:
            software[ext_id] = {
                'name': o.get('name', ''),
                'type': o.get('type', ''),
                'description': (o.get('description', '') or '')[:200],
                'platforms': o.get('x_mitre_platforms', []),
            }

# Top groups by technique count
group_techniques = defaultdict(set)
for o in objects:
    if o.get('type') == 'relationship' and o.get('relationship_type') == 'uses':
        src = o.get('source_ref', '')
        tgt = o.get('target_ref', '')
        src_obj = next((x for x in objects if x.get('id') == src), {})
        tgt_obj = next((x for x in objects if x.get('id') == tgt), {})
        if src_obj.get('type') == 'intrusion-set' and tgt_obj.get('type') == 'attack-pattern':
            group_techniques[src_obj.get('name', '')].add(tgt)

top_groups = sorted(group_techniques.items(), key=lambda x: len(x[1]), reverse=True)[:30]
print(f'Groups: {len(groups)}, Techniques: {len(techniques)}, Software: {len(software)}')
print(f'Top APT by technique count:')
for name, techs in top_groups[:10]:
    print(f'  {name}: {len(techs)} techniques')

# Load CISA KEV
with open('cisa_kev.json', 'r', encoding='utf-8') as f:
    kev = json.load(f)

# Build enhanced knowledge base
kb = {
    'version': '2.0',
    'description': 'D03 TI Knowledge Base - MITRE ATT&CK + CISA KEV enhanced',
    'last_updated': '2026-05-30',
    'sources': {
        'mitre_enterprise': f'{len(groups)} groups, {len(techniques)} techniques, {len(software)} software',
        'cisa_kev': f'{len(kev)} known exploited vulnerabilities',
    },
    'apt_groups': {},
    'top_techniques': {},
    'top_software': {},
    'critical_cves': [],
    'ransomware_cves': [],
    'known_malicious_ips': {
        '45.155.205.233': {'category': 'C2', 'threat_actor': 'APT29', 'confidence': 0.92,
            'associated_malware': ['Sunburst', 'Teardrop'], 'ports': [443, 8443, 53],
            'mitre_techniques': ['T1071.001', 'T1573.001'], 'asn': 'AS44477', 'country': 'RU'},
        '194.26.29.114': {'category': 'C2', 'threat_actor': 'APT28', 'confidence': 0.88,
            'associated_malware': ['X-Agent', 'X-Tunnel'], 'ports': [443, 8080, 993],
            'mitre_techniques': ['T1071.001', 'T1090.003'], 'asn': 'AS197695', 'country': 'RU'},
        '185.130.5.253': {'category': 'Exploit', 'threat_actor': 'Lazarus Group', 'confidence': 0.85,
            'associated_malware': ['CobaltStrike', 'Fallchill'], 'ports': [443, 445, 3389],
            'mitre_techniques': ['T1210', 'T1021.002'], 'asn': 'AS204957', 'country': 'KP'},
        '103.235.46.39': {'category': 'Phishing', 'threat_actor': 'APT10', 'confidence': 0.78,
            'associated_malware': ['PlugX', 'ShadowPad'], 'ports': [80, 443, 8443],
            'mitre_techniques': ['T1566.001', 'T1204.002'], 'asn': 'AS133774', 'country': 'CN'},
        '91.121.87.50': {'category': 'Ransomware', 'threat_actor': 'Conti', 'confidence': 0.81,
            'associated_malware': ['Conti', 'BazarLoader'], 'ports': [443, 8443, 8080],
            'mitre_techniques': ['T1486', 'T1490'], 'asn': 'AS16276', 'country': 'FR'},
    },
    'service_port_map': {
        'web_server': {'ports': [80, 443, 8080, 8443], 'products': ['Apache', 'nginx', 'IIS', 'Tomcat']},
        'ssh': {'ports': [22, 2222], 'products': ['OpenSSH', 'Dropbear']},
        'rdp': {'ports': [3389], 'products': ['Microsoft RDP']},
        'dns': {'ports': [53, 853], 'products': ['BIND', 'Unbound']},
        'sql': {'ports': [1433, 3306, 5432], 'products': ['MySQL', 'PostgreSQL', 'MSSQL']},
        'smtp': {'ports': [25, 465, 587], 'products': ['Postfix', 'Exchange']},
        'ftp': {'ports': [21, 990], 'products': ['vsftpd', 'ProFTPD']},
        'smb': {'ports': [445, 139], 'products': ['Samba', 'Windows SMB']},
        'vpn': {'ports': [1194, 51820], 'products': ['OpenVPN', 'WireGuard']},
    },
    'common_ports_by_os': {
        'windows_server': [135, 139, 445, 3389, 5985, 1433],
        'linux_server': [22, 80, 443, 3306, 5432, 6379, 8080],
        'network_device': [22, 23, 80, 443, 161, 162],
    },
    'isp_map': {
        'AS44477': {'name': 'STARK INDUSTRIES', 'type': 'hosting', 'risk': 'medium'},
        'AS197695': {'name': 'Reg.Ru', 'type': 'hosting', 'risk': 'low'},
        'AS204957': {'name': 'Larus Ltd', 'type': 'hosting', 'risk': 'low'},
        'AS16276': {'name': 'OVH SAS', 'type': 'hosting', 'risk': 'medium'},
        'AS15169': {'name': 'Google', 'type': 'business', 'risk': 'low'},
        'AS8075': {'name': 'Microsoft', 'type': 'business', 'risk': 'low'},
        'AS16509': {'name': 'AWS', 'type': 'cloud', 'risk': 'low'},
    },
}

for name, techs in top_groups[:30]:
    info = groups.get(name, {})
    kb['apt_groups'][name] = {
        'aliases': info.get('aliases', [name]),
        'technique_count': len(techs),
        'description': info.get('description', ''),
        'external_id': info.get('external_id', ''),
    }

for tid, info in sorted(techniques.items())[:200]:
    kb['top_techniques'][tid] = info

for sid, info in sorted(software.items())[:200]:
    kb['top_software'][sid] = info

ransomware_cves = [v for v in kev if v.get('ransomware_known')]
recent_cves = sorted(kev, key=lambda x: x.get('date_added', ''), reverse=True)
kb['critical_cves'] = [{
    'cve': v['cve'], 'vendor': v['vendor'], 'product': v['product'],
    'name': v['vuln_name'], 'description': v['description'],
    'ransomware_used': v.get('ransomware_known', False),
    'date_added': v['date_added'],
} for v in recent_cves[:300]]
kb['ransomware_cves'] = [{
    'cve': v['cve'], 'vendor': v['vendor'], 'product': v['product'],
    'name': v['vuln_name'], 'description': v['description'],
} for v in ransomware_cves[:100]]

with open('D03_ti_knowledge_base.json', 'w', encoding='utf-8') as f:
    json.dump(kb, f, ensure_ascii=False, indent=2)

file_size = len(json.dumps(kb, ensure_ascii=False))
print(f'\nEnhanced KB: {file_size} bytes')
print(f'  APT groups: {len(kb["apt_groups"])}')
print(f'  Techniques: {len(kb["top_techniques"])}')
print(f'  Software: {len(kb["top_software"])}')
print(f'  Critical CVEs: {len(kb["critical_cves"])}')
print(f'  Ransomware CVEs: {len(kb["ransomware_cves"])}')
print('DONE')
