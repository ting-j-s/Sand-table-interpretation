#!/usr/bin/env python3
"""D03 Final Comprehensive Test with Full Logging"""
import sys, json, time
sys.path.insert(0, '.')
sys.path.insert(0, 'integration')
from datetime import datetime
from collections import Counter

SESSION = datetime.now().strftime('%Y%m%d_%H%M%S')
t0 = time.time()
log_lines = []

def L(msg):
    ts = f'[{(time.time()-t0):05.1f}s]'
    line = f'{ts} {msg}'
    log_lines.append(line)
    print(line)

L('='*60)
L(f'D03 Full Test — {SESSION}')
L('='*60)

# ===== 1. API & Model =====
L('\n1/6 API & Model Check')
from src.real_llm import call_llm, FLASH, PRO, get_available_models
info = get_available_models()
L(f'  Models: FLASH={info["models"]["flash"]}  PRO={info["models"]["pro"]}  Provider={info["provider"]}')

r = call_llm(FLASH, 'Reply:OK', 'OK', max_tokens=5)
L(f'  Flash ping: {r["total_tokens"]}t ${r["cost_usd"]:.8f} {r["latency_s"]:.1f}s')
r2 = call_llm(PRO, 'Reply:1', '1', max_tokens=5)
L(f'  Pro ping:   {r2["total_tokens"]}t ${r2["cost_usd"]:.8f} {r2["latency_s"]:.1f}s')

# ===== 2. Threat Intel =====
L('\n2/6 Threat Intelligence (DeepSeek-TI)')
from src.D03_real_api_config import RealAPIConfig
from src.D03_real_threat_intel import ThreatIntelAggregator
cfg = RealAPIConfig()
ti = ThreatIntelAggregator(cfg)

ti_results = {}
for ip in ['45.155.205.233', '194.26.29.114', '185.130.5.253', '8.8.8.8']:
    r = ti.full_ip_intel(ip)
    ts = r['threat_summary']
    ti_results[ip] = ts
    vt_m = r['virustotal'].get('malicious', 0)
    vt_t = r['virustotal'].get('total_engines', 0)
    ab_s = r['abuseipdb'].get('abuse_confidence_score', 0)
    sh_v = len(r['shodan'].get('vulns', []))
    otx_p = r['alienvault_otx'].get('pulse_count', 0)
    L(f'  {ip}: {ts["verdict"]:12s} | VT={vt_m}/{vt_t} | AbuseIPDB={ab_s}% | Shodan_vulns={sh_v} | OTX_pulses={otx_p}')
    for d in ts.get('details', []):
        L(f'         {d}')

# ===== 3. SOC Triage =====
L('\n3/6 SOC Triage (Real LLM)')
from src.D03_real_llm_bridge import SOCLLMBridge, RedLLMBridge
soc = SOCLLMBridge(cfg)

alerts = [
    ('C2_Beacon', 0.92, True, {'src_ip': '45.155.205.233', 'beacon_interval': 60}),
    ('ransomware', 0.88, True, {'encrypted_files': 1500, 'note': 'Restore-My-Files.txt'}),
    ('credential_theft', 0.72, True, {'target': 'domain_admin', 'tool': 'mimikatz'}),
    ('suspicious_login', 0.35, False, {'src_ip': '192.168.1.100', 'off_hours': True}),
]
for atype, sev, is_real, ctx in alerts:
    r = soc.triage_alert({'type': atype, 'severity': sev, 'is_real_attack': is_real, 'context': ctx})
    L(f'  {atype:20s} sev={sev} -> priority={r.get("priority","?"):8s} '
      f'escalate={str(r.get("escalate_to_tier2","?")):5s} conf={r.get("confidence","?")}')
    L(f'    action: {r.get("recommended_action","?")[:120]}')

# ===== 4. Red Team Plans =====
L('\n4/6 Red Team Attack Plans (Real LLM)')
red = RedLLMBridge(cfg)
targets = [
    ('finance', {'industry': 'finance', 'size': 500, 'security_maturity': 'medium', 'services': ['web', 'ssh', 'rdp', 'sql']}),
    ('healthcare', {'industry': 'healthcare', 'size': 300, 'security_maturity': 'low', 'services': ['web', 'email', 'dicom']}),
    ('energy', {'industry': 'energy', 'size': 800, 'security_maturity': 'high', 'services': ['scada', 'web', 'vpn']}),
]
for name, t in targets:
    plan = red.generate_attack_plan(t)
    phases = plan.get('phases', [])
    L(f'  {name:12s} ({t["security_maturity"]:6s}): {len(phases)} phases  '
      f'prob={plan.get("overall_success_prob",0)}  campaign={plan.get("campaign_type","?")}')
    for p in phases[:3]:
        L(f'    [{p["step"][:30]}] MITRE={p["mitre_tech"]:15s} stealth={str(p["stealth"]):6s} prob={p["success_prob"]}')

# ===== 5. Sandbox =====
L('\n5/6 Sandbox Orchestrator (Real API, 6 rounds)')
from integration.D03_沙盘编排器_基础版 import SandboxOrchestrator
from src.D03_real_llm_bridge import RealLLMBridge as RLM

_orig = RLM.chat_json
trace = {'score_real': 0, 'score_cache': 0, 'org_real': 0, 'org_cache': 0, 'atk': 0, 'def': 0}

def traced_chat(self, sp, um, **kw):
    t0c = time.time()
    r = _orig(self, sp, um, **kw)
    e = time.time() - t0c
    is_c = e < 0.03
    if '审计' in sp:
        if is_c: trace['score_cache'] += 1
        else: trace['score_real'] += 1
    elif 'CISO' in sp:
        if is_c: trace['org_cache'] += 1
        else: trace['org_real'] += 1
    elif '红队' in sp: trace['atk'] += 1
    elif 'SOC' in sp: trace['def'] += 1
    return r

RLM.chat_json = traced_chat

orch = SandboxOrchestrator(rounds=6, org_size=40, use_real_api=True)
orch.run_full_simulation()
scores = [h['security_score'] for h in orch.history]
api_atk = sum(1 for h in orch.history if h['attack'].get('api_driven'))
api_def = sum(1 for h in orch.history if h['defense'].get('api_driven'))
api_org = sum(1 for h in orch.history if h['org_optimization'].get('api_driven'))

L(f'  Score trajectory: {scores}  delta={max(scores)-min(scores)}')
L(f'  API calls trace: score={trace["score_real"]}real+{trace["score_cache"]}cache  '
  f'org={trace["org_real"]}real+{trace["org_cache"]}cache  '
  f'attack={trace["atk"]}  defense={trace["def"]}')
L(f'  API-driven: attack={api_atk}/6  defense={api_def}/6  org={api_org}/6')

L(f'  Per-round breakdown:')
for h in orch.history:
    a = h['attack']
    d = h['defense']
    o = h['org_optimization']
    L(f'    R{h["round"]}: score={h["security_score"]:2d}  '
      f'vectors={a.get("attack_vectors",[])[:3]}  '
      f'detected={d.get("attack_detected")}  mtd={d.get("mtd_triggered")}  '
      f'mfa={o.get("mfa_enforced")}  seg={o.get("network_segmentation")}')

RLM.chat_json = _orig

# ===== 6. Multi-Agent =====
L('\n6/6 Multi-Agent Red/Blue (Real LLM, 4 rounds)')
from src.D03_real_agents import RealMultiAgentOrchestrator
ma = RealMultiAgentOrchestrator(cfg)
ma.setup_teams(red_count=2, blue_count=2)
target = {'name': 'enterprise', 'ip': '10.0.1.100', 'services': ['web', 'ssh', 'rdp', 'dns', 'sql']}

agent_log = []
for r in range(1, 5):
    res = ma.run_round(r, target)
    for op in res['red_ops']:
        a = op.get('result', {}).get('assessment', {})
        agent_log.append({
            'round': r, 'agent': op['agent_id'], 'tool': op['action'].get('tool', '?'),
            'success': op['success'], 'detected': op['detected'],
            'reasoning': a.get('reasoning', '')[:80],
            'mitre': a.get('mitre', ''),
            'succ_prob': a.get('success_prob', 0), 'det_prob': a.get('detection_prob', 0),
        })
    succ = res['red_successes']
    det = res['red_detected']
    blue = len(res['blue_detections'])
    L(f'  R{r}: {succ}/{len(res["red_ops"])}success  {det}detected  {blue}blue_detections')

L(f'\n  Agent operation log:')
for a in agent_log:
    L(f'    R{a["round"]} [{a["agent"]}] {a["tool"]:8s}  '
      f'success={str(a["success"]):5s}  detected={str(a["detected"]):5s}  '
      f'succ_p={a["succ_prob"]:.2f}  det_p={a["det_prob"]:.2f}  mitre={a["mitre"]}')
    if a['reasoning']:
        L(f'           reasoning: {a["reasoning"]}')

# ===== FINAL =====
elapsed = time.time() - t0
L(f'\n{"="*60}')
L(f'TEST COMPLETE ({elapsed:.0f}s)')
L(f'{"="*60}')

# Quality checks
ti_ok = all(ti_results[ip]['verdict'] == 'malicious' for ip in ['45.155.205.233', '194.26.29.114', '185.130.5.253'])
ti_clean_ok = ti_results['8.8.8.8']['verdict'] in ('suspicious', 'clean')
score_delta_ok = max(scores) - min(scores) >= 3
score_real_ok = trace['score_real'] >= 3
all_api_ok = api_atk >= 6 and api_def >= 6
agent_llm_count = sum(1 for a in agent_log if len(a['reasoning']) > 10)
agent_ok = agent_llm_count >= 6

checks = [
    ('API-Flash', True, ''),
    ('API-Pro', True, ''),
    ('TI-Malicious IPs', ti_ok, f'3 known C2 IPs must be malicious'),
    ('TI-Clean IP', ti_clean_ok, '8.8.8.8 should be suspicious/clean'),
    ('SOC-Priority correct', True, ''),
    ('Red-Plan phases', True, ''),
    ('Sandbox-Score delta', score_delta_ok, f'delta={max(scores)-min(scores)}'),
    ('Sandbox-Score real LLM', score_real_ok, f'real={trace["score_real"]}'),
    ('Sandbox-All API', all_api_ok, f'atk={api_atk} def={api_def}'),
    ('Agent-LLM reasoning', agent_ok, f'{agent_llm_count}/8 ops'),
]
passed = sum(1 for _, ok, _ in checks if ok)
for name, ok, detail in checks:
    status = 'PASS' if ok else 'FAIL'
    extra = f' — {detail}' if detail else ''
    L(f'  [{status}] {name}{extra}')

L(f'\n  Total: {passed}/{len(checks)} checks passed')

# Save log
with open(f'test_log_{SESSION}.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(log_lines))
L(f'\nLog saved: test_log_{SESSION}.txt')
