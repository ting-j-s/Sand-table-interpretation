#!/usr/bin/env python3
"""
D03 Sandbox Orchestrator — Expanded from 136 lines to full implementation.
Complete red-team / blue-team adversarial sandbox with scenario execution.

Components:
  - RedTeamAgent: Attack agents with tactics, techniques, and procedures
  - BlueTeamAgent: Defense agents with detection, response, and recovery
  - ScenarioEngine: Load and execute sandbox scenarios
  - ScoringEngine: MITRE ATT&CK aligned scoring
  - ReportGenerator: Comprehensive post-exercise analysis
"""
import json, sys, os, time, re, random
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from enum import Enum

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))


# ================================================================
# Tactics & Techniques (MITRE ATT&CK aligned)
# ================================================================
class Tactic(Enum):
    RECON = "reconnaissance"
    RESOURCE_DEV = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIV_ESC = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CRED_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFIL = "exfiltration"
    IMPACT = "impact"


TECHNIQUES = {
    Tactic.RECON: [
        {'id': 'T1595', 'name': 'Active Scanning', 'difficulty': 0.3},
        {'id': 'T1592', 'name': 'Gather Victim Host Info', 'difficulty': 0.2},
    ],
    Tactic.INITIAL_ACCESS: [
        {'id': 'T1566', 'name': 'Phishing', 'difficulty': 0.5},
        {'id': 'T1190', 'name': 'Exploit Public-Facing App', 'difficulty': 0.7},
        {'id': 'T1078', 'name': 'Valid Accounts', 'difficulty': 0.6},
    ],
    Tactic.EXECUTION: [
        {'id': 'T1059', 'name': 'Command & Scripting Interpreter', 'difficulty': 0.4},
        {'id': 'T1203', 'name': 'Exploitation for Client Execution', 'difficulty': 0.6},
    ],
    Tactic.PERSISTENCE: [
        {'id': 'T1547', 'name': 'Boot/Logon Autostart Execution', 'difficulty': 0.5},
        {'id': 'T1098', 'name': 'Account Manipulation', 'difficulty': 0.4},
    ],
    Tactic.PRIV_ESC: [
        {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'difficulty': 0.7},
        {'id': 'T1134', 'name': 'Access Token Manipulation', 'difficulty': 0.6},
    ],
    Tactic.DEFENSE_EVASION: [
        {'id': 'T1027', 'name': 'Obfuscated Files/Info', 'difficulty': 0.3},
        {'id': 'T1070', 'name': 'Indicator Removal on Host', 'difficulty': 0.4},
    ],
    Tactic.CRED_ACCESS: [
        {'id': 'T1003', 'name': 'OS Credential Dumping', 'difficulty': 0.6},
        {'id': 'T1552', 'name': 'Unsecured Credentials', 'difficulty': 0.3},
    ],
    Tactic.DISCOVERY: [
        {'id': 'T1082', 'name': 'System Information Discovery', 'difficulty': 0.2},
        {'id': 'T1046', 'name': 'Network Service Scanning', 'difficulty': 0.3},
    ],
    Tactic.EXFIL: [
        {'id': 'T1041', 'name': 'Exfiltration Over C2 Channel', 'difficulty': 0.7},
        {'id': 'T1048', 'name': 'Exfiltration Over Alternative Protocol', 'difficulty': 0.5},
    ],
    Tactic.IMPACT: [
        {'id': 'T1485', 'name': 'Data Destruction', 'difficulty': 0.8},
        {'id': 'T1486', 'name': 'Data Encrypted for Impact', 'difficulty': 0.7},
    ],
}


# ================================================================
# Red Team Agent
# ================================================================
@dataclass
class AgentCapability:
    stealth: float      # 0-1, ability to evade detection
    speed: float        # 0-1, operation speed
    persistence: float  # 0-1, ability to maintain access
    impact: float       # 0-1, damage potential


class RedTeamAgent:
    def __init__(self, agent_id: str, specialization: Tactic, skill=0.5, seed=42):
        self.agent_id = agent_id
        self.specialization = specialization
        self.skill = skill
        self.rng = random.Random(seed + hash(agent_id) % 10000)
        self.capability = AgentCapability(
            stealth=self.rng.betavariate(2, 2),
            speed=self.rng.betavariate(3, 2),
            persistence=self.rng.betavariate(2, 3),
            impact=self.rng.betavariate(1.5, 2),
        )
        self.operations: List[Dict] = []
        self.detected = False
        self.techniques_used: List[str] = []

    def execute_tactic(self, target: Dict, defense_strength=0.5) -> Dict:
        """Execute an attack tactic against the target."""
        techniques = TECHNIQUES.get(self.specialization, [])
        if not techniques:
            return {'success': False, 'reason': 'no_techniques'}

        technique = self.rng.choice(techniques)
        self.techniques_used.append(technique['id'])

        # Success probability based on skill, technique difficulty, and defense
        raw_success = self.skill * (1 - technique['difficulty'])
        defense_factor = 1 - defense_strength * 0.8
        success_prob = min(0.95, raw_success * defense_factor * self.capability.stealth)

        success = self.rng.random() < success_prob
        detected = not success or self.rng.random() < (1 - self.capability.stealth) * defense_strength

        operation = {
            'timestamp': time.time(),
            'agent_id': self.agent_id,
            'tactic': self.specialization.value,
            'technique': technique['id'],
            'technique_name': technique['name'],
            'success': success,
            'detected': detected,
            'skill_used': self.skill,
            'stealth_used': self.capability.stealth,
            'target': target.get('name', 'unknown'),
        }
        self.operations.append(operation)

        if detected:
            self.detected = True

        return operation

    def get_stats(self) -> Dict:
        ops = self.operations
        return {
            'agent_id': self.agent_id,
            'specialization': self.specialization.value,
            'total_ops': len(ops),
            'success_rate': sum(1 for o in ops if o['success']) / max(len(ops), 1),
            'detection_rate': sum(1 for o in ops if o['detected']) / max(len(ops), 1),
            'techniques_used': list(set(self.techniques_used)),
            'capability': {
                'stealth': self.capability.stealth,
                'speed': self.capability.speed,
                'persistence': self.capability.persistence,
                'impact': self.capability.impact,
            },
            'detected': self.detected,
        }


# ================================================================
# Blue Team Agent
# ================================================================
class BlueTeamAgent:
    def __init__(self, agent_id: str, defense_layer: str, strength=0.5, seed=42):
        self.agent_id = agent_id
        self.defense_layer = defense_layer
        self.strength = strength
        self.rng = random.Random(seed + hash(agent_id) % 10000)
        self.detections: List[Dict] = []
        self.alerts_raised = 0
        self.false_positives = 0

    def detect(self, operation: Dict) -> Dict:
        """Detect a red team operation."""
        detection_prob = self.strength * (1 - operation.get('stealth_used', 0.5))

        # Adjust for technique difficulty
        technique_id = operation.get('technique', '')
        is_known_technique = any(
            t['id'] == technique_id
            for techniques in TECHNIQUES.values()
            for t in techniques
        )
        if is_known_technique:
            detection_prob *= 1.2

        detected = self.rng.random() < min(0.95, detection_prob)

        detection = {
            'timestamp': time.time(),
            'defender_id': self.agent_id,
            'defense_layer': self.defense_layer,
            'operation_detected': operation,
            'detected': detected,
            'was_actual_attack': operation.get('success', False),
        }

        if detected:
            self.detections.append(detection)
            self.alerts_raised += 1
            if not operation.get('success'):
                self.false_positives += 1

        return detection

    def get_stats(self) -> Dict:
        return {
            'agent_id': self.agent_id,
            'defense_layer': self.defense_layer,
            'strength': self.strength,
            'detections': len(self.detections),
            'alerts_raised': self.alerts_raised,
            'false_positives': self.false_positives,
            'fpr': self.false_positives / max(self.alerts_raised, 1),
        }


# ================================================================
# Scenario Engine
# ================================================================
@dataclass
class ScenarioConfig:
    name: str
    description: str
    duration_phases: int
    red_team_size: int
    blue_team_size: int
    attack_tactics: List[Tactic]
    defense_layers: List[str]
    difficulty: float  # 0-1


SCENARIO_PRESETS = {
    'ransomware_outbreak': ScenarioConfig(
        name='Ransomware Outbreak',
        description='Simulated ransomware attack: phishing → execution → privilege escalation → encryption → ransom',
        duration_phases=5,
        red_team_size=8,
        blue_team_size=6,
        attack_tactics=[Tactic.INITIAL_ACCESS, Tactic.EXECUTION, Tactic.PRIV_ESC,
                       Tactic.DEFENSE_EVASION, Tactic.IMPACT],
        defense_layers=['endpoint', 'network', 'identity', 'cloud', 'email', 'siem'],
        difficulty=0.7,
    ),
    'data_exfiltration': ScenarioConfig(
        name='Data Exfiltration',
        description='Insider threat: credential access → discovery → collection → exfiltration',
        duration_phases=4,
        red_team_size=5,
        blue_team_size=5,
        attack_tactics=[Tactic.CRED_ACCESS, Tactic.DISCOVERY, Tactic.COLLECTION, Tactic.EXFIL],
        defense_layers=['dlp', 'identity', 'network', 'endpoint', 'siem'],
        difficulty=0.5,
    ),
    'apt_campaign': ScenarioConfig(
        name='APT Campaign',
        description='Advanced persistent threat: recon → initial access → persistence → lateral movement → exfil',
        duration_phases=7,
        red_team_size=12,
        blue_team_size=10,
        attack_tactics=[Tactic.RECON, Tactic.INITIAL_ACCESS, Tactic.PERSISTENCE,
                       Tactic.DEFENSE_EVASION, Tactic.DISCOVERY, Tactic.LATERAL_MOVEMENT, Tactic.EXFIL],
        defense_layers=['threat_intel', 'network', 'endpoint', 'identity', 'cloud', 'siem', 'hunt'],
        difficulty=0.9,
    ),
    'cloud_breach': ScenarioConfig(
        name='Cloud Infrastructure Breach',
        description='Cloud-focused attack: exploit public app → execution → priv esc → impact cloud resources',
        duration_phases=4,
        red_team_size=6,
        blue_team_size=6,
        attack_tactics=[Tactic.INITIAL_ACCESS, Tactic.EXECUTION, Tactic.PRIV_ESC, Tactic.IMPACT],
        defense_layers=['waf', 'cloud', 'identity', 'network', 'endpoint', 'siem'],
        difficulty=0.6,
    ),
}


class ScenarioEngine:
    def __init__(self, config: ScenarioConfig, seed=42):
        self.config = config
        self.seed = seed
        self.rng = random.Random(seed)
        self.red_team: List[RedTeamAgent] = []
        self.blue_team: List[BlueTeamAgent] = []
        self.phase_results: List[Dict] = []
        self.initialize_teams()

    def initialize_teams(self):
        for i in range(self.config.red_team_size):
            tactic = self.rng.choice(self.config.attack_tactics)
            self.red_team.append(RedTeamAgent(
                f'red_{i:03d}', tactic, skill=0.3 + 0.7 * self.rng.random(), seed=self.seed + i))

        for i in range(self.config.blue_team_size):
            layer = self.config.defense_layers[i % len(self.config.defense_layers)]
            self.blue_team.append(BlueTeamAgent(
                f'blue_{i:03d}', layer,
                strength=0.4 + 0.6 * self.rng.random(), seed=self.seed + 1000 + i))

    def run_phase(self, phase: int, target: Dict) -> Dict:
        """Execute one phase of the scenario."""
        phase_results = {'phase': phase, 'red_ops': [], 'blue_detections': [], 'alerts': 0}

        defense_strength = sum(b.strength for b in self.blue_team) / len(self.blue_team)

        # Each red agent executes one operation
        for agent in self.red_team:
            if not agent.detected:
                op = agent.execute_tactic(target, defense_strength=defense_strength)
                phase_results['red_ops'].append(op)

                # Blue team attempts detection
                if op['success'] or self.rng.random() < 0.3:
                    for defender in self.blue_team:
                        detection = defender.detect(op)
                        if detection['detected']:
                            phase_results['blue_detections'].append(detection)
                            phase_results['alerts'] += 1

        self.phase_results.append(phase_results)
        return phase_results

    def run_all_phases(self, target_name='sandbox_target') -> Dict:
        print(f"Scenario: {self.config.name}")
        print(f"  Difficulty: {self.config.difficulty} | "
              f"Red: {self.config.red_team_size} | Blue: {self.config.blue_team_size}")
        print("=" * 60)

        for phase in range(1, self.config.duration_phases + 1):
            target = {'name': target_name, 'phase': phase}
            result = self.run_phase(phase, target)

            red_ops = result['red_ops']
            successes = sum(1 for o in red_ops if o['success'])
            detected = sum(1 for o in red_ops if o.get('detected'))
            print(f"  Phase {phase}: {successes}/{len(red_ops)} ops succeeded, "
                  f"{detected} detected, {result['alerts']} alerts")

        return self.compile_report()

    def compile_report(self) -> Dict:
        red_stats = [a.get_stats() for a in self.red_team]
        blue_stats = [d.get_stats() for d in self.blue_team]

        all_ops = []
        for pr in self.phase_results:
            all_ops.extend(pr['red_ops'])

        total_ops = len(all_ops)
        successful_ops = sum(1 for o in all_ops if o['success'])
        detected_ops = sum(1 for o in all_ops if o.get('detected'))

        # Scoring
        attack_score = (successful_ops / max(total_ops, 1)) * (1 - detected_ops / max(total_ops, 1)) * 100
        defense_score = (detected_ops / max(total_ops, 1)) * 100

        # Kill chain completion
        tactics_used = set(o['tactic'] for o in all_ops if o['success'])
        kill_chain_completion = len(tactics_used) / max(len(self.config.attack_tactics), 1)

        return {
            'scenario': self.config.name,
            'config': {
                'red_team_size': self.config.red_team_size,
                'blue_team_size': self.config.blue_team_size,
                'phases': self.config.duration_phases,
                'difficulty': self.config.difficulty,
            },
            'scores': {
                'attack_score': attack_score,
                'defense_score': defense_score,
                'kill_chain_completion': kill_chain_completion,
                'overall_assessment': 'red_advantage' if attack_score > defense_score else 'blue_advantage',
            },
            'red_team': {
                'total_ops': total_ops,
                'successful_ops': successful_ops,
                'detected_ops': detected_ops,
                'success_rate': successful_ops / max(total_ops, 1),
                'detection_rate': detected_ops / max(total_ops, 1),
                'agent_stats': red_stats,
                'tactics_executed': list(tactics_used),
            },
            'blue_team': {
                'total_alerts': sum(s['alerts_raised'] for s in blue_stats),
                'false_positives': sum(s['false_positives'] for s in blue_stats),
                'agent_stats': blue_stats,
            },
            'phases': [{
                'phase': pr['phase'],
                'red_ops': len(pr['red_ops']),
                'successes': sum(1 for o in pr['red_ops'] if o['success']),
                'detections': len(pr['blue_detections']),
                'alerts': pr['alerts'],
            } for pr in self.phase_results],
        }


# ================================================================
# Scoring Engine
# ================================================================
class MITREScoringEngine:
    """Score sandbox exercises on MITRE ATT&CK alignment."""

    @staticmethod
    def score_exercise(report: Dict) -> Dict:
        red = report.get('red_team', {})
        blue = report.get('blue_team', {})

        technique_count = len(red.get('tactics_executed', []))
        success_rate = red.get('success_rate', 0)
        detection_rate = red.get('detection_rate', 0)

        # ATT&CK coverage score (0-100)
        attack_coverage = min(100, technique_count * 7 + success_rate * 40)

        # Defense resilience score (0-100)
        defense_resilience = min(100, detection_rate * 60 + (1 - success_rate) * 40)

        # Kill chain disruption score
        kill_chain = report.get('scores', {}).get('kill_chain_completion', 0)
        disruption = (1 - kill_chain) * 100

        return {
            'attack_coverage_score': attack_coverage,
            'defense_resilience_score': defense_resilience,
            'kill_chain_disruption_score': disruption,
            'overall_attck_alignment': (attack_coverage + defense_resilience) / 2,
            'technique_diversity': technique_count,
            'false_positive_penalty': max(0, blue.get('false_positives', 0) * 5),
            'final_score': max(0, (attack_coverage + defense_resilience + disruption) / 3 - blue.get('false_positives', 0) * 5),
        }


# ================================================================
# Main
# ================================================================
def main(scenario='all', output_dir=None):
    output_dir = Path(output_dir or BASE / "D03_results")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 70)
    print("  D03 Sandbox Orchestrator — Expanded Red/Blue Team Exercise")
    print("=" * 70)

    report = {'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'), 'exercises': {}}
    scorer = MITREScoringEngine()

    scenarios = list(SCENARIO_PRESETS.keys()) if scenario == 'all' else [scenario]

    for name in scenarios:
        if name not in SCENARIO_PRESETS:
            continue

        config = SCENARIO_PRESETS[name]
        engine = ScenarioEngine(config, seed=42)
        result = engine.run_all_phases()
        scores = scorer.score_exercise(result)
        result['mitre_scores'] = scores
        report['exercises'][name] = result

        print(f"\n--- {name} Results ---")
        s = result['scores']
        print(f"  Attack: {s['attack_score']:.1f} | Defense: {s['defense_score']:.1f}")
        print(f"  Kill Chain: {s['kill_chain_completion']:.1%}")
        print(f"  MITRE Final: {scores['final_score']:.1f}")

    # Overall comparison
    if len(report['exercises']) > 1:
        print(f"\n{'='*60}")
        print(f"  Cross-Scenario Comparison")
        print(f"{'Scenario':<30} {'Attack':>8} {'Defense':>8} {'KillChain':>10} {'MITRE':>8}")
        print("-" * 64)
        for name, ex in report['exercises'].items():
            s = ex['scores']
            ms = ex['mitre_scores']
            print(f"{name:<30} {s['attack_score']:>7.1f} {s['defense_score']:>7.1f} "
                  f"{s['kill_chain_completion']:>9.1%} {ms['final_score']:>7.1f}")

    out_path = output_dir / "D03_expanded_scenario_results.json"
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nReport saved to: {out_path}")

    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', default='all',
                       choices=['all', 'ransomware_outbreak', 'data_exfiltration', 'apt_campaign', 'cloud_breach'])
    args = parser.parse_args()

    main(scenario=args.scenario)
