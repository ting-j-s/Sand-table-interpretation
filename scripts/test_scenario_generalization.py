#!/usr/bin/env python3
"""
Test Script — 通用安全场景推广验收测试

验证:
1. 每个场景都能正常运行 (mock 模式)
2. 每个场景输出报告中都有 scenario_spec
3. 每个场景的 domain 不同
4. 每个场景的 log_sources 不完全相同
5. 每个场景的 scenario_metrics 不完全相同
6. 旧企业场景仍然兼容
7. mock 模式不依赖任何 API Key
"""
import sys, os, json, subprocess, textwrap
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

TEST_SCENARIOS = [
    "enterprise_default",
    "campus_network",
    "hospital_medical_system",
    "industrial_control_system",
    "cloud_native_platform",
    "ecommerce_platform",
]

PASS, FAIL = 0, 0
results_report = []


def run(cmd, desc):
    global PASS, FAIL
    print(f"\n{'='*60}")
    print(f"  TEST: {desc}")
    print(f"  CMD:  {cmd}")
    print(f"{'='*60}")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120,
                          cwd=str(BASE_DIR))
        stdout = r.stdout[-2000:]
        stderr = r.stderr[-500:]
        exit_code = r.returncode
        if exit_code == 0:
            PASS += 1
            print("  RESULT: PASS")
            results_report.append({"test": desc, "status": "PASS"})
        else:
            FAIL += 1
            print(f"  RESULT: FAIL (exit={exit_code})")
            print(f"  STDOUT: {stdout[-500:]}")
            print(f"  STDERR: {stderr[-300:]}")
            results_report.append({"test": desc, "status": "FAIL", "error": stderr[:200]})
        return exit_code == 0, stdout
    except subprocess.TimeoutExpired:
        FAIL += 1
        print("  RESULT: TIMEOUT")
        results_report.append({"test": desc, "status": "TIMEOUT"})
        return False, ""
    except Exception as e:
        FAIL += 1
        print(f"  RESULT: ERROR: {e}")
        results_report.append({"test": desc, "status": "ERROR", "error": str(e)})
        return False, ""


def main():
    global PASS, FAIL

    print("=" * 60)
    print("  D03 通用安全场景推广 — 验收测试")
    print("=" * 60)

    # === Test 1: Scenario Loader ===
    print("\n--- Test 1: Scenario Loader ---")
    from D03_scenario_loader import ScenarioLoader

    scenarios = ScenarioLoader.list_scenarios()
    assert len(scenarios) >= 6, f"Expected >=6 scenarios, got {len(scenarios)}"

    domains = set()
    log_sources_sets = []
    metric_sets = []

    for s in scenarios:
        print(f"  [{s['domain']}] {s['id']} — {s['name']}")
        domains.add(s['domain'])

    # Verify all 6 domains are distinct
    assert len(domains) >= 6, f"Expected 6 distinct domains, got {len(domains)}: {domains}"
    PASS += 1
    results_report.append({"test": "Scenarios loaded (6 distinct domains)", "status": "PASS"})

    # === Test 2: Load each scenario and check attributes ===
    print("\n--- Test 2: Scenario Attributes ---")
    for sc_id in TEST_SCENARIOS:
        spec = ScenarioLoader.load(sc_id)
        print(f"\n  {sc_id}:")
        print(f"    domain={spec.domain}, assets={len(spec.assets)}, actors={len(spec.actors)}")
        print(f"    log_sources={spec.get_enabled_log_sources()}")
        metrics = list(spec.get_scenario_metrics().keys())
        print(f"    metrics={metrics}")

        assert spec.scenario_id == sc_id, f"scenario_id mismatch: {spec.scenario_id} != {sc_id}"
        assert len(spec.assets) > 0, f"No assets in {sc_id}"
        assert len(spec.actors) > 0, f"No actors in {sc_id}"
        assert len(spec.get_enabled_log_sources()) > 0, f"No log sources in {sc_id}"

        log_sources_sets.append(frozenset(spec.get_enabled_log_sources()))
        metric_sets.append(frozenset(metrics))

    # Verify log_sources vary across scenarios
    unique_log_sets = len(set(log_sources_sets))
    assert unique_log_sets >= 3, f"Expected >=3 unique log source sets, got {unique_log_sets}"
    PASS += 1
    results_report.append({"test": "Scenario attributes valid", "status": "PASS"})

    # Verify metrics vary
    unique_metric_sets = len(set(metric_sets))
    assert unique_metric_sets >= 3, f"Expected >=3 unique metric sets, got {unique_metric_sets}"
    PASS += 1
    results_report.append({"test": "Scenario metrics vary by domain", "status": "PASS"})

    # === Test 3: --list-scenarios CLI ===
    print("\n--- Test 3: CLI --list-scenarios ---")
    ok, stdout = run(
        f"python {BASE_DIR}/src/D03_real_runner.py --list-scenarios",
        "CLI list scenarios"
    )
    assert ok, "--list-scenarios failed"
    for sc_id in TEST_SCENARIOS:
        assert sc_id in stdout, f"Missing {sc_id} in --list-scenarios output"

    # === Test 4: Run each scenario in mock mode ===
    print("\n--- Test 4: Mock mode per scenario ---")
    for sc_id in TEST_SCENARIOS:
        ok, stdout = run(
            f"python {BASE_DIR}/src/D03_real_runner.py --mode mock --rounds 2 --scenario {sc_id}",
            f"Run {sc_id} in mock mode (2 rounds)"
        )
        assert ok, f"Mock run for {sc_id} failed"

    # === Test 5: Check report files for scenario info ===
    print("\n--- Test 5: Report contents ---")
    results_dir = BASE_DIR / "integration" / "D03_results"
    report_files = sorted(results_dir.glob("d03_real_*.json"), key=os.path.getmtime, reverse=True)[:6]

    report_domains = set()
    for rf in report_files:
        with open(rf) as f:
            report = json.load(f)
        assert "scenario_spec" in report, f"Report {rf.name} missing scenario_spec"
        assert "domain" in report, f"Report {rf.name} missing domain"
        report_domains.add(report.get("domain"))
        print(f"  {rf.name}: domain={report.get('domain')}, scenario_spec keys={list(report.get('scenario_spec', {}).keys())}")

    assert len(report_domains) >= 3, f"Expected >=3 domains in reports, got {len(report_domains)}"
    PASS += 1
    results_report.append({"test": "Reports contain scenario info", "status": "PASS"})

    # === Test 6: Verify mock works without API keys ===
    print("\n--- Test 6: Mock independence from API keys ---")
    # Unset any API keys temporarily
    saved_keys = {}
    for key in ["DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        saved_keys[key] = os.environ.pop(key, None)
    try:
        ok, stdout = run(
            f"python {BASE_DIR}/src/D03_real_runner.py --mode mock --rounds 1 --scenario enterprise_default",
            "Mock mode without API keys"
        )
        assert ok, "Mock mode should work without API keys"
    finally:
        for key, val in saved_keys.items():
            if val is not None:
                os.environ[key] = val

    # === Summary ===
    print("\n" + "=" * 60)
    print(f"  RESULTS: {PASS} PASS / {FAIL} FAIL")
    print("=" * 60)
    for r in results_report:
        symbol = "✓" if r["status"] == "PASS" else "✗"
        print(f"  {symbol} {r['test']}")

    return FAIL == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
