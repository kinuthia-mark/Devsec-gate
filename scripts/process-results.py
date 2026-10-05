#!/usr/bin/env python3
"""
process-results.py

Runs the OPA policy bundle against scan input, queries all outputs,
and renders a triage report. Blocks the pipeline if allow == false.

Usage:
    python3 scripts/process-results.py [path/to/input.json]

Exit code 0 means the gate passed, 1 means it blocked (or OPA could not run).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_DIR = os.path.join(REPO_ROOT, "policies")
DEFAULT_INPUT = os.path.join(REPO_ROOT, "fixtures", "scan-blocked.json")
RESULTS_DIR = os.path.join(REPO_ROOT, "scan-results")


def resolve_opa_binary() -> str:
    """Find OPA executable on PATH or in common locations."""
    if shutil.which("opa"):
        return "opa"
    
    candidates = [
        os.path.join(REPO_ROOT, "opa.exe"),
        os.path.join(REPO_ROOT, "opa"),
        os.path.join(os.path.expanduser("~"), "bin", "opa.exe"),
        os.path.join(os.path.expanduser("~"), "bin", "opa"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    
    print("[ERROR] OPA not found. Install OPA and add to PATH.")
    sys.exit(1)


def run_opa_query(input_path: str, query: str) -> dict | list | bool | None:
    """Run a single OPA query and return the result."""
    opa_cmd = resolve_opa_binary()
    cmd = [opa_cmd, "eval", "--data", POLICY_DIR, "--input", input_path,
           "--format", "json", query]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[WARNING] OPA query '{query}' failed: {result.stderr}")
        return None
    
    try:
        parsed = json.loads(result.stdout)
        if parsed.get("result"):
            value = parsed["result"][0]["expressions"][0]["value"]
            return value
        return None
    except (KeyError, IndexError, json.JSONDecodeError):
        print(f"[WARNING] Could not parse OPA output for '{query}'")
        return None


EMPTY_NOISE = {
    "total_findings": 0,
    "actionable_findings": 0,
    "false_positives_filtered": 0,
    "excluded_packages_filtered": 0,
    "total_filtered": 0,
    "noise_reduction_percentage": 0,
}

EMPTY_SLA = {
    "overall_status": "UNKNOWN",
    "compliance_percentage": 0,
    "violations_detail": [],
}


def fetch_all_outputs(input_path: str) -> dict:
    """Evaluate the whole devsecops package once and pick out the parts
    the report needs. policy.rego and sla_gate.rego share that package."""
    bundle = run_opa_query(input_path, "data.devsecops")
    if not isinstance(bundle, dict):
        # Fail closed: if the policies cannot be evaluated, nothing passes.
        print("[ERROR] Could not evaluate the devsecops policies. Blocking.")
        bundle = {}

    return {
        "allow": bundle.get("allow", False) is True,
        "violated_policies": sorted(bundle.get("violated_policies") or []),
        "noise_statistics": bundle.get("noise_statistics") or EMPTY_NOISE,
        "sla_compliance_report": bundle.get("sla_compliance_report") or EMPTY_SLA,
        "violation_report": bundle.get("violation_report") or {},
    }


def render_report(decision: dict) -> bool:
    """Print the triage report. Return True if build passes."""
    allow = decision.get("allow", False)
    violated_policies = decision.get("violated_policies", [])
    noise = decision.get("noise_statistics", {})
    sla = decision.get("sla_compliance_report", {})
    
    print("=" * 60)
    print("DevSecOps Governance Gate - Triage Report")
    print("=" * 60)
    
    print(f"\nScanned findings : {noise.get('total_findings', 0)}")
    print(f"Actionable        : {noise.get('actionable_findings', 0)}")
    print(f"False positives   : {noise.get('false_positives_filtered', 0)}")
    print(f"Excluded packages : {noise.get('excluded_packages_filtered', 0)}")
    print(f"Noise reduction   : {noise.get('noise_reduction_percentage', 0)}%")
    
    if sla.get("violations_detail"):
        print(f"\nSLA status        : {sla.get('overall_status', 'UNKNOWN')}")
        print(f"SLA compliance    : {sla.get('compliance_percentage', 0)}%")
        for v in sla.get("violations_detail", []):
            print(f"  [SLA BREACH] {v['vulnerability_id']} ({v['severity']}) "
                  f"in '{v['package']}' - {v['overdue_by_days']}d over "
                  f"the {v['sla_days']}d window")
    
    if violated_policies:
        print("\n--- POLICY VIOLATIONS (blocking) ---")
        for msg in violated_policies:
            print(f"  [FAIL] {msg}")
    else:
        print("\nNo blocking policy violations.")
    
    print(f"\nGate decision: {'PASS' if allow else 'BLOCK'}")
    print("=" * 60)
    
    return allow


def write_summary(decision: dict) -> str:
    """Write decision to JSON file."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "triage-summary.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(decision, f, indent=2)
    print(f"\nFull JSON summary written to: {out_path}")
    return out_path


def create_ticket(summary_path: str) -> bool:
    """Call create-ticket.py to file an issue."""
    create_ticket_script = os.path.join(
        os.path.dirname(__file__), "create-ticket.py")
    
    if not os.path.exists(create_ticket_script):
        print("[WARNING] create-ticket.py not found. Skipping ticket creation.")
        return True
    
    print("\n--> Creating issue ticket...")
    result = subprocess.run(
        [sys.executable, create_ticket_script, summary_path],
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    if result.stderr and "DeprecationWarning" not in result.stderr:
        print(result.stderr, file=sys.stderr)
    
    return result.returncode == 0


def main() -> None:
    input_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT
    
    if not os.path.exists(input_path):
        print(f"[ERROR] Input file not found: {input_path}")
        sys.exit(1)
    
    print(f"[*] Evaluating policies against: {input_path}\n")
    
    decision = fetch_all_outputs(input_path)
    summary_path = write_summary(decision)
    allow = render_report(decision)
    
    if not allow:
        create_ticket(summary_path)
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()