"""Tests for the Python scripts around the OPA policies.

Run with:  python -m pytest tests/ -v
The gate tests need the `opa` binary on PATH and are skipped without it.
"""
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
SCRIPTS = ROOT / "scripts"


def load_script(name):
    """Scripts use hyphenated file names, so import them by path."""
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


normalize_trivy = load_script("normalize-trivy")
needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa is not installed")


# --- normalize-trivy.py -----------------------------------------------------

@pytest.fixture
def gate_input():
    report = json.loads((FIXTURES / "trivy-sample.json").read_text())
    kev = normalize_trivy.load_kev(str(FIXTURES / "kev-sample.json"))
    return normalize_trivy.normalize(report, kev, "2024-09-14T10:30:00Z")


def by_id(gate_input, vid):
    return next(f for f in gate_input["vulnerabilities"] if f["id"] == vid)


def test_duplicates_across_targets_are_merged(gate_input):
    ids = [f["id"] for f in gate_input["vulnerabilities"]]
    assert ids.count("CVE-2021-44228") == 1
    assert len(ids) == 4


def test_highest_v3_score_is_used(gate_input):
    assert by_id(gate_input, "CVE-2024-6119")["cvss_score"] == 7.5


def test_kev_listed_cve_is_marked_exploited(gate_input):
    log4 = by_id(gate_input, "CVE-2021-44228")
    assert log4["active_exploitation"] and log4["exploit_available"] and log4["public_exploit"]
    assert not by_id(gate_input, "CVE-2024-6119")["active_exploitation"]


def test_missing_fix_and_dev_dependency_are_noted(gate_input):
    assert "no fix available" in by_id(gate_input, "CVE-2023-42366")["description"]
    assert "dev dependency only" in by_id(gate_input, "CVE-2022-25883")["description"]


def test_dates_are_rfc3339(gate_input):
    assert by_id(gate_input, "CVE-2024-6119")["discovered_date"] == "2024-09-03T16:15:06Z"


def test_unknown_severity_and_missing_cvss_get_defaults():
    report = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "X-1", "PkgName": "p", "Severity": "UNKNOWN"}]}]}
    finding = normalize_trivy.normalize(report, set(), "2024-01-01T00:00:00Z")["vulnerabilities"][0]
    assert finding["severity"] == "LOW"
    assert finding["cvss_score"] == normalize_trivy.DEFAULT_CVSS["LOW"]
    assert finding["discovered_date"] == "2024-01-01T00:00:00Z"


def test_empty_report():
    assert normalize_trivy.normalize({"Results": None}, set(), "2024-01-01T00:00:00Z")["vulnerabilities"] == []


def test_cli_writes_output(tmp_path):
    out = tmp_path / "gate.json"
    code = normalize_trivy.main([str(FIXTURES / "trivy-sample.json"), "-o", str(out), "--scan-date", "2024-09-14T10:30:00Z"])
    assert code == 0
    assert json.loads(out.read_text())["source"]["artifact"] == "devsecops-gateway:demo"


# --- the gate end to end ----------------------------------------------------

def run_gate(input_path, cwd):
    return subprocess.run([sys.executable, str(SCRIPTS / "process-results.py"), str(input_path)],
                          capture_output=True, text=True, cwd=cwd)


@needs_opa
def test_gate_blocks_the_blocked_fixture(tmp_path):
    result = run_gate(FIXTURES / "scan-blocked.json", tmp_path)
    assert result.returncode == 1
    assert "Gate decision: BLOCK" in result.stdout
    summary = json.loads((ROOT / "scan-results" / "triage-summary.json").read_text())
    assert summary["noise_statistics"]["false_positives_filtered"] == 2
    assert summary["noise_statistics"]["noise_reduction_percentage"] == 67
    assert summary["violated_policies"] == ["CRITICAL vulnerability detected - must be remediated"]


@needs_opa
def test_gate_passes_the_clean_fixture(tmp_path):
    result = run_gate(FIXTURES / "scan-clean.json", tmp_path)
    assert result.returncode == 0
    assert "Gate decision: PASS" in result.stdout


@needs_opa
def test_trivy_report_with_kev_critical_is_blocked(tmp_path):
    gate = tmp_path / "gate.json"
    normalize_trivy.main([str(FIXTURES / "trivy-sample.json"), "-o", str(gate),
                          "--kev", str(FIXTURES / "kev-sample.json"), "--scan-date", "2024-09-14T10:30:00Z"])
    result = run_gate(gate, tmp_path)
    assert result.returncode == 1
    assert "CRITICAL vulnerability detected" in result.stdout
    # The dev-only HIGH must not be the reason for a HIGH block on its own.
    summary = json.loads((ROOT / "scan-results" / "triage-summary.json").read_text())
    assert summary["noise_statistics"]["false_positives_filtered"] == 1


# --- create-ticket.py -------------------------------------------------------

def test_ticket_falls_back_to_a_local_log_without_jira(tmp_path, monkeypatch):
    for var in ["JIRA_URL", "JIRA_USER", "JIRA_TOKEN"]:
        monkeypatch.delenv(var, raising=False)
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps({"allow": False, "violated_policies": ["CRITICAL vulnerability detected"]}))
    result = subprocess.run([sys.executable, str(SCRIPTS / "create-ticket.py"), str(summary)],
                            capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0
    assert "Jira not configured" in result.stdout
