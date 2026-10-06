#!/usr/bin/env python3
"""
normalize-trivy.py

Converts a Trivy JSON report into the input format the OPA policies expect,
so the gate can decide on real scanner output instead of a fixture.

Usage:
    trivy image --format json -o trivy.json my-image:tag
    python3 scripts/normalize-trivy.py trivy.json -o scan-results/gate-input.json \
        [--kev known_exploited_vulnerabilities.json] [--scan-date 2026-10-06T00:00:00Z]

How each gate field is filled:

    id                   VulnerabilityID (CVE-..., GHSA-...)
    package_name         PkgName
    package_version      InstalledVersion
    severity             Severity (UNKNOWN becomes LOW)
    cvss_score           highest V3 score across CVSS sources, else V2, else
                         a default for the severity
    description          Title, plus "no fix available" when Trivy has no
                         FixedVersion, plus "dev dependency only" for
                         packages Trivy marks as development dependencies
    discovered_date      PublishedDate (conservative: SLA clocks start when
                         the CVE became public, not when we first saw it)
    exploit_available,   true when the CVE is in the CISA Known Exploited
    public_exploit,      Vulnerabilities catalogue passed with --kev
    active_exploitation
    false_positive       false (suppressions belong in the policy, not here)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

DEFAULT_CVSS = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}


def load_kev(path: str | None) -> set[str]:
    """CVE IDs from the CISA KEV catalogue (JSON feed), or an empty set."""
    if not path:
        return set()
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {item["cveID"] for item in data.get("vulnerabilities", []) if "cveID" in item}


def best_cvss(vuln: dict) -> float | None:
    """Highest V3 score reported by any source; falls back to V2."""
    v3 = [s.get("V3Score") for s in (vuln.get("CVSS") or {}).values() if s.get("V3Score")]
    if v3:
        return float(max(v3))
    v2 = [s.get("V2Score") for s in (vuln.get("CVSS") or {}).values() if s.get("V2Score")]
    return float(max(v2)) if v2 else None


def to_rfc3339(value: str | None, fallback: str) -> str:
    """Trivy dates look like 2023-07-11T15:15:10.637Z; OPA wants RFC 3339."""
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize(report: dict, kev: set[str], scan_date: str) -> dict:
    findings = []
    seen = set()

    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            vid = vuln.get("VulnerabilityID", "UNKNOWN")
            pkg = vuln.get("PkgName", "unknown")
            version = vuln.get("InstalledVersion", "")
            key = (vid, pkg, version)
            if key in seen:  # the same CVE can be reported by several targets
                continue
            seen.add(key)

            severity = (vuln.get("Severity") or "LOW").upper()
            if severity not in DEFAULT_CVSS:
                severity = "LOW"

            notes = [vuln.get("Title") or vid]
            if not vuln.get("FixedVersion"):
                notes.append("no fix available")
            if vuln.get("PkgIdentifier", {}).get("Dev") or vuln.get("Dev"):
                notes.append("dev dependency only")

            exploited = vid in kev
            findings.append({
                "id": vid,
                "package_name": pkg,
                "package_version": version,
                "severity": severity,
                "cvss_score": best_cvss(vuln) or DEFAULT_CVSS[severity],
                "description": " - ".join(notes),
                "discovered_date": to_rfc3339(vuln.get("PublishedDate"), scan_date),
                "exploit_available": exploited,
                "public_exploit": exploited,
                "active_exploitation": exploited,
                "false_positive": False,
            })

    return {
        "scan_date": scan_date,
        "source": {"scanner": "trivy", "artifact": report.get("ArtifactName", "")},
        "vulnerabilities": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert a Trivy JSON report into gate input.")
    parser.add_argument("report", help="Trivy JSON report (trivy ... --format json)")
    parser.add_argument("-o", "--output", default="scan-results/gate-input.json")
    parser.add_argument("--kev", help="CISA KEV catalogue JSON; listed CVEs are marked as actively exploited")
    parser.add_argument("--scan-date", help="RFC 3339 timestamp; defaults to now (UTC)")
    args = parser.parse_args(argv)

    scan_date = args.scan_date or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(args.report, encoding="utf-8") as fh:
        report = json.load(fh)

    gate_input = normalize(report, load_kev(args.kev), scan_date)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(gate_input, fh, indent=2)

    counts = {}
    for f in gate_input["vulnerabilities"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    exploited = sum(f["active_exploitation"] for f in gate_input["vulnerabilities"])
    print(f"[*] {len(gate_input['vulnerabilities'])} findings from {gate_input['source']['artifact'] or args.report}: "
          + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
          + f"; {exploited} in CISA KEV")
    print(f"[*] Gate input written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
