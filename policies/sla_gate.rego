# policies/sla_gate.rego
#
# Severity-weighted SLA enforcement. Computes days-since-discovery for
# every finding and flags anything that has aged past its remediation
# window. Shares the "devsecops" package with policy.rego so both
# evaluate together under a single OPA query.
package devsecops

import rego.v1

# Default catch-all SLA window (days) for any severity not explicitly mapped.
default_sla_days := 9

critical_sla_days := 3
high_sla_days := 7
medium_sla_days := 14
low_sla_days := 30

default within_sla := false

within_sla if {
	count(sla_violations) == 0
}

sla_violations contains violation if {
	some vuln in input.vulnerabilities

	# Confirmed false positives are kept for the audit trail but have no
	# remediation deadline.
	not is_false_positive(vuln)

	discovered := parse_iso_date(vuln.discovered_date)
	scanned := parse_iso_date(input.scan_date)
	days_open := days_between(discovered, scanned)
	max_days := sla_for_severity(vuln.severity)
	days_open > max_days

	violation := {
		"vulnerability_id": vuln.id,
		"package": vuln.package_name,
		"severity": vuln.severity,
		"days_since_discovery": days_open,
		"sla_days": max_days,
		"overdue_by_days": days_open - max_days,
		"status": "VIOLATED",
	}
}

sla_for_severity(severity) := critical_sla_days if severity == "CRITICAL"
sla_for_severity(severity) := high_sla_days if severity == "HIGH"
sla_for_severity(severity) := medium_sla_days if severity == "MEDIUM"
sla_for_severity(severity) := low_sla_days if severity == "LOW"
sla_for_severity(severity) := default_sla_days if {
	not severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
}

parse_iso_date(date_string) := time.parse_rfc3339_ns(date_string)

days_between(start_ns, end_ns) := days if {
	ns_per_day := 86400000000000
	days := floor((end_ns - start_ns) / ns_per_day)
}

overall_sla_status(within) := "COMPLIANT" if within == true
overall_sla_status(within) := "VIOLATED" if within == false

# Guards against divide-by-zero on an empty scan.
sla_compliance_report := report if {
	total := count(input.vulnerabilities)
	total > 0
	violations := sla_violations
	compliant := total - count(violations)

	report := {
		"overall_status": overall_sla_status(count(violations) == 0),
		"total_vulnerabilities": total,
		"compliant_vulnerabilities": compliant,
		"sla_violated_vulnerabilities": count(violations),
		"compliance_percentage": round((compliant / total) * 100),
		"violations_detail": violations,
	}
}

sla_compliance_report := report if {
	count(input.vulnerabilities) == 0
	report := {
		"overall_status": "COMPLIANT",
		"total_vulnerabilities": 0,
		"compliant_vulnerabilities": 0,
		"sla_violated_vulnerabilities": 0,
		"compliance_percentage": 100,
		"violations_detail": [],
	}
}
