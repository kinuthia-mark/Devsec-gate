# policies/policy_test.rego
#
# Unit tests for the gate. Run with:  opa test policies/ -v
package devsecops_test

import data.devsecops
import rego.v1

finding(overrides) := object.union(
	{
		"id": "CVE-TEST-0001",
		"package_name": "lib",
		"package_version": "1.0.0",
		"severity": "LOW",
		"cvss_score": 2.0,
		"description": "test finding",
		"discovered_date": "2024-09-10T00:00:00Z",
		"exploit_available": false,
		"public_exploit": false,
		"active_exploitation": false,
		"false_positive": false,
	},
	overrides,
)

scan(vulns) := {"scan_date": "2024-09-14T10:30:00Z", "vulnerabilities": vulns}

# --- allow / block --------------------------------------------------------

test_empty_scan_passes if {
	devsecops.allow with input as scan([])
}

test_real_critical_blocks if {
	not devsecops.allow with input as scan([finding({"severity": "CRITICAL", "cvss_score": 9.8})])
}

test_critical_marked_false_positive_passes if {
	devsecops.allow with input as scan([finding({"severity": "CRITICAL", "cvss_score": 9.8, "false_positive": true})])
}

test_one_real_critical_among_false_positives_still_blocks if {
	not devsecops.allow with input as scan([
		finding({"id": "a", "severity": "CRITICAL", "false_positive": true}),
		finding({"id": "b", "severity": "CRITICAL"}),
	])
}

test_exploitable_high_blocks if {
	not devsecops.allow with input as scan([finding({"severity": "HIGH", "cvss_score": 6.5, "public_exploit": true})])
}

test_high_without_exploit_path_passes if {
	devsecops.allow with input as scan([finding({"severity": "HIGH", "cvss_score": 6.5})])
}

test_dev_only_high_does_not_block if {
	devsecops.allow with input as scan([finding({"severity": "HIGH", "cvss_score": 7.5, "description": "Dev dependency only"})])
}

test_excluded_package_does_not_block if {
	devsecops.allow with input as scan([finding({
		"severity": "CRITICAL",
		"package_name": "test-package",
		"package_version": "1.0.0",
	})])
}

test_medium_never_blocks if {
	devsecops.allow with input as scan([finding({"severity": "MEDIUM", "cvss_score": 6.9, "exploit_available": true})])
}

# --- noise statistics -----------------------------------------------------

test_noise_statistics_on_empty_scan if {
	stats := devsecops.noise_statistics with input as scan([])
	stats.total_findings == 0
	stats.noise_reduction_percentage == 0
}

test_noise_statistics_counts if {
	stats := devsecops.noise_statistics with input as scan([
		finding({"id": "a", "severity": "CRITICAL", "cvss_score": 9.1}),
		finding({"id": "b", "severity": "HIGH", "false_positive": true}),
		finding({"id": "c", "severity": "MEDIUM", "description": "build-time only"}),
		finding({"id": "d", "severity": "MEDIUM", "cvss_score": 5.0}),
	])
	stats.total_findings == 4
	stats.actionable_findings == 1
	stats.false_positives_filtered == 2
	stats.noise_reduction_percentage == 50
}

# --- SLA ------------------------------------------------------------------

test_critical_past_three_days_is_an_sla_breach if {
	report := devsecops.sla_compliance_report with input as scan([finding({
		"severity": "CRITICAL",
		"discovered_date": "2024-09-01T00:00:00Z",
	})])
	report.overall_status == "VIOLATED"
	some v in report.violations_detail
	v.days_since_discovery == 13
	v.overdue_by_days == 10
}

test_low_within_thirty_days_is_compliant if {
	report := devsecops.sla_compliance_report with input as scan([finding({
		"severity": "LOW",
		"discovered_date": "2024-08-20T00:00:00Z",
	})])
	report.overall_status == "COMPLIANT"
	report.compliance_percentage == 100
}

test_empty_scan_is_sla_compliant if {
	report := devsecops.sla_compliance_report with input as scan([])
	report.overall_status == "COMPLIANT"
}
