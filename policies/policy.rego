# policies/policy.rego
#
# Exploitability triage. Decides whether a batch of scanner findings is
# allowed through the gate, and reports how much noise was filtered out.
# sla_gate.rego lives in the same "devsecops" package, so one OPA query
# against data.devsecops returns the whole decision.
package devsecops

import rego.v1

default allow := false

allow if {
	count(violated_policies) == 0
}

# ---------------------------------------------------------------------------
# Blocking rules
# ---------------------------------------------------------------------------

violated_policies contains msg if {
	count(blocking_critical) > 0
	msg := "CRITICAL vulnerability detected - must be remediated"
}

violated_policies contains msg if {
	count(blocking_high) > 0
	msg := "HIGH exploitable vulnerability detected"
}

# A finding only counts towards a block decision if it is not a known false
# positive and its package is not on the exclusion list.
counts_for_blocking(vuln) if {
	not is_false_positive(vuln)
	not is_excluded_package(vuln)
}

# Every CRITICAL blocks, whether or not an exploit is known.
blocking_critical := [v |
	some v in input.vulnerabilities
	v.severity == "CRITICAL"
	counts_for_blocking(v)
]

# A HIGH blocks only when there is a realistic way to exploit it.
blocking_high := [v |
	some v in input.vulnerabilities
	v.severity == "HIGH"
	counts_for_blocking(v)
	is_exploitable(v)
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

is_exploitable(vuln) if vuln.cvss_score >= 7.0

is_exploitable(vuln) if vuln.exploit_available == true

is_exploitable(vuln) if vuln.public_exploit == true

is_exploitable(vuln) if vuln.active_exploitation == true

# Phrases scanners use for findings that cannot be reached in production.
false_positive_patterns := [
	"dev dependency only",
	"test dependency only",
	"build-time only",
	"not in executable path",
]

is_false_positive(vuln) if {
	some pattern in false_positive_patterns
	contains(lower(vuln.description), pattern)
}

is_false_positive(vuln) if vuln.false_positive == true

# Low-scoring LOW findings with no exploit are treated as noise.
is_false_positive(vuln) if {
	vuln.severity == "LOW"
	vuln.cvss_score < 4.0
	not vuln.exploit_available
}

# Packages the team has reviewed and accepted, written as "name:version".
excluded_packages := {
	"test-package:1.0.0",
	"deprecated-lib:0.0.1",
}

is_excluded_package(vuln) if {
	excluded_packages[sprintf("%s:%s", [vuln.package_name, vuln.package_version])]
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

actionable := array.concat(blocking_critical, blocking_high)

false_positives := [v | some v in input.vulnerabilities; is_false_positive(v)]

# Excluded packages that were not already counted as false positives, so
# nothing is counted twice in total_filtered.
excluded_only := [v |
	some v in input.vulnerabilities
	is_excluded_package(v)
	not is_false_positive(v)
]

noise_statistics := {
	"total_findings": total,
	"actionable_findings": count(actionable),
	"false_positives_filtered": count(false_positives),
	"excluded_packages_filtered": count(excluded_only),
	"total_filtered": filtered,
	"noise_reduction_percentage": percentage(filtered, total),
} if {
	total := count(input.vulnerabilities)
	filtered := count(false_positives) + count(excluded_only)
}

percentage(_, 0) := 0

percentage(part, whole) := round((part / whole) * 100) if whole > 0

violation_report := {
	"total_vulnerabilities": count(input.vulnerabilities),
	"actionable_vulnerabilities": count(actionable),
	"false_positives_filtered": count(false_positives),
	"details": {
		"actionable": actionable,
		"filtered_false_positives": false_positives,
	},
}
