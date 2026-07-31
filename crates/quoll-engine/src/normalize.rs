//! Turn raw scanner hits into findings, and merge duplicates.

use std::collections::HashMap;

use quoll_core::{Finding, FindingStatus, RawFinding, Remediation};

use crate::classify::classify_raw;

/// Convert and deduplicate raw findings.
///
/// Two hits with the same fingerprint become one finding with merged evidence, CWE and
/// references. Self-evident classes (secrets, known-vulnerable deps) are promoted with
/// `Finding::from_raw` so they never wait on a model.
pub fn normalize(raw: Vec<RawFinding>) -> Vec<Finding> {
    let mut by_fp: HashMap<String, Finding> = HashMap::new();

    for item in raw {
        let class = classify_raw(&item);
        let mut finding = Finding::from_raw(&item);
        // Classification enriches CWE when the tool did not supply one.
        if finding.cwe.is_empty() {
            finding.cwe = class.cwe().iter().map(|s| s.to_string()).collect();
        }

        let fp = finding.fingerprint.clone();
        match by_fp.get_mut(&fp) {
            Some(existing) => merge(existing, finding),
            None => {
                by_fp.insert(fp, finding);
            }
        }
    }

    let mut findings: Vec<Finding> = by_fp.into_values().collect();
    findings.sort_by_key(|f| f.sort_key());
    findings
}

/// Policy violations become findings of class missing-control.
pub fn from_policy_violations(violations: impl IntoIterator<Item = quoll_policy::Outcome>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for outcome in violations {
        if !outcome.is_violation() {
            continue;
        }
        let location = outcome
            .location
            .clone()
            .unwrap_or_else(|| quoll_core::Location::file("unknown"));
        let evidence = vec![outcome.to_evidence()];
        let mut finding = Finding::new(
            outcome.title.clone(),
            outcome.severity,
            location,
            evidence,
        );
        finding.description = outcome.describe();
        finding.status = FindingStatus::Reported;
        finding.cwe = quoll_core::HypothesisClass::MissingSecurityControl
            .cwe()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let control_id = outcome.control_id();
        let node_name = outcome.node_name.clone();
        if let Some(summary) = outcome.remediation {
            finding.remediation = Some(Remediation {
                summary,
                ..Default::default()
            });
        }
        // Fingerprint on control + location so re-runs match.
        finding.fingerprint = quoll_core::ids::finding_fingerprint(
            &control_id,
            &finding.location.path.to_string_lossy(),
            finding.location.snippet.as_deref().unwrap_or(&node_name),
        );
        finding.id = quoll_core::ids::stable_id("QLL", &[&finding.fingerprint]);
        findings.push(finding);
    }
    findings
}

fn merge(into: &mut Finding, other: Finding) {
    for evidence in other.evidence {
        into.add_evidence(evidence);
    }
    for cwe in other.cwe {
        if !into.cwe.contains(&cwe) {
            into.cwe.push(cwe);
        }
    }
    for cve in other.cve {
        if !into.cve.contains(&cve) {
            into.cve.push(cve);
        }
    }
    for reference in other.references {
        if !into.references.contains(&reference) {
            into.references.push(reference);
        }
    }
    for plugin in other.contributing_plugins {
        if !into.contributing_plugins.contains(&plugin) {
            into.contributing_plugins.push(plugin);
        }
    }
    if into.description.is_empty() && !other.description.is_empty() {
        into.description = other.description;
    }
    if other.severity > into.severity {
        into.severity = other.severity;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Location, Severity};

    #[test]
    fn duplicate_fingerprints_merge_evidence() {
        let a = RawFinding::new(
            "semgrep",
            "sqli",
            "SQL injection",
            Severity::High,
            Location::at("db.rs", 1).with_snippet("query(sql)"),
        );
        let a2 = a.clone();
        let findings = normalize(vec![a, a2]);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn secrets_normalise_to_findings() {
        let raw = RawFinding::new(
            "gitleaks",
            "aws",
            "AWS key",
            Severity::Critical,
            Location::at(".env", 2).with_snippet("AKIA..."),
        );
        let findings = normalize(vec![raw]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
