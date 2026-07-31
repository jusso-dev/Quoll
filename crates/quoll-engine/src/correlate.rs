//! Build attack hypotheses from normalised findings and extra evidence.

use std::collections::HashMap;

use quoll_core::{
    AttackHypothesis, Confidence, Evidence, Finding, HypothesisClass, HypothesisStatus,
};

use crate::classify::classify_raw;

/// Group findings into hypotheses by (class, path).
///
/// Findings that already represent self-evident classes are left alone — they do not
/// become hypotheses. Everything else is a candidate for investigation when confidence
/// clears the profile threshold.
pub fn correlate(
    findings: &[Finding],
    extra_evidence: &[Evidence],
) -> Vec<AttackHypothesis> {
    let mut buckets: HashMap<(String, String), AttackHypothesis> = HashMap::new();

    for finding in findings {
        // Reconstruct class from CWE / title when we only have a Finding.
        let class = class_of_finding(finding);
        if class.is_self_evident() {
            continue;
        }
        let key = (
            class.as_str().to_string(),
            finding.location.path.to_string_lossy().to_string(),
        );
        match buckets.get_mut(&key) {
            Some(hyp) => {
                for evidence in &finding.evidence {
                    hyp.add_evidence(evidence.clone());
                }
                if finding.severity > hyp.severity {
                    hyp.severity = finding.severity;
                }
            }
            None => {
                let mut hyp =
                    AttackHypothesis::new(class, finding.location.clone(), finding.evidence.clone())
                        .with_narrative(finding.description.clone());
                hyp.severity = finding.severity;
                buckets.insert(key, hyp);
            }
        }
    }

    // Extra graph/policy evidence attaches to any hypothesis on the same path.
    for evidence in extra_evidence {
        if let Some(location) = &evidence.location {
            let path = location.path.to_string_lossy().to_string();
            for ((_, p), hyp) in buckets.iter_mut() {
                if p == &path {
                    hyp.add_evidence(evidence.clone());
                }
            }
        }
    }

    let mut hypotheses: Vec<AttackHypothesis> = buckets.into_values().collect();
    hypotheses.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.cmp(&a.confidence))
            .then(a.location.display().cmp(&b.location.display()))
    });
    hypotheses
}

/// Mark hypotheses that do not clear the investigation bar.
pub fn apply_threshold(hypotheses: &mut [AttackHypothesis], threshold: Confidence) {
    for hyp in hypotheses.iter_mut() {
        if hyp.status != HypothesisStatus::Proposed {
            continue;
        }
        if !hyp.warrants_investigation(threshold) {
            hyp.status = HypothesisStatus::BelowThreshold;
        }
    }
}

/// Hypotheses that should be handed to the model.
pub fn investigation_queue(
    hypotheses: &[AttackHypothesis],
    threshold: Confidence,
    max: usize,
) -> Vec<AttackHypothesis> {
    hypotheses
        .iter()
        .filter(|h| h.warrants_investigation(threshold))
        .take(max)
        .cloned()
        .collect()
}

/// Fold settled hypotheses back into the finding list.
///
/// Confirmed / validated / still-proposed (above reporting threshold) become findings.
/// Rejected hypotheses become refuted findings only when the caller asks for full audit.
pub fn promote(
    findings: Vec<Finding>,
    hypotheses: &[AttackHypothesis],
    reporting_threshold: Confidence,
    include_refuted: bool,
) -> Vec<Finding> {
    // Keep self-evident findings; re-add the rest from hypothesis promotion.
    let self_evident: Vec<Finding> = findings
        .into_iter()
        .filter(|f| class_of_finding(f).is_self_evident())
        .collect();

    let mut promoted: Vec<Finding> = Vec::new();
    for hyp in hypotheses {
        match hyp.status {
            HypothesisStatus::Rejected if !include_refuted => continue,
            HypothesisStatus::BelowThreshold if hyp.confidence < reporting_threshold => continue,
            HypothesisStatus::Investigating => continue,
            _ => {}
        }
        if hyp.confidence < reporting_threshold
            && !matches!(
                hyp.status,
                HypothesisStatus::Confirmed | HypothesisStatus::Validated
            )
        {
            continue;
        }
        promoted.push(hyp.clone().into_finding());
    }

    let mut combined = self_evident;
    combined.extend(promoted);
    // Also keep findings that never became hypotheses (policy missing-control etc. with other)
    // Policy findings have MissingSecurityControl — they go through hyp if not self-evident.
    // Re-add nothing else.

    // If a finding was never correlated into a hypothesis (e.g. Other class weak),
    // the initial normalize list is lost. Fix: keep all original findings that are
    // self-evident OR have no matching hypothesis, handled above only self-evident.
    // Better: pass original findings and merge by fingerprint.

    combined.sort_by_key(|f| f.sort_key());
    combined
}

/// Promote while preserving findings that were not absorbed into hypotheses.
pub fn merge_promoted(
    original: Vec<Finding>,
    hypotheses: &[AttackHypothesis],
    reporting_threshold: Confidence,
    include_refuted: bool,
) -> Vec<Finding> {
    let absorbed_paths: HashMap<String, ()> = hypotheses
        .iter()
        .map(|h| {
            (
                format!("{}:{}", h.class.as_str(), h.location.path.display()),
                (),
            )
        })
        .collect();

    let mut kept: Vec<Finding> = original
        .into_iter()
        .filter(|f| {
            let class = class_of_finding(f);
            class.is_self_evident()
                || !absorbed_paths.contains_key(&format!(
                    "{}:{}",
                    class.as_str(),
                    f.location.path.display()
                ))
        })
        .filter(|f| f.confidence >= reporting_threshold || class_of_finding(f).is_self_evident())
        .collect();

    for hyp in hypotheses {
        match hyp.status {
            HypothesisStatus::Rejected if !include_refuted => continue,
            HypothesisStatus::BelowThreshold if hyp.confidence < reporting_threshold => continue,
            HypothesisStatus::Investigating => continue,
            _ => {}
        }
        if hyp.confidence < reporting_threshold
            && !matches!(
                hyp.status,
                HypothesisStatus::Confirmed | HypothesisStatus::Validated
            )
        {
            continue;
        }
        kept.push(hyp.clone().into_finding());
    }

    // Dedup by fingerprint, prefer higher confidence.
    let mut by_fp: HashMap<String, Finding> = HashMap::new();
    for finding in kept {
        match by_fp.get_mut(&finding.fingerprint) {
            Some(existing) if finding.confidence > existing.confidence => *existing = finding,
            Some(_) => {}
            None => {
                by_fp.insert(finding.fingerprint.clone(), finding);
            }
        }
    }
    let mut out: Vec<Finding> = by_fp.into_values().collect();
    out.sort_by_key(|f| f.sort_key());
    out
}

fn class_of_finding(finding: &Finding) -> HypothesisClass {
    // Prefer CWE mapping, then title keywords via a synthetic RawFinding.
    for cwe in &finding.cwe {
        let lower = cwe.to_ascii_lowercase();
        if lower.contains("89") {
            return HypothesisClass::SqlInjection;
        }
        if lower.contains("798") || lower.contains("259") {
            return HypothesisClass::ExposedSecret;
        }
        if lower.contains("306") {
            return HypothesisClass::MissingAuthentication;
        }
        if lower.contains("862") {
            return HypothesisClass::MissingAuthorisation;
        }
        if lower.contains("693") {
            return HypothesisClass::MissingSecurityControl;
        }
        if lower.contains("1395") {
            return HypothesisClass::VulnerableDependency;
        }
    }
    let raw = quoll_core::RawFinding::new(
        finding
            .contributing_plugins
            .first()
            .cloned()
            .unwrap_or_else(|| "quoll".into()),
        finding.fingerprint.clone(),
        finding.title.clone(),
        finding.severity,
        finding.location.clone(),
    )
    .with_description(finding.description.clone())
    .with_cwe(finding.cwe.clone());
    classify_raw(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Evidence, EvidenceSource, Location, Severity};

    fn finding(title: &str, path: &str, rule: &str) -> Finding {
        Finding::new(
            title,
            Severity::High,
            Location::at(path, 1).with_snippet("code"),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: rule.into(),
                },
                title,
                Confidence::new(0.8),
            )],
        )
    }

    #[test]
    fn same_path_and_class_merge() {
        let findings = vec![
            finding("SQL injection", "db.rs", "sqli"),
            finding("SQL injection via ORM", "db.rs", "sqli-orm"),
        ];
        // Both classify as sqli via title
        let hyps = correlate(&findings, &[]);
        assert_eq!(hyps.len(), 1);
        assert!(hyps[0].evidence.len() >= 2);
    }

    #[test]
    fn secrets_do_not_become_hypotheses() {
        let secret = Finding::from_raw(&quoll_core::RawFinding::new(
            "gitleaks",
            "aws",
            "AWS key",
            Severity::Critical,
            Location::at(".env", 1),
        ));
        let hyps = correlate(&[secret], &[]);
        assert!(hyps.is_empty());
    }
}
