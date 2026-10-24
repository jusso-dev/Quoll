//! Build attack hypotheses from normalised findings and extra evidence.

use std::collections::HashMap;

use quoll_core::{
    AttackHypothesis, Confidence, Evidence, EvidenceKind, EvidenceSource, Finding,
    HypothesisClass, HypothesisStatus, Location,
};

use crate::classify::{classify_raw, cwe_ids};

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
        let key = bucket_key(&class, &finding.location);
        let is_other = matches!(class, HypothesisClass::Other(_));
        match buckets.get_mut(&key) {
            Some(hyp) => {
                for evidence in &finding.evidence {
                    hyp.add_evidence(evidence.clone());
                }
                if finding.severity > hyp.severity {
                    hyp.severity = finding.severity;
                }
                for cwe in &finding.cwe {
                    if !hyp.cwe.contains(cwe) {
                        hyp.cwe.push(cwe.clone());
                    }
                }
                // Earliest line wins, so the primary location is independent of input order.
                if primary_order(&finding.location) < primary_order(&hyp.location) {
                    hyp.location = finding.location.clone();
                    hyp.narrative = finding.description.clone();
                    if is_other {
                        hyp.title = finding.title.clone();
                    }
                }
            }
            None => {
                let mut hyp =
                    AttackHypothesis::new(class, finding.location.clone(), finding.evidence.clone())
                        .with_narrative(finding.description.clone());
                hyp.severity = finding.severity;
                hyp.cwe = finding.cwe.clone();
                if is_other {
                    // `Other` carries a rule id; the scanner's title reads better.
                    hyp.title = finding.title.clone();
                }
                buckets.insert(key, hyp);
            }
        }
    }

    // Extra graph/policy evidence attaches to any hypothesis on the same path. Only
    // supporting facts: a control satisfied on one node says nothing about a different
    // class of bug elsewhere in the file, and refuting evidence would sink it.
    for evidence in extra_evidence {
        if evidence.kind != EvidenceKind::Supporting {
            continue;
        }
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
            .then(a.location.path.cmp(&b.location.path))
            .then(a.location.line().cmp(&b.location.line()))
            .then(a.class.as_str().cmp(b.class.as_str()))
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

/// What became of a hypothesis once investigation is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Reported in place of the findings it absorbed.
    Promoted,
    /// Explicitly rejected; its findings are refuted with it.
    Rejected,
    /// Neither: the absorbed scanner findings are reported as they are.
    Unsettled,
}

fn fate(hyp: &AttackHypothesis, reporting_threshold: Confidence) -> Fate {
    match hyp.status {
        HypothesisStatus::Confirmed | HypothesisStatus::Validated => Fate::Promoted,
        HypothesisStatus::Rejected => Fate::Rejected,
        HypothesisStatus::Investigating => Fate::Unsettled,
        HypothesisStatus::Proposed | HypothesisStatus::BelowThreshold => {
            if hyp.confidence >= reporting_threshold {
                Fate::Promoted
            } else {
                Fate::Unsettled
            }
        }
    }
}

/// Fold settled hypotheses back into the finding list.
///
/// The reporting threshold gates hypotheses, not scanner output: a promoted hypothesis
/// replaces the findings it absorbed, a rejected one takes them with it (reported as
/// refuted only when `include_refuted`), and anything else leaves the original
/// deterministic findings in place so they still reach the CI gate.
pub fn merge_promoted(
    original: Vec<Finding>,
    hypotheses: &[AttackHypothesis],
    reporting_threshold: Confidence,
    include_refuted: bool,
) -> Vec<Finding> {
    let fates: HashMap<(String, String), Fate> = hypotheses
        .iter()
        .map(|h| (bucket_key(&h.class, &h.location), fate(h, reporting_threshold)))
        .collect();

    let mut kept: Vec<Finding> = original
        .into_iter()
        .filter(|f| {
            let class = class_of_finding(f);
            class.is_self_evident()
                || matches!(
                    fates.get(&bucket_key(&class, &f.location)),
                    None | Some(Fate::Unsettled)
                )
        })
        .collect();

    for hyp in hypotheses {
        match fate(hyp, reporting_threshold) {
            Fate::Promoted => kept.push(hyp.clone().into_finding()),
            Fate::Rejected if include_refuted => kept.push(hyp.clone().into_finding()),
            _ => {}
        }
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

fn bucket_key(class: &HypothesisClass, location: &Location) -> (String, String) {
    (
        class.as_str().to_string(),
        location.path.to_string_lossy().to_string(),
    )
}

/// Ordering for picking a hypothesis' primary location: line numerically, then snippet.
fn primary_order(location: &Location) -> (u32, &str) {
    (location.line(), location.snippet.as_deref().unwrap_or(""))
}

fn class_of_finding(finding: &Finding) -> HypothesisClass {
    // Prefer CWE mapping (by number, so CWE-489 is not CWE-89), then the scanner's own
    // rule and title, exactly as classified at normalisation.
    for id in finding.cwe.iter().flat_map(|c| cwe_ids(c)) {
        match id {
            89 => return HypothesisClass::SqlInjection,
            798 | 259 => return HypothesisClass::ExposedSecret,
            306 => return HypothesisClass::MissingAuthentication,
            862 => return HypothesisClass::MissingAuthorisation,
            693 => return HypothesisClass::MissingSecurityControl,
            1395 => return HypothesisClass::VulnerableDependency,
            _ => {}
        }
    }
    let (plugin, rule) = finding
        .evidence
        .iter()
        .find_map(|e| match &e.source {
            EvidenceSource::Scanner { plugin, rule } => Some((plugin.clone(), rule.clone())),
            _ => None,
        })
        .unwrap_or_else(|| ("quoll".into(), finding.title.clone()));
    let raw = quoll_core::RawFinding::new(
        plugin,
        rule,
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
    use quoll_core::{Evidence, EvidenceSource, FindingStatus, Location, Severity};

    fn finding(title: &str, path: &str, rule: &str) -> Finding {
        finding_at(title, path, rule, 1, Confidence::new(0.8))
    }

    fn finding_at(title: &str, path: &str, rule: &str, line: u32, conf: Confidence) -> Finding {
        Finding::new(
            title,
            Severity::High,
            Location::at(path, line).with_snippet("code"),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: rule.into(),
                },
                title,
                conf,
            )],
        )
    }

    fn policy(kind_supporting: bool, path: &str) -> Evidence {
        let source = EvidenceSource::Policy {
            pack: "express".into(),
            control: "auth".into(),
        };
        let evidence = if kind_supporting {
            Evidence::supporting(source, "route lacks auth", Confidence::new(0.9))
        } else {
            Evidence::refuting(source, "route has auth", Confidence::new(0.9))
        };
        evidence.at(Location::at(path, 40))
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

    #[test]
    fn a_satisfied_control_does_not_sink_other_hypotheses_in_the_file() {
        let findings = vec![finding("SQL injection", "app.js", "sqli")];
        let before = correlate(&findings, &[])[0].confidence;
        let hyps = correlate(&findings, &[policy(false, "app.js")]);
        assert_eq!(hyps[0].confidence, before);
        let hyps = correlate(&findings, &[policy(true, "app.js")]);
        assert!(hyps[0].confidence > before);
    }

    #[test]
    fn primary_location_is_the_lowest_line_whatever_the_order() {
        let a = finding_at("SQL injection", "db.rs", "sqli", 10, Confidence::new(0.8));
        let b = finding_at("SQL injection via ORM", "db.rs", "orm-sqli", 9, Confidence::new(0.8));
        let one = correlate(&[a.clone(), b.clone()], &[]);
        let two = correlate(&[b, a], &[]);
        assert_eq!(one[0].location.line(), 9);
        assert_eq!(two[0].location.line(), 9);
        let mut one = one[0].clone();
        one.status = HypothesisStatus::Confirmed;
        let mut two = two[0].clone();
        two.status = HypothesisStatus::Confirmed;
        assert_eq!(one.into_finding().fingerprint, two.into_finding().fingerprint);
    }

    #[test]
    fn unclassified_findings_keep_rule_and_title() {
        let mut weak = finding("Weak hash algorithm", "crypto.rs", "weak-md5");
        weak.cwe = vec!["CWE-328".into()];
        let hyps = correlate(&[weak], &[]);
        assert_eq!(hyps[0].class, HypothesisClass::Other("weak-md5".into()));
        let promoted = hyps[0].clone().into_finding();
        assert_eq!(promoted.title, "Weak hash algorithm");
        assert_eq!(promoted.cwe, vec!["CWE-328"]);
    }

    #[test]
    fn cwe_match_is_exact() {
        let mut f = finding("Debug code left in", "app.rs", "debug");
        f.cwe = vec!["CWE-489".into()];
        assert_ne!(class_of_finding(&f), HypothesisClass::SqlInjection);
    }

    #[test]
    fn below_threshold_hypotheses_keep_their_scanner_findings() {
        // A lone ERROR-level hit with no stated confidence: 0.48 < Fast's 0.6.
        let lone = finding_at("SQL injection", "db.rs", "sqli", 3, Confidence::new(0.6));
        let mut hyps = correlate(std::slice::from_ref(&lone), &[]);
        apply_threshold(&mut hyps, Confidence::CERTAIN);
        let threshold = quoll_core::Profile::Fast.reporting_threshold();
        assert!(hyps[0].confidence < threshold);

        let out = merge_promoted(vec![lone.clone()], &hyps, threshold, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].fingerprint, lone.fingerprint);
        assert_eq!(out[0].status, FindingStatus::Reported);

        hyps[0].status = HypothesisStatus::Rejected;
        assert!(merge_promoted(vec![lone.clone()], &hyps, threshold, false).is_empty());
        let audit = merge_promoted(vec![lone], &hyps, threshold, true);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].status, FindingStatus::Refuted);
    }

    #[test]
    fn promoted_hypotheses_replace_their_findings() {
        let a = finding("SQL injection", "db.rs", "sqli");
        let mut hyps = correlate(std::slice::from_ref(&a), &[]);
        hyps[0].status = HypothesisStatus::Confirmed;
        let out = merge_promoted(vec![a], &hyps, Confidence::new(0.4), false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].status, FindingStatus::Confirmed);
        assert!(out[0].hypothesis_id.is_some());
    }
}
