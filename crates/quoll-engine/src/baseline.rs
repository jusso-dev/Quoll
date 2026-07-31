//! Baseline files: known pre-existing findings that should not fail CI.

use std::collections::BTreeSet;
use std::path::Path;

use quoll_core::{Error, Finding, FindingStatus, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub fingerprints: BTreeSet<String>,
}

impl Baseline {
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }
}

pub fn load_baseline(path: &Path) -> Result<Baseline> {
    if !path.is_file() {
        return Ok(Baseline::default());
    }
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    // Accept either `{"fingerprints":[...]}` or a bare JSON array of strings.
    if let Ok(baseline) = serde_json::from_str::<Baseline>(&text) {
        return Ok(baseline);
    }
    let list: Vec<String> = serde_json::from_str(&text)?;
    Ok(Baseline {
        fingerprints: list.into_iter().collect(),
    })
}

/// Findings present in the baseline are reported as suppressed (pre-existing).
pub fn apply_baseline(findings: &mut [Finding], baseline: &Baseline) {
    if baseline.fingerprints.is_empty() {
        return;
    }
    for finding in findings.iter_mut() {
        if baseline.contains(&finding.fingerprint)
            && finding.status != FindingStatus::Suppressed
        {
            finding.status = FindingStatus::Suppressed;
            let note = "present in baseline (pre-existing)";
            if finding.description.is_empty() {
                finding.description = note.into();
            } else if !finding.description.contains(note) {
                finding.description = format!("{}\n\n{note}", finding.description);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Confidence, Evidence, EvidenceSource, Location, Severity};

    #[test]
    fn baseline_suppresses_matching_fingerprint() {
        let mut finding = Finding::new(
            "x",
            Severity::High,
            Location::at("a.rs", 1),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "s".into(),
                    rule: "r".into(),
                },
                "x",
                Confidence::new(0.8),
            )],
        );
        let baseline = Baseline {
            fingerprints: [finding.fingerprint.clone()].into_iter().collect(),
        };
        apply_baseline(std::slice::from_mut(&mut finding), &baseline);
        assert_eq!(finding.status, FindingStatus::Suppressed);
    }
}
