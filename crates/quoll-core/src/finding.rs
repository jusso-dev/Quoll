use serde::{Deserialize, Serialize};

use crate::{evidence, ids, Confidence, Evidence, Location, Severity};

/// A finding exactly as a scanner reported it, before Quoll interprets anything.
///
/// Plugins produce these. The orchestrator never treats a `RawFinding` as a result to
/// show the user: it is evidence, and evidence has to survive correlation first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawFinding {
    /// Plugin that produced this, e.g. `semgrep`.
    pub plugin: String,
    /// Tool-native rule identifier, preserved verbatim for traceability.
    pub rule_id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    pub location: Location,
    /// Tool's own confidence, when it reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Data-flow trace, when the tool provides one (Semgrep taint mode, CodeQL).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<Location>,
    /// Anything tool-specific worth keeping but not worth modelling.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl RawFinding {
    pub fn new(
        plugin: impl Into<String>,
        rule_id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        location: Location,
    ) -> RawFinding {
        RawFinding {
            plugin: plugin.into(),
            rule_id: rule_id.into(),
            title: title.into(),
            description: String::new(),
            severity,
            location,
            confidence: None,
            cwe: Vec::new(),
            cve: Vec::new(),
            references: Vec::new(),
            trace: Vec::new(),
            metadata: serde_json::Map::new(),
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_cwe(mut self, cwe: impl IntoIterator<Item = String>) -> Self {
        self.cwe.extend(cwe);
        self
    }

    pub fn with_cve(mut self, cve: impl IntoIterator<Item = String>) -> Self {
        self.cve.extend(cve);
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Stable identity across runs and across line-number drift.
    pub fn fingerprint(&self) -> String {
        ids::finding_fingerprint(
            &format!("{}:{}", self.plugin, self.rule_id),
            &self.location.path.to_string_lossy(),
            self.location
                .snippet
                .as_deref()
                .unwrap_or(&self.title),
        )
    }

    /// Convert into supporting evidence for the hypothesis engine.
    pub fn as_evidence(&self) -> Evidence {
        let source = crate::EvidenceSource::Scanner {
            plugin: self.plugin.clone(),
            rule: self.rule_id.clone(),
        };
        // A scanner that declines to state confidence is taken at face value but not
        // treated as proof; 0.6 keeps a lone unreviewed hit below typical thresholds.
        let confidence = self.confidence.unwrap_or(Confidence::new(0.6));
        Evidence::supporting(source, self.title.clone(), confidence)
            .at(self.location.clone())
    }
}

/// Lifecycle of a finding as Quoll refines it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Deterministic evidence only; no AI has looked at it.
    Reported,
    /// Investigated by a model and judged real.
    Confirmed,
    /// Investigated and judged a false positive.
    Refuted,
    /// Proven exploitable by a dynamic validator.
    Validated,
    /// Silenced by configuration or an inline suppression comment.
    Suppressed,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Reported => "reported",
            FindingStatus::Confirmed => "confirmed",
            FindingStatus::Refuted => "refuted",
            FindingStatus::Validated => "validated",
            FindingStatus::Suppressed => "suppressed",
        }
    }

    /// Whether this finding should count towards CI failure thresholds.
    pub fn is_actionable(self) -> bool {
        matches!(
            self,
            FindingStatus::Reported | FindingStatus::Confirmed | FindingStatus::Validated
        )
    }
}

/// A concrete code change that resolves a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fix {
    pub location: Location,
    pub description: String,
    /// Unified diff, when the fix is mechanical enough to generate safely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
}

/// Guidance attached to a finding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Remediation {
    pub summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<Fix>,
    /// Test that fails before the fix and passes after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression_test: Option<String>,
}

/// A correlated, evidence-backed result — the only thing Quoll shows a user.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    /// Stable across runs; used for baselines and suppressions.
    pub fingerprint: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: FindingStatus,
    pub location: Location,
    /// Every fact that argues for or against this finding.
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
    /// Hypothesis this finding was promoted from, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis_id: Option<String>,
    /// Plugins that contributed evidence, for the run summary.
    #[serde(default)]
    pub contributing_plugins: Vec<String>,
}

impl Finding {
    pub fn new(
        title: impl Into<String>,
        severity: Severity,
        location: Location,
        evidence: Vec<Evidence>,
    ) -> Finding {
        let title = title.into();
        let confidence = evidence::correlate(&evidence);
        let fingerprint = ids::finding_fingerprint(
            &title,
            &location.path.to_string_lossy(),
            location.snippet.as_deref().unwrap_or(""),
        );
        let id = ids::stable_id("QLL", &[&fingerprint]);
        let contributing_plugins = collect_plugins(&evidence);
        Finding {
            id,
            fingerprint,
            title,
            description: String::new(),
            severity,
            confidence,
            status: FindingStatus::Reported,
            location,
            evidence,
            cwe: Vec::new(),
            cve: Vec::new(),
            references: Vec::new(),
            remediation: None,
            hypothesis_id: None,
            contributing_plugins,
        }
    }

    /// Promote a single scanner result into a finding without correlation.
    ///
    /// Used for classes where the tool is authoritative — a leaked credential or a
    /// known CVE in a lockfile needs no second opinion.
    pub fn from_raw(raw: &RawFinding) -> Finding {
        let evidence = vec![raw.as_evidence()];
        let mut finding = Finding::new(
            raw.title.clone(),
            raw.severity,
            raw.location.clone(),
            evidence,
        );
        finding.fingerprint = raw.fingerprint();
        finding.id = ids::stable_id("QLL", &[&finding.fingerprint]);
        finding.description = raw.description.clone();
        finding.cwe = raw.cwe.clone();
        finding.cve = raw.cve.clone();
        finding.references = raw.references.clone();
        finding
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_status(mut self, status: FindingStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_remediation(mut self, remediation: Remediation) -> Self {
        self.remediation = Some(remediation);
        self
    }

    /// Recompute confidence and plugin attribution after evidence changes.
    pub fn recorrelate(&mut self) {
        self.confidence = evidence::correlate(&self.evidence);
        self.contributing_plugins = collect_plugins(&self.evidence);
    }

    pub fn add_evidence(&mut self, item: Evidence) {
        if !self.evidence.iter().any(|e| e.id == item.id) {
            self.evidence.push(item);
            self.recorrelate();
        }
    }

    pub fn deterministic_evidence(&self) -> impl Iterator<Item = &Evidence> {
        self.evidence.iter().filter(|e| e.is_deterministic())
    }

    /// Whether any model reasoning contributed to this finding.
    pub fn used_ai(&self) -> bool {
        self.evidence.iter().any(|e| !e.is_deterministic())
    }

    /// Enforce Quoll's reporting invariants.
    ///
    /// A finding must point at real code and must never rest on model output alone.
    /// This is the check that keeps "the LLM said so" out of the report.
    pub fn validate(&self) -> crate::Result<()> {
        if self.evidence.is_empty() {
            return Err(crate::Error::other(format!(
                "finding {} has no evidence",
                self.id
            )));
        }
        if self.location.path.as_os_str().is_empty() {
            return Err(crate::Error::other(format!(
                "finding {} has no source location",
                self.id
            )));
        }
        if self.used_ai() && self.deterministic_evidence().next().is_none() {
            return Err(crate::Error::other(format!(
                "finding {} rests on AI evidence alone",
                self.id
            )));
        }
        Ok(())
    }

    /// Ordering key for reports: severity first, then confidence, then path.
    pub fn sort_key(&self) -> (std::cmp::Reverse<Severity>, std::cmp::Reverse<Confidence>, String) {
        (
            std::cmp::Reverse(self.severity),
            std::cmp::Reverse(self.confidence),
            self.location.display(),
        )
    }
}

fn collect_plugins(evidence: &[Evidence]) -> Vec<String> {
    let mut plugins: Vec<String> = evidence
        .iter()
        .filter_map(|e| match &e.source {
            crate::EvidenceSource::Scanner { plugin, .. }
            | crate::EvidenceSource::Dynamic { plugin } => Some(plugin.clone()),
            _ => None,
        })
        .collect();
    plugins.sort();
    plugins.dedup();
    plugins
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvidenceSource;

    fn ai_evidence() -> Evidence {
        Evidence::supporting(
            EvidenceSource::Ai {
                provider: "openai".into(),
                model: "gpt-5.6".into(),
            },
            "model believes this is exploitable",
            Confidence::new(0.9),
        )
    }

    fn scanner_evidence() -> Evidence {
        Evidence::supporting(
            EvidenceSource::Scanner {
                plugin: "semgrep".into(),
                rule: "sqli".into(),
            },
            "string-concatenated query",
            Confidence::new(0.7),
        )
    }

    #[test]
    fn rejects_findings_built_only_from_ai() {
        let finding = Finding::new(
            "SQL injection",
            Severity::High,
            Location::at("src/db.rs", 10),
            vec![ai_evidence()],
        );
        assert!(finding.validate().is_err());
    }

    #[test]
    fn accepts_ai_findings_that_cite_deterministic_evidence() {
        let finding = Finding::new(
            "SQL injection",
            Severity::High,
            Location::at("src/db.rs", 10),
            vec![scanner_evidence(), ai_evidence()],
        );
        assert!(finding.validate().is_ok());
        assert!(finding.used_ai());
    }

    #[test]
    fn rejects_findings_with_no_evidence() {
        let finding = Finding::new("x", Severity::Low, Location::at("a.rs", 1), vec![]);
        assert!(finding.validate().is_err());
    }

    #[test]
    fn adding_evidence_raises_confidence_and_is_idempotent() {
        let mut finding = Finding::new(
            "SQL injection",
            Severity::High,
            Location::at("src/db.rs", 10),
            vec![scanner_evidence()],
        );
        let before = finding.confidence;
        finding.add_evidence(ai_evidence());
        assert!(finding.confidence > before);

        let after = finding.confidence;
        finding.add_evidence(ai_evidence());
        assert_eq!(finding.confidence, after, "duplicate evidence must not stack");
    }

    #[test]
    fn raw_findings_keep_identity_when_lines_move() {
        let mut raw = RawFinding::new(
            "semgrep",
            "sqli",
            "SQL injection",
            Severity::High,
            Location::at("src/db.rs", 10).with_snippet("db.query(sql)"),
        );
        let first = raw.fingerprint();
        raw.location = Location::at("src/db.rs", 92).with_snippet("db.query(sql)");
        assert_eq!(first, raw.fingerprint());
    }

    #[test]
    fn suppressed_findings_do_not_fail_ci() {
        assert!(!FindingStatus::Suppressed.is_actionable());
        assert!(!FindingStatus::Refuted.is_actionable());
        assert!(FindingStatus::Validated.is_actionable());
    }
}
