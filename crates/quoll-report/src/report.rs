use std::collections::BTreeMap;
use std::path::PathBuf;

use quoll_core::{time_util, Finding, FindingStatus, Profile, Severity};
use quoll_plugin::PluginRun;
use serde::{Deserialize, Serialize};

use crate::verify::{VerificationSummary, Verifier};

/// Report format version.
///
/// Anything consuming Quoll's JSON — a dashboard, a diffing script, a baseline file — needs
/// to know when the shape changed. Bumped on any breaking change to the document.
pub const SCHEMA_VERSION: u32 = 1;

/// A finding as it appears in a report, with the verdict on its location.
///
/// The wrapper exists so `quoll-core` stays free of reporting concerns while a reader can
/// still tell a verified citation from a stale one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportedFinding {
    #[serde(flatten)]
    pub finding: Finding,
    /// Whether the cited file and line were confirmed against the working tree.
    pub location_verified: bool,
    /// Why not, when they were not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_note: Option<String>,
}

impl ReportedFinding {
    pub fn severity(&self) -> Severity {
        self.finding.severity
    }

    pub fn is_actionable(&self) -> bool {
        self.finding.status.is_actionable()
    }
}

/// What produced this report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub information_uri: String,
}

impl Default for ToolInfo {
    fn default() -> Self {
        ToolInfo {
            name: "Quoll".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            information_uri: "https://github.com/jusso-dev/Quoll".to_string(),
        }
    }
}

/// The scan this report describes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanInfo {
    pub id: String,
    pub profile: Profile,
    pub root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub files_scanned: usize,
}

impl ScanInfo {
    pub fn new(id: impl Into<String>, profile: Profile, root: impl Into<PathBuf>) -> ScanInfo {
        ScanInfo {
            id: id.into(),
            profile,
            root: root.into(),
            commit: None,
            started_at: time_util::now_rfc3339(),
            completed_at: None,
            files_scanned: 0,
        }
    }

    pub fn with_commit(mut self, commit: Option<String>) -> ScanInfo {
        self.commit = commit;
        self
    }

    pub fn completed(mut self, files_scanned: usize) -> ScanInfo {
        self.completed_at = Some(time_util::now_rfc3339());
        self.files_scanned = files_scanned;
        self
    }
}

/// What the scan did and did not cover.
///
/// Reported alongside the findings because a clean result from a scan where three tools
/// failed to start is not a clean result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    pub plugins_run: usize,
    pub plugins_skipped: usize,
    /// Plugins that failed, timed out or were not installed.
    pub plugins_degraded: Vec<String>,
    pub policy_packs_applied: Vec<String>,
    pub policy_nodes_evaluated: usize,
    /// True when no model was called, which is the default and costs nothing.
    pub ai_used: bool,
}

impl Coverage {
    /// Whether the scan lost coverage it was expected to have.
    pub fn is_degraded(&self) -> bool {
        !self.plugins_degraded.is_empty()
    }
}

/// A complete scan result, ready to render in any format.
///
/// No `PartialEq`: `PluginRun` carries a `Duration` and is not equated elsewhere, and a
/// report is an output document rather than a value the pipeline compares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: ToolInfo,
    pub scan: ScanInfo,
    pub findings: Vec<ReportedFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugin_runs: Vec<PluginRun>,
    pub coverage: Coverage,
    pub verification: VerificationSummary,
}

impl Report {
    /// Build a report, verifying every location before anything is rendered.
    ///
    /// The rule is asymmetric on purpose. A deterministic finding whose file has since
    /// moved is kept and flagged — the tool did see something, and hiding it would lose a
    /// real result. A finding resting on model output whose location does not exist is
    /// removed entirely, because a model that invents a line number has demonstrated
    /// exactly the failure mode Quoll exists to avoid.
    pub fn build(
        scan: ScanInfo,
        findings: Vec<Finding>,
        verifier: &mut Verifier,
    ) -> Report {
        let mut reported = Vec::with_capacity(findings.len());
        let mut verification = VerificationSummary::default();

        for mut finding in findings {
            let outcome = verifier.verify_finding(&mut finding);
            if outcome.is_verified() {
                verification.verified += 1;
                reported.push(ReportedFinding {
                    finding,
                    location_verified: true,
                    verification_note: None,
                });
                continue;
            }

            if finding.used_ai() {
                verification.dropped += 1;
                tracing::warn!(
                    finding = %finding.id,
                    location = %finding.location.display(),
                    reason = %outcome.describe(),
                    "dropping an AI-derived finding whose location could not be verified"
                );
                continue;
            }

            verification.flagged += 1;
            reported.push(ReportedFinding {
                finding,
                location_verified: false,
                verification_note: Some(outcome.describe()),
            });
        }

        Report {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo::default(),
            scan,
            findings: sorted(reported),
            plugin_runs: Vec::new(),
            coverage: Coverage::default(),
            verification,
        }
    }

    /// Build a report without touching the filesystem. For tests and for consumers that
    /// have already verified.
    pub fn unverified(scan: ScanInfo, findings: Vec<Finding>) -> Report {
        let reported = findings
            .into_iter()
            .map(|finding| ReportedFinding {
                finding,
                location_verified: false,
                verification_note: Some("not verified".to_string()),
            })
            .collect();
        Report {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo::default(),
            scan,
            findings: sorted(reported),
            plugin_runs: Vec::new(),
            coverage: Coverage::default(),
            verification: VerificationSummary::default(),
        }
    }

    pub fn with_plugin_runs(mut self, runs: Vec<PluginRun>) -> Report {
        self.coverage.plugins_run = runs
            .iter()
            .filter(|run| matches!(run.status, quoll_plugin::RunStatus::Completed))
            .count();
        self.coverage.plugins_skipped = runs
            .iter()
            .filter(|run| matches!(run.status, quoll_plugin::RunStatus::Skipped { .. }))
            .count();
        self.coverage.plugins_degraded = runs
            .iter()
            .filter(|run| run.status.degraded_coverage())
            .map(|run| run.plugin_id.clone())
            .collect();
        self.plugin_runs = runs;
        self
    }

    pub fn with_coverage(mut self, coverage: Coverage) -> Report {
        // Plugin counts are derived from the runs; preserve them across an explicit set.
        let derived = self.coverage.clone();
        self.coverage = Coverage {
            plugins_run: derived.plugins_run,
            plugins_skipped: derived.plugins_skipped,
            plugins_degraded: derived.plugins_degraded,
            ..coverage
        };
        self
    }

    /// Findings that count towards a CI gate.
    pub fn actionable(&self) -> impl Iterator<Item = &ReportedFinding> {
        self.findings.iter().filter(|f| f.is_actionable())
    }

    /// Counts by severity, actionable findings only.
    pub fn counts(&self) -> BTreeMap<Severity, usize> {
        let mut counts = BTreeMap::new();
        for finding in self.actionable() {
            *counts.entry(finding.severity()).or_insert(0) += 1;
        }
        counts
    }

    pub fn worst_severity(&self) -> Option<Severity> {
        self.actionable().map(|f| f.severity()).max()
    }

    /// Whether any actionable finding is at or above the gate.
    pub fn breaches(&self, threshold: Severity) -> bool {
        self.actionable().any(|f| f.severity() >= threshold)
    }

    pub fn suppressed_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.finding.status == FindingStatus::Suppressed)
            .count()
    }

    /// One line for a terminal or a CI log.
    pub fn summary(&self) -> String {
        let counts = self.counts();
        if counts.is_empty() {
            return format!("no findings across {} file(s)", self.scan.files_scanned);
        }
        let parts: Vec<String> = Severity::ALL
            .iter()
            .rev()
            .filter_map(|severity| {
                counts
                    .get(severity)
                    .map(|count| format!("{count} {}", severity.as_str()))
            })
            .collect();
        parts.join(", ")
    }
}

/// Severity first, then path and line, so a report reads worst-first and diffs cleanly.
fn sorted(mut findings: Vec<ReportedFinding>) -> Vec<ReportedFinding> {
    findings.sort_by(|a, b| {
        b.severity()
            .cmp(&a.severity())
            .then(a.finding.location.path.cmp(&b.finding.location.path))
            .then(a.finding.location.line().cmp(&b.finding.location.line()))
            .then(a.finding.id.cmp(&b.finding.id))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Confidence, Evidence, EvidenceSource, Location};

    pub(crate) fn scanner_finding(title: &str, severity: Severity, line: u32) -> Finding {
        Finding::new(
            title,
            severity,
            Location::at("src/api.rs", line),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: "r1".into(),
                },
                "semgrep matched",
                Confidence::new(0.8),
            )],
        )
    }

    fn ai_finding(title: &str, line: u32) -> Finding {
        Finding::new(
            title,
            Severity::High,
            Location::at("src/api.rs", line),
            vec![
                Evidence::supporting(
                    EvidenceSource::Ai {
                        provider: "openai".into(),
                        model: "gpt".into(),
                    },
                    "the model reasoned",
                    Confidence::new(0.7),
                ),
                Evidence::supporting(
                    EvidenceSource::Scanner {
                        plugin: "semgrep".into(),
                        rule: "r1".into(),
                    },
                    "semgrep matched",
                    Confidence::new(0.8),
                ),
            ],
        )
    }

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/api.rs"), "a\nb\nc\n").unwrap();
        dir
    }

    fn scan() -> ScanInfo {
        ScanInfo::new("scan-1", Profile::Balanced, "/repo")
    }

    #[test]
    fn verified_findings_are_kept_and_marked() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let report = Report::build(scan(), vec![scanner_finding("A", Severity::High, 2)], &mut verifier);

        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].location_verified);
        assert_eq!(report.verification.verified, 1);
    }

    #[test]
    fn a_deterministic_finding_with_a_stale_location_is_kept_but_flagged() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let report = Report::build(
            scan(),
            vec![scanner_finding("A", Severity::High, 900)],
            &mut verifier,
        );

        assert_eq!(report.findings.len(), 1, "a real scanner hit must not vanish");
        assert!(!report.findings[0].location_verified);
        assert!(report.findings[0]
            .verification_note
            .as_ref()
            .unwrap()
            .contains("past the end"));
        assert_eq!(report.verification.flagged, 1);
    }

    #[test]
    fn an_ai_finding_with_an_unverifiable_location_is_dropped() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let report = Report::build(scan(), vec![ai_finding("Invented", 900)], &mut verifier);

        assert!(report.findings.is_empty(), "a hallucinated line must not be reported");
        assert_eq!(report.verification.dropped, 1);
    }

    #[test]
    fn an_ai_finding_with_a_real_location_survives() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let report = Report::build(scan(), vec![ai_finding("Real", 2)], &mut verifier);

        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].location_verified);
    }

    #[test]
    fn findings_are_ordered_worst_first() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let report = Report::build(
            scan(),
            vec![
                scanner_finding("low", Severity::Low, 1),
                scanner_finding("critical", Severity::Critical, 3),
                scanner_finding("medium", Severity::Medium, 2),
            ],
            &mut verifier,
        );

        let severities: Vec<Severity> = report.findings.iter().map(|f| f.severity()).collect();
        assert_eq!(
            severities,
            vec![Severity::Critical, Severity::Medium, Severity::Low]
        );
    }

    #[test]
    fn ordering_is_stable_for_equal_severities() {
        let dir = repo();
        let build = || {
            let mut verifier = Verifier::new(dir.path());
            Report::build(
                scan(),
                vec![
                    scanner_finding("b", Severity::High, 3),
                    scanner_finding("a", Severity::High, 1),
                ],
                &mut verifier,
            )
        };
        assert_eq!(build().findings, build().findings);
    }

    #[test]
    fn the_gate_compares_against_the_threshold() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let report = Report::build(
            scan(),
            vec![scanner_finding("medium", Severity::Medium, 1)],
            &mut verifier,
        );

        assert!(report.breaches(Severity::Low));
        assert!(report.breaches(Severity::Medium));
        assert!(!report.breaches(Severity::High));
        assert_eq!(report.worst_severity(), Some(Severity::Medium));
    }

    #[test]
    fn suppressed_findings_do_not_breach_the_gate() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let suppressed =
            scanner_finding("x", Severity::Critical, 1).with_status(FindingStatus::Suppressed);
        let report = Report::build(scan(), vec![suppressed], &mut verifier);

        assert!(!report.breaches(Severity::Low));
        assert_eq!(report.suppressed_count(), 1);
        assert!(report.counts().is_empty());
    }

    #[test]
    fn plugin_runs_populate_coverage() {
        use quoll_plugin::RunStatus;
        use std::time::Duration;

        let runs = vec![
            PluginRun {
                plugin_id: "semgrep".into(),
                status: RunStatus::Completed,
                duration: Duration::from_secs(1),
                findings_count: 2,
                diagnostics: vec![],
                tool_version: None,
            },
            PluginRun {
                plugin_id: "trivy".into(),
                status: RunStatus::TimedOut { seconds: 300 },
                duration: Duration::from_secs(300),
                findings_count: 0,
                diagnostics: vec![],
                tool_version: None,
            },
            PluginRun {
                plugin_id: "cargo-audit".into(),
                status: RunStatus::Skipped {
                    reason: "no Cargo.lock".into(),
                },
                duration: Duration::from_millis(1),
                findings_count: 0,
                diagnostics: vec![],
                tool_version: None,
            },
        ];

        let report = Report::unverified(scan(), vec![]).with_plugin_runs(runs);

        assert_eq!(report.coverage.plugins_run, 1);
        assert_eq!(report.coverage.plugins_skipped, 1);
        assert_eq!(report.coverage.plugins_degraded, vec!["trivy"]);
        assert!(report.coverage.is_degraded());
    }

    #[test]
    fn the_summary_reads_worst_first() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let report = Report::build(
            scan(),
            vec![
                scanner_finding("a", Severity::Low, 1),
                scanner_finding("b", Severity::Critical, 2),
                scanner_finding("c", Severity::Critical, 3),
            ],
            &mut verifier,
        );
        assert_eq!(report.summary(), "2 critical, 1 low");
    }

    #[test]
    fn an_empty_report_says_so() {
        let report = Report::unverified(scan().completed(120), vec![]);
        assert!(report.summary().contains("no findings"));
        assert!(report.summary().contains("120"));
    }
}
