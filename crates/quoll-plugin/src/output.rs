use std::time::Duration;

use quoll_core::{Evidence, RawFinding};
use serde::{Deserialize, Serialize};

/// Something the plugin wants a human to know that is not a security finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Diagnostic {
    /// The plugin skipped work, with a reason.
    Skipped(String),
    /// The plugin ran but something degraded its results.
    Warning(String),
    /// Informational note, e.g. the underlying tool's version.
    Note(String),
}

impl Diagnostic {
    pub fn message(&self) -> &str {
        match self {
            Diagnostic::Skipped(m) | Diagnostic::Warning(m) | Diagnostic::Note(m) => m,
        }
    }

    pub fn level(&self) -> &'static str {
        match self {
            Diagnostic::Skipped(_) => "skipped",
            Diagnostic::Warning(_) => "warning",
            Diagnostic::Note(_) => "note",
        }
    }
}

/// What a plugin produced in one invocation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginOutput {
    /// Raw tool results. These are evidence, not conclusions.
    #[serde(default)]
    pub findings: Vec<RawFinding>,
    /// Structural or contextual facts for the graph and hypothesis engine.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    /// Version string of the underlying tool, recorded for reproducibility.
    #[serde(default)]
    pub tool_version: Option<String>,
    /// Files the plugin actually looked at, for coverage reporting.
    #[serde(default)]
    pub files_scanned: usize,
}

impl PluginOutput {
    pub fn empty() -> PluginOutput {
        PluginOutput::default()
    }

    /// A plugin that correctly decided it had nothing to do.
    ///
    /// Distinct from an error: a Go scanner on a Rust repository is working perfectly.
    pub fn skipped(reason: impl Into<String>) -> PluginOutput {
        PluginOutput {
            diagnostics: vec![Diagnostic::Skipped(reason.into())],
            ..PluginOutput::default()
        }
    }

    pub fn with_findings(mut self, findings: Vec<RawFinding>) -> Self {
        self.findings = findings;
        self
    }

    pub fn with_tool_version(mut self, version: Option<String>) -> Self {
        self.tool_version = version;
        self
    }

    pub fn warn(mut self, message: impl Into<String>) -> Self {
        self.diagnostics.push(Diagnostic::Warning(message.into()));
        self
    }

    pub fn note(mut self, message: impl Into<String>) -> Self {
        self.diagnostics.push(Diagnostic::Note(message.into()));
        self
    }

    pub fn was_skipped(&self) -> bool {
        self.findings.is_empty()
            && self
                .diagnostics
                .iter()
                .any(|d| matches!(d, Diagnostic::Skipped(_)))
    }
}

/// Outcome of scheduling one plugin, recorded in the run report.
///
/// Failure is a first-class outcome. A scan where Semgrep crashed is not the same as a
/// scan where Semgrep found nothing, and conflating the two is how teams end up
/// trusting a green build that never ran.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRun {
    pub plugin_id: String,
    pub status: RunStatus,
    #[serde(with = "duration_millis")]
    pub duration: Duration,
    pub findings_count: usize,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    #[serde(default)]
    pub tool_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RunStatus {
    Completed,
    /// Not applicable to this repository, or filtered out by profile or config.
    Skipped { reason: String },
    /// Required binary is not installed.
    Unavailable { reason: String },
    Failed { error: String },
    TimedOut { seconds: u64 },
}

impl RunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunStatus::Completed => "completed",
            RunStatus::Skipped { .. } => "skipped",
            RunStatus::Unavailable { .. } => "unavailable",
            RunStatus::Failed { .. } => "failed",
            RunStatus::TimedOut { .. } => "timed out",
        }
    }

    /// Whether coverage was lost. Used to warn that a green result may be incomplete.
    pub fn degraded_coverage(&self) -> bool {
        matches!(
            self,
            RunStatus::Unavailable { .. } | RunStatus::Failed { .. } | RunStatus::TimedOut { .. }
        )
    }
}

mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(value.as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_millis(u64::deserialize(d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_output_is_distinguishable_from_a_clean_result() {
        assert!(PluginOutput::skipped("no rust files").was_skipped());
        assert!(!PluginOutput::empty().was_skipped());
    }

    #[test]
    fn only_failures_flag_degraded_coverage() {
        assert!(!RunStatus::Completed.degraded_coverage());
        assert!(!RunStatus::Skipped {
            reason: "n/a".into()
        }
        .degraded_coverage());
        assert!(RunStatus::TimedOut { seconds: 300 }.degraded_coverage());
        assert!(RunStatus::Unavailable {
            reason: "missing".into()
        }
        .degraded_coverage());
    }

    #[test]
    fn run_serialises_duration_as_milliseconds() {
        let run = PluginRun {
            plugin_id: "semgrep".into(),
            status: RunStatus::Completed,
            duration: Duration::from_millis(1234),
            findings_count: 3,
            diagnostics: vec![],
            tool_version: None,
        };
        let json = serde_json::to_string(&run).unwrap();
        assert!(json.contains("\"duration\":1234"), "{json}");
        let back: PluginRun = serde_json::from_str(&json).unwrap();
        assert_eq!(back.duration, run.duration);
    }
}
