use std::path::Path;

use quoll_core::{Confidence, Location, RawFinding, Result, Severity, Span};
use quoll_plugin::{
    async_trait, BinaryRequirement, Capability, CostTier, Plugin, PluginManifest, PluginOutput,
    ScanContext,
};
use serde::Deserialize;

use crate::common;

/// Gitleaks: credential material in the working tree and in history.
pub struct Gitleaks {
    manifest: PluginManifest,
}

impl Default for Gitleaks {
    fn default() -> Self {
        Gitleaks::new()
    }
}

impl Gitleaks {
    pub fn new() -> Gitleaks {
        Gitleaks {
            manifest: PluginManifest::builder("gitleaks", "Gitleaks")
                .description("Finds hardcoded secrets in files and in git history")
                .capability(Capability::SecretScanning)
                .cost(CostTier::Fast)
                .license("MIT")
                .homepage("https://gitleaks.io")
                .confidence(Confidence::new(0.7))
                .requires(
                    BinaryRequirement::new("gitleaks")
                        .install_hint("brew install gitleaks, or see https://gitleaks.io"),
                )
                .build(),
        }
    }
}

#[async_trait]
impl Plugin for Gitleaks {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// Secrets are language-independent. Every repository is worth scanning.
    fn applies_to(&self, _ctx: &ScanContext) -> bool {
        true
    }

    async fn run(&self, ctx: &ScanContext) -> Result<PluginOutput> {
        let report_path = ctx.ensure_work_dir()?.join("gitleaks.json");

        let mut exec = common::command(ctx, "gitleaks")
            // `dir` scans the working tree. History scanning is a separate, far slower
            // mode and belongs to the deep profile, not to every run.
            .arg("dir")
            .path_arg(ctx.root())
            .arg("--report-format")
            .arg("json")
            .arg("--report-path")
            .path_arg(&report_path)
            .arg("--no-banner")
            .arg("--exit-code")
            // Findings are the expected outcome, not a failure.
            .arg("0");

        for config in &ctx.settings().config {
            exec = exec.arg("--config").path_arg(config);
        }

        let output = common::with_extra_args(exec, ctx).run_lenient().await?;

        // Gitleaks writes to the report file, not to stdout.
        let text = match std::fs::read_to_string(&report_path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PluginOutput::default()
                    .warn(format!("gitleaks wrote no report: {}", output.error_summary())));
            }
            Err(err) => return Err(quoll_core::Error::io(report_path, err)),
        };
        let _ = std::fs::remove_file(&report_path);

        Ok(PluginOutput::default().with_findings(parse(ctx.root(), &text)?))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Leak {
    // Not `RuleId`. PascalCase would produce the wrong key and silently leave every
    // finding unattributed to a rule.
    #[serde(rename = "RuleID", default)]
    rule_id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    file: String,
    #[serde(default)]
    start_line: i64,
    #[serde(default)]
    end_line: i64,
    #[serde(default)]
    entropy: f64,
    #[serde(default)]
    commit: String,
    #[serde(default)]
    author: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    match_: Option<String>,
}

/// Convert a Gitleaks JSON report into findings.
///
/// The secret itself is never carried into a finding. A report is written to disk, pasted
/// into tickets and sometimes uploaded to a code-scanning dashboard; reproducing the
/// credential in it would turn a leak into a wider leak.
pub fn parse(root: &Path, json: &str) -> Result<Vec<RawFinding>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let leaks: Vec<Leak> = common::parse_json("gitleaks", json)?;

    Ok(leaks
        .into_iter()
        .map(|leak| {
            let start = common::line(leak.start_line).unwrap_or(1);
            let span = match common::line(leak.end_line) {
                Some(end) if end > start => Span::lines(start, end),
                _ => Span::line(start),
            };
            let location = Location::file(common::relative(root, &leak.file)).with_span(span);

            let rule = if leak.rule_id.is_empty() {
                "generic-secret".to_string()
            } else {
                leak.rule_id.clone()
            };
            let title = if leak.description.is_empty() {
                format!("Secret detected: {rule}")
            } else {
                leak.description.clone()
            };

            let mut finding = RawFinding::new("gitleaks", &rule, title, Severity::High, location)
                .with_description(
                    "A credential appears in the repository. Treat it as compromised: rotate it, \
                     then remove it from the working tree and from history."
                        .to_string(),
                )
                .with_cwe(["CWE-798".to_string()])
                // Entropy-based matches are noisier than rule-based ones, and a secret in a
                // fixture or an example file is common. High, not certain.
                .with_confidence(Confidence::new(0.7));

            if leak.entropy > 0.0 {
                finding
                    .metadata
                    .insert("entropy".into(), leak.entropy.into());
            }
            if !leak.commit.is_empty() {
                finding.metadata.insert("commit".into(), leak.commit.into());
                finding.metadata.insert("author".into(), leak.author.into());
                finding.metadata.insert("date".into(), leak.date.into());
            }
            if !leak.fingerprint.is_empty() {
                finding
                    .metadata
                    .insert("gitleaks_fingerprint".into(), leak.fingerprint.into());
            }
            // Length only. Enough to tell a 40-character token from a 4-character
            // placeholder, without reproducing either.
            if let Some(matched) = leak.match_ {
                finding
                    .metadata
                    .insert("match_length".into(), matched.len().into());
            }
            finding
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"[
      {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "File": "config/prod.env",
        "StartLine": 12,
        "EndLine": 12,
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "Match": "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
        "Entropy": 3.5,
        "Commit": "a1b2c3d4",
        "Author": "someone",
        "Date": "2026-01-02T03:04:05Z",
        "Fingerprint": "config/prod.env:aws-access-token:12"
      }
    ]"#;

    fn parsed() -> Vec<RawFinding> {
        parse(Path::new("/repo"), REPORT).unwrap()
    }

    #[test]
    fn parses_a_leak_into_a_high_severity_finding() {
        let findings = parsed();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule_id, "aws-access-token");
        assert_eq!(findings[0].location.path.to_str().unwrap(), "config/prod.env");
        assert_eq!(findings[0].location.line(), 12);
    }

    #[test]
    fn the_secret_is_never_copied_into_the_finding() {
        let serialised = serde_json::to_string(&parsed()).unwrap();
        assert!(
            !serialised.contains("AKIAIOSFODNN7EXAMPLE"),
            "a report must not reproduce the credential it is reporting"
        );
        assert!(!serialised.contains("AWS_KEY=AKIA"));
    }

    #[test]
    fn the_match_length_is_kept_without_the_match() {
        let finding = &parsed()[0];
        assert_eq!(
            finding.metadata.get("match_length").unwrap().as_u64(),
            Some("AWS_KEY=AKIAIOSFODNN7EXAMPLE".len() as u64)
        );
    }

    #[test]
    fn commit_provenance_is_preserved() {
        let metadata = &parsed()[0].metadata;
        assert_eq!(metadata.get("commit").unwrap(), "a1b2c3d4");
        assert_eq!(metadata.get("author").unwrap(), "someone");
    }

    #[test]
    fn every_leak_carries_the_credential_cwe() {
        assert_eq!(parsed()[0].cwe, vec!["CWE-798"]);
    }

    #[test]
    fn an_empty_report_is_not_an_error() {
        assert!(parse(Path::new("/repo"), "[]").unwrap().is_empty());
        assert!(parse(Path::new("/repo"), "").unwrap().is_empty());
    }

    #[test]
    fn a_leak_with_no_rule_still_becomes_a_finding() {
        let findings = parse(
            Path::new("/repo"),
            r#"[{"File":"a.env","StartLine":1}]"#,
        )
        .unwrap();
        assert_eq!(findings[0].rule_id, "generic-secret");
        assert!(findings[0].title.contains("Secret detected"));
    }

    #[test]
    fn gitleaks_applies_to_every_repository() {
        let ctx = ScanContext::new("/repo", quoll_core::Profile::Fast);
        assert!(Gitleaks::new().applies_to(&ctx));
    }

    #[test]
    fn the_manifest_is_fast_and_offline_capable() {
        let manifest = Gitleaks::new().manifest().clone();
        assert_eq!(manifest.cost, CostTier::Fast);
        assert!(manifest.offline_capable);
        assert!(manifest.has_capability(Capability::SecretScanning));
    }
}
