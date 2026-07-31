use std::path::Path;

use quoll_core::{Confidence, Location, RawFinding, Result, Severity, Span};
use quoll_plugin::{
    async_trait, BinaryRequirement, Capability, CostTier, Plugin, PluginManifest, PluginOutput,
    ScanContext,
};
use serde::Deserialize;

use crate::common;

/// Semgrep: pattern and taint analysis over source code.
pub struct Semgrep {
    manifest: PluginManifest,
}

impl Default for Semgrep {
    fn default() -> Self {
        Semgrep::new()
    }
}

impl Semgrep {
    pub fn new() -> Semgrep {
        Semgrep {
            manifest: PluginManifest::builder("semgrep", "Semgrep")
                .description("Pattern and taint analysis across many languages")
                .capability(Capability::StaticAnalysis)
                .cost(CostTier::Moderate)
                .license("LGPL-2.1")
                .homepage("https://semgrep.dev")
                .confidence(Confidence::new(0.75))
                .requires(
                    BinaryRequirement::new("semgrep")
                        .install_hint("pip install semgrep, or brew install semgrep"),
                )
                .build(),
        }
    }
}

#[async_trait]
impl Plugin for Semgrep {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// Semgrep declares no languages in its manifest, so the default gate would always
    /// pass. It is worth running on anything with source in it, but not on a repository
    /// that is entirely configuration.
    fn applies_to(&self, ctx: &ScanContext) -> bool {
        ctx.tech_stack()
            .languages
            .iter()
            .any(|(language, _)| language.has_grammar())
    }

    async fn run(&self, ctx: &ScanContext) -> Result<PluginOutput> {
        let config = if ctx.settings().config.is_empty() {
            // `p/ci` is Semgrep's curated low-noise ruleset. A scanner whose default
            // configuration produces hundreds of style findings gets switched off, and a
            // switched-off scanner finds nothing at all.
            vec!["p/ci".to_string()]
        } else {
            ctx.settings().config.clone()
        };

        let mut exec = common::command(ctx, "semgrep")
            .arg("--json")
            .arg("--quiet")
            .arg("--disable-version-check")
            // Semgrep phones home unless told not to. A security tool must not exfiltrate
            // findings metadata from a scan the user believes is local.
            .arg("--metrics=off")
            .arg("--timeout")
            .arg(ctx.timeout().as_secs().to_string());

        for ruleset in &config {
            exec = exec.arg("--config").arg(ruleset);
        }
        if ctx.is_offline() {
            // Registry rulesets need the network; a local rule directory does not.
            if config.iter().any(|c| c.starts_with("p/") || c.starts_with("r/")) {
                return Ok(PluginOutput::skipped(
                    "scan is offline and the configured Semgrep rulesets are registry-hosted",
                ));
            }
        }

        for path in ctx.target_files() {
            exec = exec.path_arg(path);
        }
        if ctx.target_files().is_empty() {
            return Ok(PluginOutput::skipped("no files in scope"));
        }

        // Semgrep exits 1 when it finds something, which is not a failure.
        let output = common::with_extra_args(exec, ctx).run_lenient().await?;
        let findings = parse(ctx.root(), &output.stdout)?;

        let mut result = PluginOutput::default().with_findings(findings);
        result.files_scanned = ctx.target_files().len();
        for line in output.stderr.lines().filter(|l| !l.trim().is_empty()).take(3) {
            result = result.warn(line.trim().to_string());
        }
        Ok(result)
    }
}

#[derive(Debug, Deserialize)]
struct Report {
    #[serde(default)]
    results: Vec<Hit>,
    #[serde(default)]
    errors: Vec<SemgrepError>,
}

#[derive(Debug, Deserialize)]
struct Hit {
    check_id: String,
    path: String,
    start: Position,
    #[serde(default)]
    end: Option<Position>,
    extra: Extra,
}

#[derive(Debug, Deserialize)]
struct Position {
    #[serde(default)]
    line: i64,
    #[serde(default)]
    col: i64,
}

#[derive(Debug, Deserialize)]
struct Extra {
    #[serde(default)]
    message: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    lines: Option<String>,
    #[serde(default)]
    metadata: Metadata,
}

#[derive(Debug, Default, Deserialize)]
struct Metadata {
    /// Semgrep writes this as a string for one entry and a list for several.
    #[serde(default)]
    cwe: OneOrMany,
    #[serde(default)]
    references: OneOrMany,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::None => Vec::new(),
            OneOrMany::One(single) => vec![single],
            OneOrMany::Many(many) => many,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SemgrepError {
    #[serde(default)]
    message: String,
}

/// Convert Semgrep's JSON report into findings.
///
/// Pure and separately testable: the adapter is exercised against recorded tool output, so
/// the parser has coverage without Semgrep being installed.
pub fn parse(root: &Path, json: &str) -> Result<Vec<RawFinding>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let report: Report = common::parse_json("semgrep", json)?;

    for error in &report.errors {
        tracing::debug!(message = %error.message, "semgrep reported an error");
    }

    Ok(report
        .results
        .into_iter()
        .map(|hit| finding(root, hit))
        .collect())
}

fn finding(root: &Path, hit: Hit) -> RawFinding {
    let mut span = Span::line(common::line(hit.start.line).unwrap_or(1));
    if let Some(end) = &hit.end {
        if let Some(end_line) = common::line(end.line) {
            span = Span::lines(span.start_line, end_line);
        }
    }
    if let Some(column) = common::line(hit.start.col) {
        span = span.with_columns(column, hit.end.as_ref().and_then(|e| common::line(e.col)).unwrap_or(column));
    }

    let mut location = Location::file(common::relative(root, &hit.path)).with_span(span);
    if let Some(snippet) = hit.extra.lines {
        location = location.with_snippet(snippet.trim().to_string());
    }

    // Semgrep's INFO is genuinely informational, but its WARNING covers real issues, so
    // the floor is Low rather than Info.
    let severity = match hit.extra.severity.to_ascii_uppercase().as_str() {
        "ERROR" => Severity::High,
        "WARNING" => Severity::Medium,
        _ => Severity::Low,
    };

    // The rule id is the last dotted segment; the full id is kept as the rule identity.
    let title = hit
        .check_id
        .rsplit('.')
        .next()
        .unwrap_or(&hit.check_id)
        .replace(['-', '_'], " ");

    let mut finding = RawFinding::new("semgrep", &hit.check_id, title, severity, location)
        .with_description(hit.extra.message)
        .with_cwe(
            hit.extra
                .metadata
                .cwe
                .into_vec()
                .into_iter()
                .map(|entry| normalise_cwe(&entry)),
        );

    finding.references = hit.extra.metadata.references.into_vec();
    if let Some(confidence) = hit.extra.metadata.confidence {
        finding = finding.with_confidence(match confidence.to_ascii_uppercase().as_str() {
            "HIGH" => Confidence::new(0.85),
            "MEDIUM" => Confidence::new(0.6),
            _ => Confidence::new(0.4),
        });
    }
    if let Some(category) = hit.extra.metadata.category {
        finding
            .metadata
            .insert("category".into(), category.into());
    }
    finding
}

/// Semgrep writes CWEs as `CWE-89: Improper Neutralization...`; reports want `CWE-89`.
fn normalise_cwe(raw: &str) -> String {
    raw.split(':').next().unwrap_or(raw).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{
      "results": [
        {
          "check_id": "javascript.express.security.audit.express-open-redirect",
          "path": "/repo/src/routes/auth.js",
          "start": { "line": 42, "col": 5 },
          "end": { "line": 44, "col": 20 },
          "extra": {
            "message": "Detected an open redirect from user input.",
            "severity": "ERROR",
            "lines": "  res.redirect(req.query.next)",
            "metadata": {
              "cwe": ["CWE-601: URL Redirection to Untrusted Site"],
              "references": ["https://owasp.org/open-redirect"],
              "confidence": "HIGH",
              "category": "security"
            }
          }
        },
        {
          "check_id": "generic.secrets.hardcoded",
          "path": "src/config.ts",
          "start": { "line": 7, "col": 1 },
          "extra": {
            "message": "Hardcoded credential.",
            "severity": "WARNING",
            "metadata": { "cwe": "CWE-798" }
          }
        }
      ],
      "errors": []
    }"#;

    fn parsed() -> Vec<RawFinding> {
        parse(Path::new("/repo"), REPORT).unwrap()
    }

    #[test]
    fn parses_findings_from_recorded_output() {
        assert_eq!(parsed().len(), 2);
    }

    #[test]
    fn absolute_and_relative_paths_both_become_repository_relative() {
        let findings = parsed();
        assert_eq!(findings[0].location.path.to_str().unwrap(), "src/routes/auth.js");
        assert_eq!(findings[1].location.path.to_str().unwrap(), "src/config.ts");
    }

    #[test]
    fn severity_maps_from_semgrep_levels() {
        let findings = parsed();
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn spans_carry_start_end_and_columns() {
        let span = parsed()[0].location.span.unwrap();
        assert_eq!(span.start_line, 42);
        assert_eq!(span.end_line, Some(44));
        assert_eq!(span.start_column, Some(5));
    }

    #[test]
    fn cwe_is_normalised_to_the_identifier() {
        assert_eq!(parsed()[0].cwe, vec!["CWE-601"]);
    }

    #[test]
    fn a_single_cwe_string_parses_as_readily_as_a_list() {
        assert_eq!(parsed()[1].cwe, vec!["CWE-798"]);
    }

    #[test]
    fn the_full_rule_id_is_preserved_for_traceability() {
        assert_eq!(
            parsed()[0].rule_id,
            "javascript.express.security.audit.express-open-redirect"
        );
        assert_eq!(parsed()[0].title, "express open redirect");
    }

    #[test]
    fn snippets_and_references_survive() {
        let finding = &parsed()[0];
        assert!(finding.location.snippet.as_ref().unwrap().contains("res.redirect"));
        assert_eq!(finding.references, vec!["https://owasp.org/open-redirect"]);
        assert_eq!(finding.confidence.unwrap().value(), 0.85);
    }

    #[test]
    fn an_empty_report_is_not_an_error() {
        assert!(parse(Path::new("/repo"), r#"{"results":[],"errors":[]}"#).unwrap().is_empty());
        assert!(parse(Path::new("/repo"), "").unwrap().is_empty());
    }

    #[test]
    fn malformed_output_names_semgrep() {
        let err = parse(Path::new("/repo"), "Usage: semgrep [OPTIONS]").unwrap_err();
        assert!(err.to_string().contains("semgrep"), "{err}");
    }

    #[test]
    fn findings_fingerprint_stably_across_line_moves() {
        let one = parse(Path::new("/repo"), REPORT).unwrap();
        let shifted = REPORT.replace("\"line\": 42", "\"line\": 90");
        let two = parse(Path::new("/repo"), &shifted).unwrap();
        assert_eq!(one[0].fingerprint(), two[0].fingerprint());
    }

    #[test]
    fn the_manifest_declares_what_the_scheduler_needs() {
        let manifest = Semgrep::new().manifest().clone();
        assert_eq!(manifest.id, "semgrep");
        assert!(manifest.has_capability(Capability::StaticAnalysis));
        assert_eq!(manifest.cost, CostTier::Moderate);
        assert_eq!(manifest.required_binaries[0].name, "semgrep");
        assert!(manifest.required_binaries[0].install_hint.is_some());
    }
}
