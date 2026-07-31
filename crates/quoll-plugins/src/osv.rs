use std::path::Path;

use quoll_core::{Confidence, Ecosystem, Location, RawFinding, Result, Severity};
use quoll_plugin::{
    async_trait, BinaryRequirement, Capability, CostTier, Plugin, PluginManifest, PluginOutput,
    ScanContext,
};
use serde::Deserialize;

use crate::common;

/// OSV-Scanner: known advisories against declared dependencies.
pub struct OsvScanner {
    manifest: PluginManifest,
}

impl Default for OsvScanner {
    fn default() -> Self {
        OsvScanner::new()
    }
}

impl OsvScanner {
    pub fn new() -> OsvScanner {
        OsvScanner {
            manifest: PluginManifest::builder("osv-scanner", "OSV-Scanner")
                .description("Matches lockfiles against the Open Source Vulnerabilities database")
                .capability(Capability::DependencyAudit)
                .cost(CostTier::Fast)
                .license("Apache-2.0")
                .homepage("https://google.github.io/osv-scanner/")
                // An advisory match against a declared version is a fact, not a heuristic.
                .confidence(Confidence::new(0.95))
                .ecosystems([
                    Ecosystem::Cargo,
                    Ecosystem::Npm,
                    Ecosystem::Pypi,
                    Ecosystem::Go,
                    Ecosystem::Maven,
                    Ecosystem::RubyGems,
                    Ecosystem::Composer,
                    Ecosystem::NuGet,
                ])
                .requires(
                    BinaryRequirement::new("osv-scanner")
                        .install_hint("brew install osv-scanner, or go install github.com/google/osv-scanner/cmd/osv-scanner@latest"),
                )
                .build(),
        }
    }
}

#[async_trait]
impl Plugin for OsvScanner {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// Needs a lockfile to be worth running. A repository with a manifest but no lock has
    /// no resolved versions to match advisories against.
    fn applies_to(&self, ctx: &ScanContext) -> bool {
        const LOCKFILES: &[&str] = &[
            "Cargo.lock",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "poetry.lock",
            "requirements.txt",
            "go.sum",
            "Gemfile.lock",
            "composer.lock",
        ];
        LOCKFILES
            .iter()
            .any(|name| !ctx.files_named(name).is_empty())
    }

    async fn run(&self, ctx: &ScanContext) -> Result<PluginOutput> {
        if ctx.is_offline() {
            // The scanner can run against a local database, but the default path queries
            // the OSV API.
            return Ok(PluginOutput::skipped(
                "scan is offline and OSV-Scanner needs the advisory database",
            ));
        }

        let exec = common::command(ctx, "osv-scanner")
            .arg("--format")
            .arg("json")
            .arg("--recursive")
            .path_arg(ctx.root());

        // Exits 1 when vulnerabilities are found.
        let output = common::with_extra_args(exec, ctx).run_lenient().await?;
        Ok(PluginOutput::default().with_findings(parse(ctx.root(), &output.stdout)?))
    }
}

#[derive(Debug, Deserialize)]
struct Report {
    #[serde(default)]
    results: Vec<SourceResult>,
}

#[derive(Debug, Deserialize)]
struct SourceResult {
    #[serde(default)]
    source: Source,
    #[serde(default)]
    packages: Vec<PackageResult>,
}

#[derive(Debug, Default, Deserialize)]
struct Source {
    #[serde(default)]
    path: String,
}

#[derive(Debug, Deserialize)]
struct PackageResult {
    #[serde(default)]
    package: PackageInfo,
    #[serde(default)]
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Default, Deserialize)]
struct PackageInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    #[serde(default)]
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<SeverityEntry>,
    #[serde(default)]
    database_specific: DatabaseSpecific,
}

#[derive(Debug, Deserialize)]
struct SeverityEntry {
    #[serde(default)]
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    score: String,
}

#[derive(Debug, Default, Deserialize)]
struct DatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
}

/// Convert an OSV-Scanner report into findings, one per advisory per package.
pub fn parse(root: &Path, json: &str) -> Result<Vec<RawFinding>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let report: Report = common::parse_json("osv-scanner", json)?;
    let mut findings = Vec::new();

    for result in report.results {
        // The lockfile is the location. There is no line to point at — the vulnerable
        // version is a property of the resolved dependency graph, not of a source line.
        let location = Location::file(common::relative(root, &result.source.path));

        for package in result.packages {
            for vulnerability in package.vulnerabilities {
                findings.push(finding(&location, &package.package, vulnerability));
            }
        }
    }
    Ok(findings)
}

fn finding(location: &Location, package: &PackageInfo, vulnerability: Vulnerability) -> RawFinding {
    let severity = advisory_severity(&vulnerability);
    let title = if vulnerability.summary.is_empty() {
        format!("{} affects {}", vulnerability.id, package.name)
    } else {
        vulnerability.summary.clone()
    };

    let cves: Vec<String> = vulnerability
        .aliases
        .iter()
        .filter(|alias| alias.starts_with("CVE-"))
        .cloned()
        .chain(
            std::iter::once(vulnerability.id.clone())
                .filter(|id| id.starts_with("CVE-")),
        )
        .collect();

    let mut finding = RawFinding::new(
        "osv-scanner",
        &vulnerability.id,
        title,
        severity,
        location.clone(),
    )
    .with_description(format!(
        "{} {} is affected by {}.{}",
        package.name,
        package.version,
        vulnerability.id,
        if vulnerability.details.is_empty() {
            String::new()
        } else {
            format!(" {}", first_paragraph(&vulnerability.details))
        }
    ))
    .with_cve(cves)
    .with_confidence(Confidence::new(0.95));

    finding.references = vec![format!("https://osv.dev/vulnerability/{}", vulnerability.id)];
    finding
        .metadata
        .insert("package".into(), package.name.clone().into());
    finding
        .metadata
        .insert("installed_version".into(), package.version.clone().into());
    if !package.ecosystem.is_empty() {
        finding
            .metadata
            .insert("ecosystem".into(), package.ecosystem.clone().into());
    }
    if !vulnerability.aliases.is_empty() {
        finding
            .metadata
            .insert("aliases".into(), vulnerability.aliases.into());
    }
    finding
}

/// Prefer a CVSS vector when the advisory carries one, and fall back to the database's own
/// word. An advisory with neither is Medium: unknown is not the same as harmless.
fn advisory_severity(vulnerability: &Vulnerability) -> Severity {
    for entry in &vulnerability.severity {
        if entry.kind.starts_with("CVSS") {
            if let Some(score) = cvss_base_score(&entry.score) {
                return common::severity_from_cvss(score);
            }
        }
    }
    match &vulnerability.database_specific.severity {
        Some(word) => common::severity(word, Severity::Medium),
        None => Severity::Medium,
    }
}

/// Extract a base score from a CVSS vector string, or from a bare numeric score.
fn cvss_base_score(raw: &str) -> Option<f64> {
    if let Ok(score) = raw.trim().parse::<f64>() {
        return Some(score);
    }
    // Vectors do not carry the score itself, only the metrics. Computing it properly means
    // implementing CVSS; instead the caller falls back to the database's severity word.
    None
}

fn first_paragraph(details: &str) -> String {
    let paragraph = details.split("\n\n").next().unwrap_or(details).trim();
    if paragraph.chars().count() > 400 {
        format!("{}…", paragraph.chars().take(400).collect::<String>())
    } else {
        paragraph.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{
      "results": [
        {
          "source": { "path": "/repo/Cargo.lock", "type": "lockfile" },
          "packages": [
            {
              "package": { "name": "openssl", "version": "0.10.55", "ecosystem": "crates.io" },
              "vulnerabilities": [
                {
                  "id": "RUSTSEC-2023-0044",
                  "summary": "openssl leaks memory",
                  "details": "A long description.\n\nA second paragraph.",
                  "aliases": ["CVE-2023-1234", "GHSA-xxxx-yyyy-zzzz"],
                  "severity": [{ "type": "CVSS_V3", "score": "7.5" }],
                  "database_specific": { "severity": "HIGH" }
                }
              ]
            },
            {
              "package": { "name": "time", "version": "0.1.44", "ecosystem": "crates.io" },
              "vulnerabilities": [
                {
                  "id": "RUSTSEC-2020-0071",
                  "summary": "Potential segfault",
                  "aliases": [],
                  "severity": [],
                  "database_specific": { "severity": "LOW" }
                }
              ]
            }
          ]
        }
      ]
    }"#;

    fn parsed() -> Vec<RawFinding> {
        parse(Path::new("/repo"), REPORT).unwrap()
    }

    #[test]
    fn one_finding_per_advisory_per_package() {
        assert_eq!(parsed().len(), 2);
    }

    #[test]
    fn the_lockfile_is_the_location() {
        assert_eq!(parsed()[0].location.path.to_str().unwrap(), "Cargo.lock");
        assert!(
            parsed()[0].location.span.is_none(),
            "a resolved version has no source line"
        );
    }

    #[test]
    fn a_cvss_score_decides_severity() {
        assert_eq!(parsed()[0].severity, Severity::High);
    }

    #[test]
    fn the_database_severity_word_is_the_fallback() {
        assert_eq!(parsed()[1].severity, Severity::Low);
    }

    #[test]
    fn an_advisory_with_no_severity_at_all_is_medium_not_info() {
        let findings = parse(
            Path::new("/repo"),
            r#"{"results":[{"source":{"path":"go.sum"},"packages":[{"package":{"name":"x","version":"1"},"vulnerabilities":[{"id":"GHSA-1"}]}]}]}"#,
        )
        .unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn cve_aliases_are_extracted_and_ghsa_ones_are_not() {
        assert_eq!(parsed()[0].cve, vec!["CVE-2023-1234"]);
    }

    #[test]
    fn the_package_and_version_survive_into_metadata() {
        let metadata = &parsed()[0].metadata;
        assert_eq!(metadata.get("package").unwrap(), "openssl");
        assert_eq!(metadata.get("installed_version").unwrap(), "0.10.55");
    }

    #[test]
    fn long_details_are_truncated_to_the_first_paragraph() {
        assert!(parsed()[0].description.contains("A long description."));
        assert!(!parsed()[0].description.contains("second paragraph"));
    }

    #[test]
    fn every_finding_links_to_the_advisory() {
        assert_eq!(
            parsed()[0].references,
            vec!["https://osv.dev/vulnerability/RUSTSEC-2023-0044"]
        );
    }

    #[test]
    fn an_empty_report_is_not_an_error() {
        assert!(parse(Path::new("/repo"), r#"{"results":[]}"#).unwrap().is_empty());
        assert!(parse(Path::new("/repo"), "").unwrap().is_empty());
    }

    #[test]
    fn applicability_needs_a_lockfile() {
        let ctx = ScanContext::new("/repo", quoll_core::Profile::Fast);
        let with_lock = ctx.clone().with_files(vec!["Cargo.lock".into()]);
        let without = ctx.with_files(vec!["Cargo.toml".into()]);

        assert!(OsvScanner::new().applies_to(&with_lock));
        assert!(!OsvScanner::new().applies_to(&without));
    }
}
