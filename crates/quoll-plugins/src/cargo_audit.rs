use std::path::Path;

use quoll_core::{Confidence, Ecosystem, Language, Location, RawFinding, Result, Severity};
use quoll_plugin::{
    async_trait, BinaryRequirement, Capability, CostTier, Plugin, PluginManifest, PluginOutput,
    ScanContext,
};
use serde::Deserialize;

use crate::common;

/// cargo-audit: the RustSec advisory database against `Cargo.lock`.
pub struct CargoAudit {
    manifest: PluginManifest,
}

impl Default for CargoAudit {
    fn default() -> Self {
        CargoAudit::new()
    }
}

impl CargoAudit {
    pub fn new() -> CargoAudit {
        CargoAudit {
            manifest: PluginManifest::builder("cargo-audit", "cargo-audit")
                .description("Checks Cargo.lock against the RustSec advisory database")
                .capability(Capability::DependencyAudit)
                .cost(CostTier::Fast)
                .license("Apache-2.0 OR MIT")
                .homepage("https://rustsec.org")
                .confidence(Confidence::new(0.95))
                .languages([Language::Rust])
                .ecosystems([Ecosystem::Cargo])
                .requires(
                    BinaryRequirement::new("cargo-audit")
                        .install_hint("cargo install cargo-audit"),
                )
                .build(),
        }
    }
}

#[async_trait]
impl Plugin for CargoAudit {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// Rust alone is not enough — the advisory database matches resolved versions, and
    /// those live in `Cargo.lock`. A library crate that does not commit one has nothing
    /// for this scanner to check.
    fn applies_to(&self, ctx: &ScanContext) -> bool {
        !ctx.files_named("Cargo.lock").is_empty()
    }

    async fn run(&self, ctx: &ScanContext) -> Result<PluginOutput> {
        let lockfiles = ctx.files_named("Cargo.lock");
        let lockfile = match lockfiles.first() {
            Some(path) => path.clone(),
            None => return Ok(PluginOutput::skipped("no Cargo.lock")),
        };

        let mut exec = common::command(ctx, "cargo-audit")
            .arg("audit")
            .arg("--json")
            .arg("--file")
            .path_arg(ctx.absolute(&lockfile));

        if ctx.is_offline() {
            // The advisory database is a git checkout; without a fetch, cargo-audit uses
            // whatever is already cached rather than failing.
            exec = exec.arg("--no-fetch");
        }

        // Exits 1 when advisories are found.
        let output = common::with_extra_args(exec, ctx).run_lenient().await?;
        if output.stdout.trim().is_empty() {
            return Ok(PluginOutput::default()
                .warn(format!("cargo-audit produced no report: {}", output.error_summary())));
        }

        Ok(PluginOutput::default().with_findings(parse(&lockfile, &output.stdout)?))
    }
}

#[derive(Debug, Deserialize)]
struct Report {
    #[serde(default)]
    vulnerabilities: Vulnerabilities,
    #[serde(default)]
    warnings: std::collections::BTreeMap<String, Vec<Warning>>,
}

#[derive(Debug, Default, Deserialize)]
struct Vulnerabilities {
    #[serde(default)]
    list: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    advisory: Advisory,
    #[serde(default)]
    package: Package,
    #[serde(default)]
    versions: Versions,
}

#[derive(Debug, Default, Deserialize)]
struct Advisory {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    cvss: Option<String>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    withdrawn: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Package {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Default, Deserialize)]
struct Versions {
    #[serde(default)]
    patched: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Warning {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    package: Package,
    #[serde(default)]
    advisory: Option<Advisory>,
}

/// Convert a cargo-audit JSON report into findings.
///
/// Warnings — unmaintained and yanked crates — are included at a lower severity. They are
/// not vulnerabilities, but an unmaintained dependency is how a repository acquires one.
pub fn parse(lockfile: &Path, json: &str) -> Result<Vec<RawFinding>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let report: Report = common::parse_json("cargo-audit", json)?;
    let location = Location::file(lockfile.to_path_buf());
    let mut findings = Vec::new();

    for entry in report.vulnerabilities.list {
        // A withdrawn advisory has been retracted by RustSec. Reporting it would send
        // someone chasing a vulnerability that no longer exists.
        if entry.advisory.withdrawn.is_some() {
            continue;
        }
        findings.push(vulnerability(&location, entry));
    }

    for (kind, warnings) in report.warnings {
        for warning in warnings {
            findings.push(unmaintained(&location, &kind, warning));
        }
    }
    Ok(findings)
}

fn vulnerability(location: &Location, entry: Entry) -> RawFinding {
    let advisory = entry.advisory;
    let severity = match &advisory.cvss {
        Some(vector) => cvss_severity(vector),
        None => Severity::High,
    };

    let remediation = if entry.versions.patched.is_empty() {
        "No patched version is available; consider replacing the dependency.".to_string()
    } else {
        format!("Upgrade to {}.", entry.versions.patched.join(" or "))
    };

    let mut finding = RawFinding::new(
        "cargo-audit",
        &advisory.id,
        if advisory.title.is_empty() {
            format!("{} affects {}", advisory.id, entry.package.name)
        } else {
            advisory.title.clone()
        },
        severity,
        location.clone(),
    )
    .with_description(format!(
        "{} {} is affected by {}. {remediation}",
        entry.package.name, entry.package.version, advisory.id
    ))
    .with_cve(
        advisory
            .aliases
            .iter()
            .filter(|alias| alias.starts_with("CVE-"))
            .cloned(),
    )
    .with_confidence(Confidence::new(0.95));

    finding.references = advisory.url.into_iter().collect();
    finding
        .metadata
        .insert("package".into(), entry.package.name.into());
    finding
        .metadata
        .insert("installed_version".into(), entry.package.version.into());
    if !entry.versions.patched.is_empty() {
        finding
            .metadata
            .insert("patched_versions".into(), entry.versions.patched.into());
    }
    if !advisory.categories.is_empty() {
        finding
            .metadata
            .insert("categories".into(), advisory.categories.into());
    }
    finding
}

fn unmaintained(location: &Location, kind: &str, warning: Warning) -> RawFinding {
    let advisory = warning.advisory.unwrap_or_default();
    let kind = if warning.kind.is_empty() {
        kind.to_string()
    } else {
        warning.kind.clone()
    };

    let rule = if advisory.id.is_empty() {
        format!("cargo-audit/{kind}")
    } else {
        advisory.id.clone()
    };

    let mut finding = RawFinding::new(
        "cargo-audit",
        rule,
        format!("{} is {}", warning.package.name, kind.replace('-', " ")),
        // A warning is a maintenance risk, not an exploitable defect today.
        Severity::Low,
        location.clone(),
    )
    .with_description(if advisory.description.is_empty() {
        format!(
            "cargo-audit reports `{}` as {kind}.",
            warning.package.name
        )
    } else {
        advisory.description.clone()
    })
    .with_confidence(Confidence::new(0.9));

    finding.references = advisory.url.into_iter().collect();
    finding
        .metadata
        .insert("package".into(), warning.package.name.into());
    finding.metadata.insert("warning_kind".into(), kind.into());
    finding
}

/// Read the base score out of a CVSS v3 vector.
///
/// RustSec stores the vector, not the score. Rather than implement the full CVSS
/// calculation, this reads the severity from the impact metrics that dominate it — enough
/// to place the advisory in the right band, and honest about being an approximation.
fn cvss_severity(vector: &str) -> Severity {
    if let Ok(score) = vector.trim().parse::<f64>() {
        return common::severity_from_cvss(score);
    }
    let upper = vector.to_ascii_uppercase();
    let high_impact = upper.matches("H").count();
    match (upper.contains("AV:N"), high_impact) {
        (true, impacts) if impacts >= 3 => Severity::Critical,
        (true, impacts) if impacts >= 1 => Severity::High,
        (true, _) => Severity::Medium,
        (false, impacts) if impacts >= 2 => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{
      "vulnerabilities": {
        "found": true,
        "count": 1,
        "list": [
          {
            "advisory": {
              "id": "RUSTSEC-2023-0044",
              "title": "openssl leaks memory",
              "description": "A description.",
              "url": "https://rustsec.org/advisories/RUSTSEC-2023-0044",
              "aliases": ["CVE-2023-1234"],
              "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "categories": ["memory-exposure"]
            },
            "package": { "name": "openssl", "version": "0.10.55" },
            "versions": { "patched": [">=0.10.57"] }
          }
        ]
      },
      "warnings": {
        "unmaintained": [
          {
            "kind": "unmaintained",
            "package": { "name": "ansi_term", "version": "0.12.1" },
            "advisory": {
              "id": "RUSTSEC-2021-0139",
              "description": "ansi_term is unmaintained.",
              "url": "https://rustsec.org/advisories/RUSTSEC-2021-0139"
            }
          }
        ]
      }
    }"#;

    fn parsed() -> Vec<RawFinding> {
        parse(Path::new("Cargo.lock"), REPORT).unwrap()
    }

    #[test]
    fn parses_vulnerabilities_and_warnings() {
        assert_eq!(parsed().len(), 2);
    }

    #[test]
    fn the_lockfile_is_the_location() {
        assert!(parsed().iter().all(|f| f.location.path == Path::new("Cargo.lock")));
    }

    #[test]
    fn a_network_reachable_full_impact_advisory_is_critical() {
        assert_eq!(parsed()[0].severity, Severity::Critical);
    }

    #[test]
    fn warnings_rank_below_vulnerabilities() {
        let warning = parsed().into_iter().find(|f| f.rule_id.contains("2021")).unwrap();
        assert_eq!(warning.severity, Severity::Low);
        assert!(warning.title.contains("unmaintained"));
    }

    #[test]
    fn the_fix_is_named_in_the_description() {
        assert!(parsed()[0].description.contains(">=0.10.57"), "{}", parsed()[0].description);
    }

    #[test]
    fn cve_aliases_are_carried_through() {
        assert_eq!(parsed()[0].cve, vec!["CVE-2023-1234"]);
    }

    #[test]
    fn a_withdrawn_advisory_is_not_reported() {
        let withdrawn = REPORT.replace(
            r#""id": "RUSTSEC-2023-0044","#,
            r#""id": "RUSTSEC-2023-0044", "withdrawn": "2024-01-01","#,
        );
        let findings = parse(Path::new("Cargo.lock"), &withdrawn).unwrap();
        assert_eq!(findings.len(), 1, "only the warning should remain");
    }

    #[test]
    fn a_clean_audit_produces_nothing() {
        let clean = r#"{"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#;
        assert!(parse(Path::new("Cargo.lock"), clean).unwrap().is_empty());
    }

    #[test]
    fn an_advisory_with_no_cvss_is_high_not_unknown() {
        let text = r#"{"vulnerabilities":{"list":[{"advisory":{"id":"R-1","title":"T"},"package":{"name":"p","version":"1"}}]},"warnings":{}}"#;
        assert_eq!(parse(Path::new("Cargo.lock"), text).unwrap()[0].severity, Severity::High);
    }

    #[test]
    fn applicability_needs_a_lockfile_not_merely_rust() {
        let ctx = ScanContext::new("/repo", quoll_core::Profile::Fast);
        assert!(!CargoAudit::new().applies_to(&ctx.clone().with_files(vec!["src/main.rs".into()])));
        assert!(CargoAudit::new().applies_to(&ctx.with_files(vec!["Cargo.lock".into()])));
    }
}
