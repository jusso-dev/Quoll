use std::collections::BTreeMap;
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
        if lockfiles.is_empty() {
            return Ok(PluginOutput::skipped("no Cargo.lock"));
        }

        // A repository can hold several independent workspaces (a fuzz crate, an example,
        // a vendored tool), each with its own lockfile. Every one is audited.
        let mut findings = Vec::new();
        for (index, lockfile) in lockfiles.iter().enumerate() {
            let mut exec = common::command(ctx, "cargo-audit")
                .inherit_env(["CARGO_HOME", "RUSTUP_HOME", "CARGO_NET_*", "CARGO_HTTP_*"])
                .arg("audit")
                .arg("--json")
                .arg("--file")
                .path_arg(ctx.absolute(lockfile));

            // The advisory database is a git checkout; without a fetch, cargo-audit uses
            // whatever is already cached rather than failing. After the first lockfile the
            // cache is fresh, so fetching again only costs time.
            if ctx.is_offline() || index > 0 {
                exec = exec.arg("--no-fetch");
            }

            // Exits 1 when advisories are found, and also when it fails — but a failure
            // prints no report, which `common::report` rejects.
            let output = common::with_extra_args(exec, ctx)
                .success_codes([0, 1])
                .run()
                .await?;
            findings.extend(parse(lockfile, common::report("cargo-audit", &output)?)?);
        }

        Ok(PluginOutput::default().with_findings(findings))
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

/// Place a CVSS vector in a severity band.
///
/// RustSec stores the vector, not the score. CVSS 3.x vectors are scored exactly with the
/// specification's base formula. Anything else — CVSS 4.0, whose scoring is a lookup table
/// too large to carry here, or a malformed vector — falls back to counting high
/// confidentiality/integrity/availability impacts, which is an approximation and says so.
fn cvss_severity(vector: &str) -> Severity {
    if let Ok(score) = vector.trim().parse::<f64>() {
        return common::severity_from_cvss(score);
    }
    let upper = vector.trim().to_ascii_uppercase();
    let metrics: BTreeMap<&str, &str> = upper
        .split('/')
        .filter_map(|pair| pair.split_once(':'))
        .collect();

    if metrics.get("CVSS").is_some_and(|v| v.starts_with("3.")) {
        if let Some(score) = cvss3_base_score(&metrics) {
            return common::severity_from_cvss(score);
        }
    }

    // Only impact metrics count. Matching any `H` would let `AC:H` or `PR:H` — which make
    // a vulnerability harder to exploit — raise its severity.
    const IMPACTS: &[&str] = &["C", "I", "A", "VC", "VI", "VA", "SC", "SI", "SA"];
    let high_impact = IMPACTS
        .iter()
        .filter(|metric| metrics.get(*metric) == Some(&"H"))
        .count();
    match (metrics.get("AV") == Some(&"N"), high_impact) {
        (true, impacts) if impacts >= 3 => Severity::Critical,
        (true, impacts) if impacts >= 1 => Severity::High,
        (true, _) => Severity::Medium,
        (false, impacts) if impacts >= 2 => Severity::Medium,
        _ => Severity::Low,
    }
}

/// The CVSS 3.x base score, per section 7.1 of the v3.1 specification.
///
/// `None` when a base metric is missing or has a value the specification does not define.
fn cvss3_base_score(metrics: &BTreeMap<&str, &str>) -> Option<f64> {
    let get = |key: &str| metrics.get(key).copied();
    let changed = match get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let attack_vector = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let attack_complexity = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let privileges = match (get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let interaction = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let impact_of = |key: &str| match get(key)? {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let (c, i, a) = (impact_of("C")?, impact_of("I")?, impact_of("A")?);

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability =
        8.22 * attack_vector * attack_complexity * privileges * interaction;
    let base = if changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(round_up(base))
}

/// CVSS 3.1 `Roundup`: the smallest one-decimal number not below the input, computed in
/// integers so floating-point noise cannot push 4.0 to 4.1.
fn round_up(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) + 1) as f64 / 10.0
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
    fn cvss3_vectors_are_scored_with_the_specification_formula() {
        let score = |v: &str| {
            let upper = v.to_ascii_uppercase();
            let metrics: BTreeMap<&str, &str> =
                upper.split('/').filter_map(|p| p.split_once(':')).collect();
            cvss3_base_score(&metrics).unwrap()
        };
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
        assert_eq!(score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8);
        assert_eq!(score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
    }

    #[test]
    fn hard_to_exploit_metrics_do_not_raise_severity() {
        // `AC:H` and `PR:H` make this harder to exploit; the old letter count read them
        // as high impact and called it High. It scores 2.0.
        assert_eq!(
            cvss_severity("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"),
            Severity::Low
        );
    }

    #[test]
    fn cvss4_falls_back_to_counting_only_impact_metrics() {
        let low_impact = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N";
        assert_eq!(cvss_severity(low_impact), Severity::Medium);
        let full_impact = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
        assert_eq!(cvss_severity(full_impact), Severity::Critical);
    }

    #[test]
    fn applicability_needs_a_lockfile_not_merely_rust() {
        let ctx = ScanContext::new("/repo", quoll_core::Profile::Fast);
        assert!(!CargoAudit::new().applies_to(&ctx.clone().with_files(vec!["src/main.rs".into()])));
        assert!(CargoAudit::new().applies_to(&ctx.with_files(vec!["Cargo.lock".into()])));
    }
}
