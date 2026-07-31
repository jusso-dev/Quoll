use std::path::Path;

use quoll_core::{Confidence, Location, RawFinding, Result, Severity, Span};
use quoll_plugin::{
    async_trait, BinaryRequirement, Capability, CostTier, Plugin, PluginManifest, PluginOutput,
    ScanContext,
};
use serde::Deserialize;

use crate::common;

/// Trivy: dependencies, infrastructure-as-code and container configuration.
pub struct Trivy {
    manifest: PluginManifest,
}

impl Default for Trivy {
    fn default() -> Self {
        Trivy::new()
    }
}

impl Trivy {
    pub fn new() -> Trivy {
        Trivy {
            manifest: PluginManifest::builder("trivy", "Trivy")
                .description("Dependency, IaC and container misconfiguration scanning")
                .capability(Capability::DependencyAudit)
                .capability(Capability::IacScanning)
                .capability(Capability::ContainerScanning)
                // Trivy downloads and updates a vulnerability database, and scans broadly.
                // Fine in CI, too slow for a pre-commit hook.
                .cost(CostTier::Moderate)
                .license("Apache-2.0")
                .homepage("https://trivy.dev")
                .confidence(Confidence::new(0.85))
                .requires(
                    BinaryRequirement::new("trivy")
                        .install_hint("brew install trivy, or see https://trivy.dev/latest/getting-started/installation/"),
                )
                .build(),
        }
    }
}

#[async_trait]
impl Plugin for Trivy {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn applies_to(&self, _ctx: &ScanContext) -> bool {
        true
    }

    async fn run(&self, ctx: &ScanContext) -> Result<PluginOutput> {
        if ctx.is_offline() {
            return Ok(PluginOutput::skipped(
                "scan is offline and Trivy needs its vulnerability database",
            ));
        }

        let exec = common::command(ctx, "trivy")
            .arg("filesystem")
            .arg("--format")
            .arg("json")
            .arg("--quiet")
            .arg("--scanners")
            .arg("vuln,misconfig")
            // Findings are the expected outcome; a non-zero exit here would be noise.
            .arg("--exit-code")
            .arg("0")
            .path_arg(ctx.root());

        let output = common::with_extra_args(exec, ctx).run_lenient().await?;
        Ok(PluginOutput::default().with_findings(parse(ctx.root(), &output.stdout)?))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Report {
    #[serde(default)]
    results: Vec<TargetResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TargetResult {
    #[serde(default)]
    target: String,
    #[serde(default)]
    vulnerabilities: Vec<Vulnerability>,
    #[serde(default)]
    misconfigurations: Vec<Misconfiguration>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Vulnerability {
    #[serde(rename = "VulnerabilityID", default)]
    id: String,
    #[serde(default)]
    pkg_name: String,
    #[serde(default)]
    installed_version: String,
    #[serde(default)]
    fixed_version: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(rename = "CweIDs", default)]
    cwe_ids: Vec<String>,
    #[serde(rename = "PrimaryURL", default)]
    primary_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Misconfiguration {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    resolution: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    cause_metadata: CauseMetadata,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CauseMetadata {
    #[serde(default)]
    start_line: i64,
    #[serde(default)]
    end_line: i64,
    #[serde(default)]
    resource: Option<String>,
}

/// Convert a Trivy filesystem report into findings.
pub fn parse(root: &Path, json: &str) -> Result<Vec<RawFinding>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let report: Report = common::parse_json("trivy", json)?;
    let mut findings = Vec::new();

    for result in report.results {
        let path = common::relative(root, &result.target);

        for vulnerability in result.vulnerabilities {
            findings.push(dependency_finding(&path, vulnerability));
        }
        for misconfiguration in result.misconfigurations {
            findings.push(misconfiguration_finding(&path, misconfiguration));
        }
    }
    Ok(findings)
}

fn dependency_finding(path: &Path, vulnerability: Vulnerability) -> RawFinding {
    let remediation = if vulnerability.fixed_version.is_empty() {
        "No fixed version is published yet.".to_string()
    } else {
        format!("Upgrade to {}.", vulnerability.fixed_version)
    };

    let title = if vulnerability.title.is_empty() {
        format!("{} affects {}", vulnerability.id, vulnerability.pkg_name)
    } else {
        vulnerability.title.clone()
    };

    let mut finding = RawFinding::new(
        "trivy",
        &vulnerability.id,
        title,
        common::severity(&vulnerability.severity, Severity::Medium),
        Location::file(path.to_path_buf()),
    )
    .with_description(format!(
        "{} {} is affected by {}. {remediation}",
        vulnerability.pkg_name, vulnerability.installed_version, vulnerability.id
    ))
    .with_cwe(vulnerability.cwe_ids)
    .with_cve(
        std::iter::once(vulnerability.id.clone()).filter(|id| id.starts_with("CVE-")),
    )
    .with_confidence(Confidence::new(0.9));

    finding.references = vulnerability
        .primary_url
        .into_iter()
        .chain(vulnerability.references)
        .collect();
    finding
        .metadata
        .insert("package".into(), vulnerability.pkg_name.into());
    finding
        .metadata
        .insert("installed_version".into(), vulnerability.installed_version.into());
    if !vulnerability.fixed_version.is_empty() {
        finding
            .metadata
            .insert("fixed_version".into(), vulnerability.fixed_version.into());
    }
    if !vulnerability.description.is_empty() {
        finding
            .metadata
            .insert("detail".into(), vulnerability.description.into());
    }
    finding
}

fn misconfiguration_finding(path: &Path, misconfiguration: Misconfiguration) -> RawFinding {
    let mut location = Location::file(path.to_path_buf());
    if let Some(start) = common::line(misconfiguration.cause_metadata.start_line) {
        let span = match common::line(misconfiguration.cause_metadata.end_line) {
            Some(end) if end > start => Span::lines(start, end),
            _ => Span::line(start),
        };
        location = location.with_span(span);
    }

    let description = [
        misconfiguration.message.trim(),
        misconfiguration.description.trim(),
        misconfiguration.resolution.trim(),
    ]
    .iter()
    .filter(|part| !part.is_empty())
    .cloned()
    .collect::<Vec<_>>()
    .join(" ");

    let mut finding = RawFinding::new(
        "trivy",
        &misconfiguration.id,
        if misconfiguration.title.is_empty() {
            misconfiguration.id.clone()
        } else {
            misconfiguration.title.clone()
        },
        common::severity(&misconfiguration.severity, Severity::Medium),
        location,
    )
    .with_description(description)
    .with_confidence(Confidence::new(0.85));

    finding.references = misconfiguration.references;
    if let Some(resource) = misconfiguration.cause_metadata.resource {
        finding.metadata.insert("resource".into(), resource.into());
    }
    finding
        .metadata
        .insert("finding_kind".into(), "misconfiguration".into());
    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{
      "Results": [
        {
          "Target": "package-lock.json",
          "Class": "lang-pkgs",
          "Type": "npm",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2024-1234",
              "PkgName": "lodash",
              "InstalledVersion": "4.17.20",
              "FixedVersion": "4.17.21",
              "Severity": "HIGH",
              "Title": "Prototype pollution in lodash",
              "Description": "Detailed text.",
              "CweIDs": ["CWE-1321"],
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-1234",
              "References": ["https://github.com/lodash/lodash/issues/1"]
            }
          ]
        },
        {
          "Target": "infra/main.tf",
          "Class": "config",
          "Type": "terraform",
          "Misconfigurations": [
            {
              "ID": "AVD-AWS-0088",
              "Title": "S3 bucket is not encrypted",
              "Description": "Buckets should be encrypted at rest.",
              "Message": "Bucket 'assets' has no encryption configured.",
              "Severity": "MEDIUM",
              "Resolution": "Enable server-side encryption.",
              "References": ["https://avd.aquasec.com/misconfig/avd-aws-0088"],
              "CauseMetadata": { "StartLine": 12, "EndLine": 18, "Resource": "aws_s3_bucket.assets" }
            }
          ]
        }
      ]
    }"#;

    fn parsed() -> Vec<RawFinding> {
        parse(Path::new("/repo"), REPORT).unwrap()
    }

    #[test]
    fn parses_both_vulnerabilities_and_misconfigurations() {
        assert_eq!(parsed().len(), 2);
    }

    #[test]
    fn dependency_findings_carry_the_fix() {
        let finding = &parsed()[0];
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.description.contains("4.17.21"));
        assert_eq!(finding.metadata.get("fixed_version").unwrap(), "4.17.21");
        assert_eq!(finding.cve, vec!["CVE-2024-1234"]);
        assert_eq!(finding.cwe, vec!["CWE-1321"]);
    }

    #[test]
    fn misconfigurations_point_at_a_line_range() {
        let finding = &parsed()[1];
        let span = finding.location.span.unwrap();
        assert_eq!(span.start_line, 12);
        assert_eq!(span.end_line, Some(18));
        assert_eq!(finding.location.path.to_str().unwrap(), "infra/main.tf");
    }

    #[test]
    fn the_misconfiguration_description_combines_message_detail_and_resolution() {
        let description = &parsed()[1].description;
        assert!(description.contains("has no encryption"), "{description}");
        assert!(description.contains("Enable server-side encryption"), "{description}");
    }

    #[test]
    fn the_primary_url_leads_the_references() {
        assert_eq!(
            parsed()[0].references[0],
            "https://avd.aquasec.com/nvd/cve-2024-1234"
        );
        assert_eq!(parsed()[0].references.len(), 2);
    }

    #[test]
    fn the_terraform_resource_is_kept() {
        assert_eq!(
            parsed()[1].metadata.get("resource").unwrap(),
            "aws_s3_bucket.assets"
        );
    }

    #[test]
    fn an_unknown_severity_word_falls_back_to_medium() {
        let text = r#"{"Results":[{"Target":"a","Vulnerabilities":[{"VulnerabilityID":"X","Severity":"SPICY"}]}]}"#;
        assert_eq!(parse(Path::new("/repo"), text).unwrap()[0].severity, Severity::Medium);
    }

    #[test]
    fn an_empty_report_is_not_an_error() {
        assert!(parse(Path::new("/repo"), r#"{"Results":[]}"#).unwrap().is_empty());
        assert!(parse(Path::new("/repo"), "").unwrap().is_empty());
    }

    #[test]
    fn the_manifest_declares_three_capabilities() {
        let manifest = Trivy::new().manifest().clone();
        assert!(manifest.has_capability(Capability::DependencyAudit));
        assert!(manifest.has_capability(Capability::IacScanning));
        assert!(manifest.has_capability(Capability::ContainerScanning));
        assert_eq!(manifest.cost, CostTier::Moderate);
    }
}
