//! SARIF 2.1.0 export.
//!
//! SARIF is the format GitHub code scanning, VS Code and most CI dashboards understand.
//! Quoll emits a single run whose driver is Quoll itself; rules are synthesised from the
//! findings so a consumer that only knows SARIF still gets a stable rule id, a severity
//! level and a clickable location.
//!
//! Quoll-specific fields (confidence, verification, contributing plugins, evidence) ride
//! in `properties` so a strict SARIF consumer can ignore them and a Quoll-aware one can
//! rehydrate the richer document.

use std::collections::BTreeMap;

use quoll_core::{FindingStatus, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{Report, ReportedFinding};

const SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const VERSION: &str = "2.1.0";

/// SARIF 2.1.0 document for the report.
pub fn render(report: &Report) -> Result<String> {
    let log = build(report);
    Ok(serde_json::to_string_pretty(&log)?)
}

fn build(report: &Report) -> SarifLog {
    let mut rules_by_id: BTreeMap<String, SarifRule> = BTreeMap::new();
    let mut results = Vec::with_capacity(report.findings.len());

    for item in &report.findings {
        let rule_id = rule_id(item);
        rules_by_id
            .entry(rule_id.clone())
            .or_insert_with(|| rule_for(item, &rule_id));
        results.push(result_for(item, &rule_id));
    }

    let rules: Vec<SarifRule> = rules_by_id.into_values().collect();

    let mut invocation = SarifInvocation {
        execution_successful: !report.coverage.is_degraded(),
        start_time_utc: Some(report.scan.started_at.clone()),
        end_time_utc: report.scan.completed_at.clone(),
        working_directory: Some(SarifArtifactLocation {
            uri: path_uri(&report.scan.root),
            uri_base_id: None,
        }),
        properties: None,
    };
    if report.coverage.is_degraded() || !report.verification.is_clean() {
        invocation.properties = Some(json!({
            "pluginsDegraded": report.coverage.plugins_degraded,
            "verification": report.verification,
        }));
    }

    SarifLog {
        schema: SCHEMA,
        version: VERSION,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: report.tool.name.clone(),
                    version: Some(report.tool.version.clone()),
                    information_uri: Some(report.tool.information_uri.clone()),
                    rules,
                },
            },
            results,
            invocations: vec![invocation],
            version_control_provenance: report.scan.commit.as_ref().map(|commit| {
                vec![SarifVersionControl {
                    repository_uri: None,
                    revision_id: Some(commit.clone()),
                }]
            }),
            original_uri_base_ids: {
                let mut map = BTreeMap::new();
                map.insert(
                    "%SRCROOT%".to_string(),
                    SarifArtifactLocation {
                        uri: path_uri(&report.scan.root),
                        uri_base_id: None,
                    },
                );
                map
            },
            properties: Some(json!({
                "schemaVersion": report.schema_version,
                "scanId": report.scan.id,
                "profile": report.scan.profile,
                "filesScanned": report.scan.files_scanned,
                "coverage": report.coverage,
                "verification": report.verification,
            })),
        }],
    }
}

fn rule_id(item: &ReportedFinding) -> String {
    for evidence in &item.finding.evidence {
        if let quoll_core::EvidenceSource::Scanner { plugin, rule } = &evidence.source {
            return format!("{plugin}/{rule}");
        }
    }
    // Policy and graph findings have no scanner rule; the finding id is stable and short.
    format!("quoll/{}", item.finding.id)
}

fn rule_for(item: &ReportedFinding, id: &str) -> SarifRule {
    let finding = &item.finding;
    let mut properties = json!({
        "security-severity": format!("{:.1}", finding.severity.nominal_cvss()),
        "precision": precision(finding.confidence.value()),
    });
    if !finding.cwe.is_empty() {
        properties["cwe"] = json!(finding.cwe);
    }
    if !finding.cve.is_empty() {
        properties["cve"] = json!(finding.cve);
    }

    SarifRule {
        id: id.to_string(),
        name: Some(finding.title.clone()),
        short_description: Some(SarifMessage {
            text: finding.title.clone(),
        }),
        full_description: non_empty(&finding.description).map(|text| SarifMessage {
            text: text.to_string(),
        }),
        help: finding.remediation.as_ref().map(|r| SarifMessage {
            text: r.summary.clone(),
        }),
        default_configuration: Some(SarifReportingConfig {
            level: finding.severity.sarif_level().to_string(),
        }),
        properties: Some(properties),
    }
}

fn result_for(item: &ReportedFinding, rule_id: &str) -> SarifResult {
    let finding = &item.finding;
    let mut properties = json!({
        "quollId": finding.id,
        "fingerprint": finding.fingerprint,
        "confidence": finding.confidence.value(),
        "status": finding.status.as_str(),
        "severity": finding.severity.as_str(),
        "locationVerified": item.location_verified,
        "contributingPlugins": finding.contributing_plugins,
        "usedAi": finding.used_ai(),
    });
    if let Some(note) = &item.verification_note {
        properties["verificationNote"] = json!(note);
    }
    if !finding.cwe.is_empty() {
        properties["cwe"] = json!(finding.cwe);
    }
    if !finding.evidence.is_empty() {
        properties["evidence"] = json!(finding
            .evidence
            .iter()
            .map(|e| {
                let kind = match e.kind {
                    quoll_core::EvidenceKind::Supporting => "supporting",
                    quoll_core::EvidenceKind::Refuting => "refuting",
                    quoll_core::EvidenceKind::Contextual => "contextual",
                };
                json!({
                    "source": e.source.label(),
                    "kind": kind,
                    "description": e.description,
                    "confidence": e.confidence.value(),
                })
            })
            .collect::<Vec<_>>());
    }

    let mut partial = BTreeMap::new();
    partial.insert("quollFingerprint".to_string(), finding.fingerprint.clone());

    SarifResult {
        rule_id: rule_id.to_string(),
        level: Some(finding.severity.sarif_level().to_string()),
        message: SarifMessage {
            text: if finding.description.is_empty() {
                finding.title.clone()
            } else {
                format!("{}\n\n{}", finding.title, finding.description)
            },
        },
        locations: vec![SarifLocation {
            physical_location: physical(&finding.location),
        }],
        partial_fingerprints: Some(partial),
        suppressions: if finding.status == FindingStatus::Suppressed {
            Some(vec![SarifSuppression {
                kind: "external".into(),
                status: Some("accepted".into()),
            }])
        } else {
            None
        },
        properties: Some(properties),
    }
}

fn physical(location: &quoll_core::Location) -> SarifPhysicalLocation {
    let region = location.span.map(|span| SarifRegion {
        start_line: span.start_line,
        end_line: span.end_line,
        start_column: span.start_column,
        end_column: span.end_column,
        snippet: location.snippet.as_ref().map(|text| SarifMessage {
            text: text.clone(),
        }),
    });
    SarifPhysicalLocation {
        artifact_location: SarifArtifactLocation {
            uri: location.path.to_string_lossy().replace('\\', "/"),
            uri_base_id: Some("%SRCROOT%".into()),
        },
        region,
    }
}

fn precision(confidence: f64) -> &'static str {
    // SARIF's precision vocabulary: very-high / high / medium / low.
    match confidence {
        c if c >= 0.9 => "very-high",
        c if c >= 0.7 => "high",
        c if c >= 0.4 => "medium",
        _ => "low",
    }
}

fn non_empty(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn path_uri(path: &std::path::Path) -> String {
    let text = path.to_string_lossy();
    // SARIF wants a URI. Absolute paths become file://; relative ones stay relative.
    if path.is_absolute() {
        let normalised = text.replace('\\', "/");
        if normalised.starts_with('/') {
            format!("file://{normalised}")
        } else {
            // Windows drive path
            format!("file:///{}", normalised.replace(':', "%3A"))
        }
    } else {
        text.replace('\\', "/")
    }
}

// --- SARIF document types -----------------------------------------------------------
// Hand-rolled rather than pulled from a crate: the surface Quoll needs is small, and a
// dependency would pin us to someone else's opinion about optional fields.

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    invocations: Vec<SarifInvocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_control_provenance: Option<Vec<SarifVersionControl>>,
    original_uri_base_ids: BTreeMap<String, SarifArtifactLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    information_uri: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    short_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_configuration: Option<SarifReportingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReportingConfig {
    level: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    partial_fingerprints: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressions: Option<Vec<SarifSuppression>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<SarifMessage>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_time_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_time_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    working_directory: Option<SarifArtifactLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifVersionControl {
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifSuppression {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_report;
    use crate::{Report, ScanInfo, Verifier};
    use quoll_core::{
        Confidence, Evidence, EvidenceSource, Finding, FindingStatus, Location, Profile, Severity,
    };

    #[test]
    fn emits_sarif_21_with_results_and_rules() {
        let report = sample_report();
        let text = render(&report).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["version"], "2.1.0");
        assert!(value["$schema"].as_str().unwrap().contains("sarif"));
        let run = &value["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "Quoll");
        assert_eq!(run["results"].as_array().unwrap().len(), 2);
        assert!(!run["tool"]["driver"]["rules"].as_array().unwrap().is_empty());

        let first = &run["results"][0];
        assert_eq!(first["level"], "error");
        assert_eq!(
            first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/api.rs"
        );
        assert_eq!(
            first["locations"][0]["physicalLocation"]["region"]["startLine"],
            2
        );
        assert!(!first["partialFingerprints"]["quollFingerprint"]
            .as_str()
            .unwrap()
            .is_empty());
        assert_eq!(first["properties"]["locationVerified"], true);
    }

    #[test]
    fn rule_ids_come_from_scanner_evidence() {
        let report = sample_report();
        let text = render(&report).unwrap();
        assert!(text.contains("semgrep/javascript.lang.security.audit.sqli"));
    }

    #[test]
    fn suppressed_findings_carry_a_suppression() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/api.rs"), "x\n").unwrap();
        let mut verifier = Verifier::new(dir.path());
        let finding = Finding::new(
            "noise",
            Severity::Low,
            Location::at("src/api.rs", 1),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: "r".into(),
                },
                "hit",
                Confidence::new(0.5),
            )],
        )
        .with_status(FindingStatus::Suppressed);
        let report = Report::build(
            ScanInfo::new("s", Profile::Fast, dir.path()),
            vec![finding],
            &mut verifier,
        );
        let text = render(&report).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value["runs"][0]["results"][0]["suppressions"][0]["kind"],
            "external"
        );
    }

    #[test]
    fn severity_maps_onto_sarif_levels() {
        assert_eq!(Severity::Info.sarif_level(), "note");
        assert_eq!(Severity::Medium.sarif_level(), "warning");
        assert_eq!(Severity::Critical.sarif_level(), "error");
    }
}
