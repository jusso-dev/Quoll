use serde::{Deserialize, Serialize};

use crate::{evidence, ids, Confidence, Evidence, Location, Severity};

/// Vulnerability classes Quoll reasons about at the hypothesis level.
///
/// These are deliberately coarse. A hypothesis class answers "what kind of attack is
/// this?", which is what decides the investigation prompt and the dynamic validator —
/// not the specific CWE, which comes from the underlying evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisClass {
    /// Object reference reachable without an ownership check.
    InsecureDirectObjectReference,
    /// Route reachable without authentication.
    MissingAuthentication,
    /// Authenticated, but no authorisation decision on the path.
    MissingAuthorisation,
    /// Data from one tenant reachable by another.
    TenantIsolationBreach,
    /// Untrusted input reaches a query without parameterisation.
    SqlInjection,
    /// Untrusted input reaches a shell or process boundary.
    CommandInjection,
    /// Untrusted input reaches an outbound request target.
    ServerSideRequestForgery,
    /// State-changing route without an anti-CSRF control.
    CrossSiteRequestForgery,
    /// Untrusted input reaches a rendering sink.
    CrossSiteScripting,
    /// Untrusted input reaches a deserialiser or template engine.
    UnsafeDeserialisation,
    /// Credential material committed to the repository.
    ExposedSecret,
    /// Dependency with a known advisory that is actually reachable.
    VulnerableDependency,
    /// Infrastructure or framework configured below its secure default.
    InsecureConfiguration,
    /// A control the framework policy pack requires is absent.
    MissingSecurityControl,
    /// Anything else, carrying its own label.
    Other(String),
}

impl HypothesisClass {
    pub fn as_str(&self) -> &str {
        match self {
            HypothesisClass::InsecureDirectObjectReference => "idor",
            HypothesisClass::MissingAuthentication => "missing_authentication",
            HypothesisClass::MissingAuthorisation => "missing_authorisation",
            HypothesisClass::TenantIsolationBreach => "tenant_isolation",
            HypothesisClass::SqlInjection => "sql_injection",
            HypothesisClass::CommandInjection => "command_injection",
            HypothesisClass::ServerSideRequestForgery => "ssrf",
            HypothesisClass::CrossSiteRequestForgery => "csrf",
            HypothesisClass::CrossSiteScripting => "xss",
            HypothesisClass::UnsafeDeserialisation => "unsafe_deserialisation",
            HypothesisClass::ExposedSecret => "exposed_secret",
            HypothesisClass::VulnerableDependency => "vulnerable_dependency",
            HypothesisClass::InsecureConfiguration => "insecure_configuration",
            HypothesisClass::MissingSecurityControl => "missing_security_control",
            HypothesisClass::Other(name) => name,
        }
    }

    pub fn title(&self) -> &str {
        match self {
            HypothesisClass::InsecureDirectObjectReference => "Insecure direct object reference",
            HypothesisClass::MissingAuthentication => "Missing authentication",
            HypothesisClass::MissingAuthorisation => "Missing authorisation",
            HypothesisClass::TenantIsolationBreach => "Tenant isolation breach",
            HypothesisClass::SqlInjection => "SQL injection",
            HypothesisClass::CommandInjection => "Command injection",
            HypothesisClass::ServerSideRequestForgery => "Server-side request forgery",
            HypothesisClass::CrossSiteRequestForgery => "Cross-site request forgery",
            HypothesisClass::CrossSiteScripting => "Cross-site scripting",
            HypothesisClass::UnsafeDeserialisation => "Unsafe deserialisation",
            HypothesisClass::ExposedSecret => "Exposed secret",
            HypothesisClass::VulnerableDependency => "Vulnerable dependency",
            HypothesisClass::InsecureConfiguration => "Insecure configuration",
            HypothesisClass::MissingSecurityControl => "Missing security control",
            HypothesisClass::Other(name) => name,
        }
    }

    pub fn cwe(&self) -> &[&str] {
        match self {
            HypothesisClass::InsecureDirectObjectReference => &["CWE-639"],
            HypothesisClass::MissingAuthentication => &["CWE-306"],
            HypothesisClass::MissingAuthorisation => &["CWE-862"],
            HypothesisClass::TenantIsolationBreach => &["CWE-639", "CWE-1230"],
            HypothesisClass::SqlInjection => &["CWE-89"],
            HypothesisClass::CommandInjection => &["CWE-78"],
            HypothesisClass::ServerSideRequestForgery => &["CWE-918"],
            HypothesisClass::CrossSiteRequestForgery => &["CWE-352"],
            HypothesisClass::CrossSiteScripting => &["CWE-79"],
            HypothesisClass::UnsafeDeserialisation => &["CWE-502"],
            HypothesisClass::ExposedSecret => &["CWE-798"],
            HypothesisClass::VulnerableDependency => &["CWE-1395"],
            HypothesisClass::InsecureConfiguration => &["CWE-16"],
            HypothesisClass::MissingSecurityControl => &["CWE-693"],
            HypothesisClass::Other(_) => &[],
        }
    }

    /// Severity to assume before evidence refines it.
    pub fn baseline_severity(&self) -> Severity {
        match self {
            HypothesisClass::SqlInjection
            | HypothesisClass::CommandInjection
            | HypothesisClass::UnsafeDeserialisation
            | HypothesisClass::ExposedSecret
            | HypothesisClass::TenantIsolationBreach => Severity::Critical,
            HypothesisClass::InsecureDirectObjectReference
            | HypothesisClass::MissingAuthentication
            | HypothesisClass::MissingAuthorisation
            | HypothesisClass::ServerSideRequestForgery => Severity::High,
            HypothesisClass::CrossSiteScripting
            | HypothesisClass::CrossSiteRequestForgery
            | HypothesisClass::VulnerableDependency => Severity::Medium,
            HypothesisClass::InsecureConfiguration
            | HypothesisClass::MissingSecurityControl
            | HypothesisClass::Other(_) => Severity::Low,
        }
    }

    /// Whether deterministic tooling already proves this class outright.
    ///
    /// Sending a leaked AWS key to a model to ask whether it is really a secret wastes
    /// tokens and adds uncertainty to something Gitleaks already proved.
    pub fn is_self_evident(&self) -> bool {
        matches!(
            self,
            HypothesisClass::ExposedSecret | HypothesisClass::VulnerableDependency
        )
    }
}

/// Where a hypothesis sits in the investigation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    /// Formed from correlated evidence, awaiting triage.
    Proposed,
    /// Below the investigation threshold; recorded but not pursued.
    BelowThreshold,
    /// Selected for AI investigation.
    Investigating,
    /// Investigation concluded the vulnerability is real.
    Confirmed,
    /// Investigation concluded it is not.
    Rejected,
    /// A dynamic validator reproduced it.
    Validated,
}

impl HypothesisStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HypothesisStatus::Proposed => "proposed",
            HypothesisStatus::BelowThreshold => "below_threshold",
            HypothesisStatus::Investigating => "investigating",
            HypothesisStatus::Confirmed => "confirmed",
            HypothesisStatus::Rejected => "rejected",
            HypothesisStatus::Validated => "validated",
        }
    }
}

/// A candidate attack, assembled from evidence that no single tool could produce alone.
///
/// This is the unit Quoll spends model tokens on, and only when its correlated
/// confidence clears the configured threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackHypothesis {
    pub id: String,
    pub class: HypothesisClass,
    pub title: String,
    /// What an attacker would do, in one sentence.
    pub narrative: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: HypothesisStatus,
    /// Primary code location; the entry point where an attacker would start.
    pub location: Location,
    /// Every fact for and against.
    pub evidence: Vec<Evidence>,
    /// Route or entry point, when the graph identified one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
    /// Code path from entry point to the dangerous operation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack_path: Vec<Location>,
    /// Questions only a model can answer, handed to the investigator verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_questions: Vec<String>,
}

impl AttackHypothesis {
    pub fn new(
        class: HypothesisClass,
        location: Location,
        evidence: Vec<Evidence>,
    ) -> AttackHypothesis {
        let confidence = evidence::correlate(&evidence);
        let title = class.title().to_string();
        let id = ids::stable_id(
            "HYP",
            &[class.as_str(), &location.path.to_string_lossy(), &title],
        );
        let severity = class.baseline_severity();
        AttackHypothesis {
            id,
            class,
            title,
            narrative: String::new(),
            severity,
            confidence,
            status: HypothesisStatus::Proposed,
            location,
            evidence,
            entry_point: None,
            attack_path: Vec::new(),
            open_questions: Vec::new(),
        }
    }

    pub fn with_narrative(mut self, narrative: impl Into<String>) -> Self {
        self.narrative = narrative.into();
        self
    }

    pub fn with_entry_point(mut self, entry_point: impl Into<String>) -> Self {
        self.entry_point = Some(entry_point.into());
        self
    }

    pub fn asking(mut self, question: impl Into<String>) -> Self {
        self.open_questions.push(question.into());
        self
    }

    pub fn add_evidence(&mut self, item: Evidence) {
        if !self.evidence.iter().any(|e| e.id == item.id) {
            self.evidence.push(item);
            self.confidence = evidence::correlate(&self.evidence);
        }
    }

    /// Whether this hypothesis earns model tokens.
    ///
    /// Two gates, both required: it must clear the confidence threshold, and it must not
    /// be something deterministic tooling already settled.
    pub fn warrants_investigation(&self, threshold: Confidence) -> bool {
        self.confidence >= threshold && !self.class.is_self_evident()
    }

    /// Convert a settled hypothesis into a reportable finding.
    pub fn into_finding(self) -> crate::Finding {
        let status = match self.status {
            HypothesisStatus::Validated => crate::FindingStatus::Validated,
            HypothesisStatus::Confirmed => crate::FindingStatus::Confirmed,
            HypothesisStatus::Rejected => crate::FindingStatus::Refuted,
            _ => crate::FindingStatus::Reported,
        };
        let hypothesis_id = self.id.clone();
        let description = self.narrative.clone();
        let cwe: Vec<String> = self.class.cwe().iter().map(|s| s.to_string()).collect();
        let mut finding = crate::Finding::new(
            self.title,
            self.severity,
            self.location,
            self.evidence,
        );
        finding.description = description;
        finding.status = status;
        finding.cwe = cwe;
        finding.hypothesis_id = Some(hypothesis_id);
        finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvidenceSource;

    fn strong_evidence() -> Vec<Evidence> {
        vec![
            Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: "missing-tenant-filter".into(),
                },
                "update without tenant predicate",
                Confidence::new(0.8),
            ),
            Evidence::supporting(
                EvidenceSource::Graph {
                    relation: "routes_to".into(),
                },
                "route reaches database update",
                Confidence::new(0.9),
            ),
        ]
    }

    #[test]
    fn correlated_evidence_beats_any_single_source() {
        let hyp = AttackHypothesis::new(
            HypothesisClass::InsecureDirectObjectReference,
            Location::at("app/api/orders/route.ts", 42),
            strong_evidence(),
        );
        assert!(hyp.confidence.value() > 0.8);
    }

    #[test]
    fn self_evident_classes_never_reach_the_model() {
        let hyp = AttackHypothesis::new(
            HypothesisClass::ExposedSecret,
            Location::at(".env", 3),
            strong_evidence(),
        );
        assert!(hyp.confidence.value() > 0.5);
        assert!(!hyp.warrants_investigation(Confidence::new(0.5)));
    }

    #[test]
    fn weak_hypotheses_stay_below_threshold() {
        let weak = vec![Evidence::supporting(
            EvidenceSource::Scanner {
                plugin: "semgrep".into(),
                rule: "maybe".into(),
            },
            "weak signal",
            Confidence::new(0.2),
        )];
        let hyp = AttackHypothesis::new(
            HypothesisClass::SqlInjection,
            Location::at("a.rs", 1),
            weak,
        );
        assert!(!hyp.warrants_investigation(Confidence::new(0.7)));
    }

    #[test]
    fn promotion_carries_evidence_and_cwe() {
        let mut hyp = AttackHypothesis::new(
            HypothesisClass::SqlInjection,
            Location::at("src/db.rs", 12),
            strong_evidence(),
        );
        hyp.status = HypothesisStatus::Confirmed;
        let finding = hyp.into_finding();
        assert_eq!(finding.status, crate::FindingStatus::Confirmed);
        assert_eq!(finding.cwe, vec!["CWE-89"]);
        assert_eq!(finding.evidence.len(), 2);
        assert!(finding.validate().is_ok());
    }

    #[test]
    fn ids_are_stable_for_the_same_class_and_place() {
        let a = AttackHypothesis::new(
            HypothesisClass::SqlInjection,
            Location::at("src/db.rs", 12),
            strong_evidence(),
        );
        let b = AttackHypothesis::new(
            HypothesisClass::SqlInjection,
            Location::at("src/db.rs", 99),
            vec![],
        );
        assert_eq!(a.id, b.id);
    }
}
