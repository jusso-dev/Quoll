//! Map scanner output onto hypothesis classes.
//!
//! Classification is deliberately heuristic and conservative: a wrong class wastes model
//! tokens or mislabels a report, so unknown rules fall through to `Other` rather than a
//! confident wrong answer.

use quoll_core::{HypothesisClass, RawFinding};

/// Best-effort class for a raw scanner finding.
pub fn classify_raw(raw: &RawFinding) -> HypothesisClass {
    let haystack = format!(
        "{} {} {} {}",
        raw.rule_id,
        raw.title,
        raw.description,
        raw.cwe.join(" ")
    )
    .to_ascii_lowercase();

    if matches_any(&haystack, &["secret", "password", "api_key", "apikey", "token", "credential", "private key"])
        || raw.plugin == "gitleaks"
    {
        return HypothesisClass::ExposedSecret;
    }
    if matches_any(&haystack, &["cve-", "ghsa-", "advisory", "vulnerable depend", "osv", "cargo-audit"])
        || raw.plugin == "osv-scanner"
        || raw.plugin == "cargo-audit"
    {
        return HypothesisClass::VulnerableDependency;
    }
    if matches_any(&haystack, &["sql injection", "sqli", "cwe-89"]) {
        return HypothesisClass::SqlInjection;
    }
    if matches_any(&haystack, &["command injection", "os command", "shell injection", "cwe-78"]) {
        return HypothesisClass::CommandInjection;
    }
    if matches_any(&haystack, &["ssrf", "server-side request", "cwe-918"]) {
        return HypothesisClass::ServerSideRequestForgery;
    }
    if matches_any(&haystack, &["xss", "cross-site scripting", "cwe-79"]) {
        return HypothesisClass::CrossSiteScripting;
    }
    if matches_any(&haystack, &["csrf", "cross-site request forgery", "cwe-352"]) {
        return HypothesisClass::CrossSiteRequestForgery;
    }
    if matches_any(&haystack, &["idor", "insecure direct object", "cwe-639"]) {
        return HypothesisClass::InsecureDirectObjectReference;
    }
    if matches_any(&haystack, &["missing auth", "unauthenticated", "cwe-306", "no authentication"]) {
        return HypothesisClass::MissingAuthentication;
    }
    if matches_any(&haystack, &["authori", "authorization", "cwe-862", "cwe-863", "access control"]) {
        return HypothesisClass::MissingAuthorisation;
    }
    if matches_any(&haystack, &["tenant", "multi-tenant", "cwe-1230"]) {
        return HypothesisClass::TenantIsolationBreach;
    }
    if matches_any(&haystack, &["deserial", "pickle", "yaml.load", "cwe-502"]) {
        return HypothesisClass::UnsafeDeserialisation;
    }
    if matches_any(&haystack, &["misconfig", "insecure config", "dockerfile", "cwe-16"])
        || raw.plugin == "trivy"
    {
        return HypothesisClass::InsecureConfiguration;
    }

    HypothesisClass::Other(raw.rule_id.clone())
}

fn matches_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Location, Severity};

    #[test]
    fn gitleaks_is_always_a_secret() {
        let raw = RawFinding::new(
            "gitleaks",
            "aws-access-key",
            "AWS key",
            Severity::Critical,
            Location::at(".env", 1),
        );
        assert_eq!(classify_raw(&raw), HypothesisClass::ExposedSecret);
    }

    #[test]
    fn sqli_rule_ids_classify() {
        let raw = RawFinding::new(
            "semgrep",
            "javascript.lang.security.audit.sqli",
            "SQL injection",
            Severity::High,
            Location::at("db.js", 3),
        );
        assert_eq!(classify_raw(&raw), HypothesisClass::SqlInjection);
    }
}
