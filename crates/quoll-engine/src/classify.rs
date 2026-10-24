//! Map scanner output onto hypothesis classes.
//!
//! Classification is deliberately heuristic and conservative: a wrong class wastes model
//! tokens or mislabels a report, so unknown rules fall through to `Other` rather than a
//! confident wrong answer.

use quoll_core::{HypothesisClass, RawFinding};

/// Best-effort class for a raw scanner finding.
pub fn classify_raw(raw: &RawFinding) -> HypothesisClass {
    let haystack = format!("{} {} {}", raw.rule_id, raw.title, raw.description)
        .to_ascii_lowercase();
    // CWE ids compare as numbers: a substring test lets CWE-79 match CWE-798.
    let mut cwes = cwe_ids(&haystack);
    for entry in &raw.cwe {
        cwes.extend(cwe_ids(entry));
    }
    let hit = |needles: &[&str], ids: &[u32]| {
        matches_any(&haystack, needles) || ids.iter().any(|id| cwes.contains(id))
    };

    if hit(&["secret", "password", "api_key", "apikey", "token", "credential", "private key"], &[798, 259])
        || raw.plugin == "gitleaks"
    {
        return HypothesisClass::ExposedSecret;
    }
    if hit(&["cve-", "ghsa-", "advisory", "vulnerable depend", "osv", "cargo-audit"], &[1395])
        || raw.plugin == "osv-scanner"
        || raw.plugin == "cargo-audit"
    {
        return HypothesisClass::VulnerableDependency;
    }
    if hit(&["sql injection", "sqli"], &[89]) {
        return HypothesisClass::SqlInjection;
    }
    if hit(&["command injection", "os command", "shell injection"], &[78]) {
        return HypothesisClass::CommandInjection;
    }
    if hit(&["ssrf", "server-side request"], &[918]) {
        return HypothesisClass::ServerSideRequestForgery;
    }
    if hit(&["xss", "cross-site scripting"], &[79]) {
        return HypothesisClass::CrossSiteScripting;
    }
    if hit(&["csrf", "cross-site request forgery"], &[352]) {
        return HypothesisClass::CrossSiteRequestForgery;
    }
    if hit(&["idor", "insecure direct object"], &[639]) {
        return HypothesisClass::InsecureDirectObjectReference;
    }
    if hit(&["missing auth", "unauthenticated", "no authentication"], &[306]) {
        return HypothesisClass::MissingAuthentication;
    }
    if hit(&["authori", "authorization", "access control"], &[862, 863]) {
        return HypothesisClass::MissingAuthorisation;
    }
    if hit(&["tenant", "multi-tenant"], &[1230]) {
        return HypothesisClass::TenantIsolationBreach;
    }
    if hit(&["deserial", "pickle", "yaml.load"], &[502]) {
        return HypothesisClass::UnsafeDeserialisation;
    }
    if hit(&["misconfig", "insecure config", "dockerfile"], &[16]) || raw.plugin == "trivy" {
        return HypothesisClass::InsecureConfiguration;
    }

    HypothesisClass::Other(raw.rule_id.clone())
}

/// Every `CWE-<n>` id mentioned in `text`, case-insensitively, as integers.
pub fn cwe_ids(text: &str) -> Vec<u32> {
    let lower = text.to_ascii_lowercase();
    lower
        .match_indices("cwe-")
        .filter_map(|(at, tag)| {
            let digits: String = lower[at + tag.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().ok()
        })
        .collect()
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

    #[test]
    fn cwe_ids_compare_exactly() {
        assert_eq!(cwe_ids("CWE-79, cwe-798: x"), vec![79, 798]);
        let with_cwe = |cwe: &str| {
            RawFinding::new("semgrep", "r", "x", Severity::High, Location::at("a.js", 1))
                .with_cwe([cwe.to_string()])
        };
        assert_eq!(classify_raw(&with_cwe("CWE-79")), HypothesisClass::CrossSiteScripting);
        assert_eq!(classify_raw(&with_cwe("CWE-798")), HypothesisClass::ExposedSecret);
        assert_eq!(classify_raw(&with_cwe("CWE-789")), HypothesisClass::Other("r".into()));
        assert_eq!(classify_raw(&with_cwe("CWE-160")), HypothesisClass::Other("r".into()));
    }
}
