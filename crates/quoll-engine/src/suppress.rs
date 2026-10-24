//! Apply configured suppressions.

use globset::{GlobBuilder, GlobSetBuilder};
use quoll_core::config::{SuppressConfig, Suppression};
use quoll_core::{time_util, Finding, FindingStatus};

/// Mark matching findings as suppressed. Never deletes them.
pub fn apply_suppressions(findings: &mut [Finding], config: &SuppressConfig) {
    let now = time_util::now_rfc3339();
    for finding in findings.iter_mut() {
        if let Some(reason) = match_suppression(finding, config, &now) {
            finding.status = FindingStatus::Suppressed;
            if finding.description.is_empty() {
                finding.description = format!("Suppressed: {reason}");
            } else if !finding.description.contains("Suppressed:") {
                finding.description = format!("{}\n\nSuppressed: {reason}", finding.description);
            }
        }
    }
}

fn match_suppression(finding: &Finding, config: &SuppressConfig, now: &str) -> Option<String> {
    let path = finding.location.path.to_string_lossy();

    for pattern in &config.paths {
        if path_matches(&path, pattern) {
            return Some(format!("path `{pattern}`"));
        }
    }

    for rule in &config.rules {
        if rule_matches(finding, rule) {
            return Some(format!("rule `{rule}`"));
        }
    }

    for entry in &config.entries {
        if !entry_active(entry, now) {
            continue;
        }
        if let Some(entry_path) = &entry.path {
            if !path_matches(&path, entry_path) {
                continue;
            }
        }
        if id_matches(finding, &entry.id) {
            return Some(entry.reason.clone());
        }
    }
    None
}

fn entry_active(entry: &Suppression, now: &str) -> bool {
    match &entry.expires {
        None => true,
        // RFC3339 lexicographic compare is valid for identical formats.
        Some(expires) => expires.as_str() > now,
    }
}

fn rule_matches(finding: &Finding, rule: &str) -> bool {
    if finding.fingerprint == rule || finding.id == rule {
        return true;
    }
    for evidence in &finding.evidence {
        if let quoll_core::EvidenceSource::Scanner { plugin, rule: r } = &evidence.source {
            if rule == r || rule == format!("{plugin}:{r}") || rule == plugin {
                return true;
            }
        }
    }
    false
}

fn id_matches(finding: &Finding, id: &str) -> bool {
    rule_matches(finding, id)
        || finding.fingerprint == id
        || finding.id == id
        || finding.title == id
}

/// Glob match on whole path components (`*` never crosses `/`).
///
/// A pattern without `/` matches a file or directory of that name at any depth, the way
/// `.gitignore` does; a pattern with `/` is anchored at the repository root. Either way a
/// pattern naming a directory also covers everything beneath it.
fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern == "**" || pattern == "*" {
        return true;
    }
    let pattern = pattern.trim_start_matches("./").trim_start_matches('/');
    let pattern = pattern.trim_end_matches('/');
    let anchored = if pattern.contains('/') {
        pattern.to_string()
    } else {
        format!("**/{pattern}")
    };
    let mut builder = GlobSetBuilder::new();
    for glob in [anchored.clone(), format!("{anchored}/**")] {
        match GlobBuilder::new(&glob).literal_separator(true).build() {
            Ok(glob) => {
                builder.add(glob);
            }
            Err(err) => {
                tracing::warn!(pattern, error = %err, "invalid suppress path pattern");
                return path == pattern;
            }
        }
    }
    builder.build().is_ok_and(|set| set.is_match(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Confidence, Evidence, EvidenceSource, Location, Severity};

    fn finding() -> Finding {
        Finding::new(
            "x",
            Severity::High,
            Location::at("tests/fixture.rs", 1),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: "noisy".into(),
                },
                "hit",
                Confidence::new(0.7),
            )],
        )
    }

    #[test]
    fn path_suppression_marks_status() {
        let mut findings = vec![finding()];
        let config = SuppressConfig {
            paths: vec!["tests/**".into()],
            ..Default::default()
        };
        apply_suppressions(&mut findings, &config);
        assert_eq!(findings[0].status, FindingStatus::Suppressed);
    }

    #[test]
    fn path_patterns_match_whole_components() {
        // Each of these used to suppress by substring, prefix or suffix.
        assert!(!path_matches("src/latest_api.rs", "**/test/**"));
        assert!(!path_matches("testsuite/a.rs", "tests/**"));
        assert!(!path_matches("src/myconfig.rs", "config.rs"));

        assert!(path_matches("src/test/a.rs", "**/test/**"));
        assert!(path_matches("test/a.rs", "**/test/**"));
        assert!(path_matches("tests/unit/a.rs", "tests/**"));
        assert!(path_matches("src/config.rs", "config.rs"));
        assert!(path_matches("config.rs", "config.rs"));
        assert!(path_matches("a/fixtures/b.rs", "fixtures"));
        assert!(path_matches("web/app.test.js", "*.test.js"));
        assert!(!path_matches("src/a/b.rs", "src/*.rs"));
    }

    #[test]
    fn rule_suppression() {
        let mut findings = vec![finding()];
        let config = SuppressConfig {
            rules: vec!["semgrep:noisy".into()],
            ..Default::default()
        };
        apply_suppressions(&mut findings, &config);
        assert_eq!(findings[0].status, FindingStatus::Suppressed);
    }
}
