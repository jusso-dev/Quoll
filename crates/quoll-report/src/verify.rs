use std::collections::HashMap;
use std::path::{Path, PathBuf};

use quoll_core::{Finding, Location};
use serde::{Deserialize, Serialize};

/// Whether a reported location actually exists in the working tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Verification {
    /// The file exists and the line is inside it.
    Verified,
    /// No such file.
    PathMissing,
    /// The file exists but is shorter than the reported line.
    LineOutOfRange { line: u32, file_lines: u32 },
    /// The file could not be read — permissions, or it is not UTF-8.
    Unreadable { reason: String },
    /// The location names no file at all.
    NoPath,
}

impl Verification {
    pub fn is_verified(&self) -> bool {
        matches!(self, Verification::Verified)
    }

    pub fn describe(&self) -> String {
        match self {
            Verification::Verified => "location verified against the working tree".into(),
            Verification::PathMissing => "the file does not exist".into(),
            Verification::LineOutOfRange { line, file_lines } => {
                format!("line {line} is past the end of the file ({file_lines} lines)")
            }
            Verification::Unreadable { reason } => format!("the file could not be read: {reason}"),
            Verification::NoPath => "the finding names no file".into(),
        }
    }
}

/// What verification did across a whole report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub verified: usize,
    /// Kept, but flagged: deterministic evidence pointing at a location that has moved.
    pub flagged: usize,
    /// Removed entirely, because a model produced the location and it does not exist.
    pub dropped: usize,
}

impl VerificationSummary {
    pub fn total(&self) -> usize {
        self.verified + self.flagged + self.dropped
    }

    pub fn is_clean(&self) -> bool {
        self.flagged == 0 && self.dropped == 0
    }
}

/// Checks reported locations against the files on disk.
///
/// This is the last gate before a finding reaches a human. A report that cites
/// `src/api.rs:412` in a file with 80 lines is worse than no report: it destroys trust in
/// every other line of the document.
///
/// File contents are cached because findings cluster — twenty results in one file should
/// read it once.
pub struct Verifier {
    root: PathBuf,
    cache: HashMap<PathBuf, Option<Vec<String>>>,
    /// Populate `snippet` from disk for verified locations.
    fill_snippets: bool,
}

impl Verifier {
    pub fn new(root: impl Into<PathBuf>) -> Verifier {
        Verifier {
            root: root.into(),
            cache: HashMap::new(),
            fill_snippets: true,
        }
    }

    pub fn fill_snippets(mut self, fill: bool) -> Verifier {
        self.fill_snippets = fill;
        self
    }

    /// Check one location.
    pub fn verify(&mut self, location: &Location) -> Verification {
        if location.path.as_os_str().is_empty() {
            return Verification::NoPath;
        }
        // A path that escapes the repository is treated as missing rather than read. A
        // finding must never be the thing that makes Quoll open `/etc/shadow`.
        if !contained(&self.root, &location.path) {
            return Verification::PathMissing;
        }

        let lines = match self.lines(&location.path) {
            Some(lines) => lines,
            None => return Verification::PathMissing,
        };
        let file_lines = lines.len() as u32;

        match location.span {
            None => Verification::Verified,
            Some(span) => {
                let line = span.start_line;
                if line == 0 || line > file_lines {
                    Verification::LineOutOfRange { line, file_lines }
                } else {
                    Verification::Verified
                }
            }
        }
    }

    /// Verify a finding and, when it checks out, refresh its snippet from disk.
    ///
    /// Refreshing matters: a snippet recorded by a scanner minutes ago may already be
    /// stale, and a report should quote the file as it is now.
    pub fn verify_finding(&mut self, finding: &mut Finding) -> Verification {
        let verification = self.verify(&finding.location);
        if verification.is_verified() && self.fill_snippets {
            if let Some(snippet) = self.snippet(&finding.location) {
                finding.location.snippet = Some(snippet);
            }
        }
        verification
    }

    /// The source line a location points at, trimmed.
    pub fn snippet(&mut self, location: &Location) -> Option<String> {
        let span = location.span?;
        let lines = self.lines(&location.path)?;
        let index = span.start_line.checked_sub(1)? as usize;
        lines.get(index).map(|line| line.trim_end().to_string())
    }

    /// Several lines of context around a location, for the Markdown report.
    pub fn context(&mut self, location: &Location, radius: u32) -> Vec<(u32, String)> {
        let span = match location.span {
            Some(span) => span,
            None => return Vec::new(),
        };
        let lines = match self.lines(&location.path) {
            Some(lines) => lines,
            None => return Vec::new(),
        };
        let start = span.start_line.saturating_sub(radius).max(1);
        let end = (span.last_line() + radius).min(lines.len() as u32);

        (start..=end)
            .filter_map(|number| {
                lines
                    .get(number as usize - 1)
                    .map(|text| (number, text.trim_end().to_string()))
            })
            .collect()
    }

    fn lines(&mut self, relative: &Path) -> Option<&Vec<String>> {
        let key = relative.to_path_buf();
        if !self.cache.contains_key(&key) {
            let absolute = self.root.join(relative);
            let value = std::fs::read_to_string(&absolute)
                .ok()
                .map(|text| text.lines().map(str::to_string).collect());
            self.cache.insert(key.clone(), value);
        }
        self.cache.get(&key).and_then(|entry| entry.as_ref())
    }
}

/// Whether a repository-relative path stays inside the repository once `..` is resolved.
fn contained(root: &Path, relative: &Path) -> bool {
    use std::path::Component;

    if relative.is_absolute() {
        return relative.starts_with(root);
    }
    let mut depth = 0i32;
    for component in relative.components() {
        match component {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Confidence, Evidence, EvidenceSource, Severity, Span};

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/api.rs"),
            "fn one() {}\nfn two() {}\nfn three() {}\n",
        )
        .unwrap();
        dir
    }

    fn finding(location: Location, ai: bool) -> Finding {
        let source = if ai {
            EvidenceSource::Ai {
                provider: "openai".into(),
                model: "gpt".into(),
            }
        } else {
            EvidenceSource::Scanner {
                plugin: "semgrep".into(),
                rule: "r1".into(),
            }
        };
        Finding::new(
            "Title",
            Severity::High,
            location,
            vec![Evidence::supporting(source, "because", Confidence::new(0.8))],
        )
    }

    #[test]
    fn a_real_line_verifies() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let location = Location::at("src/api.rs", 2);
        assert_eq!(verifier.verify(&location), Verification::Verified);
    }

    #[test]
    fn a_line_past_the_end_of_the_file_is_caught() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let verification = verifier.verify(&Location::at("src/api.rs", 400));

        assert_eq!(
            verification,
            Verification::LineOutOfRange {
                line: 400,
                file_lines: 3
            }
        );
        assert!(verification.describe().contains("past the end"));
    }

    #[test]
    fn a_missing_file_is_caught() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        assert_eq!(
            verifier.verify(&Location::at("src/gone.rs", 1)),
            Verification::PathMissing
        );
    }

    #[test]
    fn a_location_with_no_line_verifies_on_the_file_alone() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        assert_eq!(
            verifier.verify(&Location::file("src/api.rs")),
            Verification::Verified
        );
    }

    #[test]
    fn a_traversing_path_is_never_opened() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        assert_eq!(
            verifier.verify(&Location::at("../../etc/passwd", 1)),
            Verification::PathMissing
        );
    }

    #[test]
    fn an_empty_path_is_reported_distinctly() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        assert_eq!(
            verifier.verify(&Location::file("")),
            Verification::NoPath
        );
    }

    #[test]
    fn verification_refreshes_the_snippet_from_disk() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let mut finding = finding(
            Location::at("src/api.rs", 2).with_snippet("stale text from an earlier run"),
            false,
        );

        assert!(verifier.verify_finding(&mut finding).is_verified());
        assert_eq!(finding.location.snippet.as_deref(), Some("fn two() {}"));
    }

    #[test]
    fn snippet_filling_can_be_switched_off() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path()).fill_snippets(false);
        let mut finding = finding(Location::at("src/api.rs", 2), false);

        verifier.verify_finding(&mut finding);
        assert!(finding.location.snippet.is_none());
    }

    #[test]
    fn context_returns_numbered_lines_around_the_hit() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let context = verifier.context(&Location::at("src/api.rs", 2), 1);

        assert_eq!(context.len(), 3);
        assert_eq!(context[0], (1, "fn one() {}".to_string()));
        assert_eq!(context[1], (2, "fn two() {}".to_string()));
    }

    #[test]
    fn context_clamps_at_the_file_boundaries() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let context = verifier.context(&Location::at("src/api.rs", 1), 10);
        assert_eq!(context.first().unwrap().0, 1);
        assert_eq!(context.last().unwrap().0, 3);
    }

    #[test]
    fn a_file_is_read_once_however_many_findings_cite_it() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        for line in 1..=3 {
            verifier.verify(&Location::at("src/api.rs", line));
        }
        assert_eq!(verifier.cache.len(), 1);
    }

    #[test]
    fn a_span_ending_past_the_file_still_verifies_on_its_start() {
        let dir = repo();
        let mut verifier = Verifier::new(dir.path());
        let location = Location::file("src/api.rs").with_span(Span::lines(2, 99));
        // The start line is what a reader clicks. An over-long end is a scanner quirk,
        // not a reason to discard an otherwise real finding.
        assert_eq!(verifier.verify(&location), Verification::Verified);
    }

    #[test]
    fn the_summary_counts_every_outcome() {
        let summary = VerificationSummary {
            verified: 3,
            flagged: 1,
            dropped: 2,
        };
        assert_eq!(summary.total(), 6);
        assert!(!summary.is_clean());
        assert!(VerificationSummary {
            verified: 5,
            ..Default::default()
        }
        .is_clean());
    }
}
