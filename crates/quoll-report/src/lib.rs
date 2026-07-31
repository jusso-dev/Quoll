//! JSON, SARIF and Markdown reporting for Quoll.
//!
//! A report is not a dump of scanner output. Every finding that reaches a human has
//! already survived correlation and, on the way out, source-location verification —
//! so a line cited as `src/api.rs:412` is a line that still exists.
//!
//! The asymmetric verification rule is deliberate. A deterministic finding whose file
//! has since moved is kept and flagged: the tool saw something real. A finding that
//! rests on model output and points at a line that does not exist is dropped entirely,
//! because inventing a location is exactly the failure mode Quoll exists to prevent.
//!
//! ```no_run
//! use quoll_report::{Format, Report, ScanInfo, Verifier};
//! use quoll_core::{Finding, Profile};
//!
//! # let findings: Vec<Finding> = vec![];
//! let mut verifier = Verifier::new("/repo");
//! let scan = ScanInfo::new("scan-1", Profile::Balanced, "/repo").completed(120);
//! let report = Report::build(scan, findings, &mut verifier);
//!
//! let json = Format::Json.render(&report)?;
//! let sarif = Format::Sarif.render(&report)?;
//! let md = Format::Markdown.render(&report)?;
//! # Ok::<(), quoll_core::Error>(())
//! ```

pub mod json;
pub mod markdown;
pub mod report;
pub mod sarif;
pub mod verify;

pub use report::{
    Coverage, Report, ReportedFinding, ScanInfo, ToolInfo, SCHEMA_VERSION,
};
pub use verify::{Verification, VerificationSummary, Verifier};

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use quoll_core::{Error, Result};

/// The three formats Quoll writes.
///
/// Kept as a closed enum rather than free-form strings so a typo in `quoll.toml` cannot
/// silently produce an empty report directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    Json,
    Sarif,
    Markdown,
}

impl Format {
    pub const ALL: [Format; 3] = [Format::Json, Format::Sarif, Format::Markdown];

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Sarif => "sarif",
            Format::Markdown => "markdown",
        }
    }

    /// File extension, without the leading dot.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Sarif => "sarif",
            Format::Markdown => "md",
        }
    }

    /// Default basename under the report output directory.
    pub fn default_filename(self) -> &'static str {
        match self {
            Format::Json => "report.json",
            Format::Sarif => "report.sarif",
            Format::Markdown => "report.md",
        }
    }

    /// Render the report to a string in this format.
    pub fn render(self, report: &Report) -> Result<String> {
        match self {
            Format::Json => json::render(report),
            Format::Sarif => sarif::render(report),
            Format::Markdown => Ok(markdown::render(report)),
        }
    }

    /// Write the report to a path, creating parent directories as needed.
    pub fn write(self, report: &Report, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| Error::io(parent, err))?;
            }
        }
        let body = self.render(report)?;
        std::fs::write(path, body).map_err(|err| Error::io(path, err))?;
        Ok(())
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            "markdown" | "md" => Ok(Format::Markdown),
            other => Err(Error::config(format!(
                "unknown report format `{other}` (expected markdown, json or sarif)"
            ))),
        }
    }
}

/// Write every requested format under `dir`, using each format's default filename.
///
/// Returns the paths written, in the same order as `formats`.
pub fn write_all(
    report: &Report,
    dir: impl AsRef<Path>,
    formats: &[Format],
) -> Result<Vec<std::path::PathBuf>> {
    let dir = dir.as_ref();
    std::fs::create_dir_all(dir).map_err(|err| Error::io(dir, err))?;
    let mut paths = Vec::with_capacity(formats.len());
    for format in formats {
        let path = dir.join(format.default_filename());
        format.write(report, &path)?;
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Confidence, Evidence, EvidenceSource, Finding, Location, Profile, Severity};

    pub(crate) fn scanner_finding(title: &str, severity: Severity, line: u32) -> Finding {
        Finding::new(
            title,
            severity,
            Location::at("src/api.rs", line),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: "javascript.lang.security.audit.sqli".into(),
                },
                "semgrep matched",
                Confidence::new(0.8),
            )],
        )
        .with_description("User input reaches a raw SQL query.")
    }

    pub(crate) fn sample_report() -> Report {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/api.rs"), "a\nb\nc\n").unwrap();

        let mut verifier = Verifier::new(dir.path());
        let scan = ScanInfo::new("scan-1", Profile::Balanced, dir.path())
            .with_commit(Some("abc123".into()))
            .completed(3);
        // Leak the tempdir for the life of the process; tests only need the report body.
        std::mem::forget(dir);
        Report::build(
            scan,
            vec![
                scanner_finding("SQL injection", Severity::Critical, 2),
                scanner_finding("Missing auth", Severity::High, 1),
            ],
            &mut verifier,
        )
    }

    #[test]
    fn formats_parse_from_config_strings() {
        assert_eq!("json".parse::<Format>().unwrap(), Format::Json);
        assert_eq!("SARIF".parse::<Format>().unwrap(), Format::Sarif);
        assert_eq!("md".parse::<Format>().unwrap(), Format::Markdown);
        assert!("pdf".parse::<Format>().is_err());
    }

    #[test]
    fn write_all_emits_every_requested_file() {
        let report = sample_report();
        let out = tempfile::tempdir().unwrap();
        let paths = write_all(
            &report,
            out.path(),
            &[Format::Json, Format::Sarif, Format::Markdown],
        )
        .unwrap();

        assert_eq!(paths.len(), 3);
        for path in &paths {
            assert!(path.exists(), "{path:?} missing");
            assert!(std::fs::metadata(path).unwrap().len() > 0);
        }
    }
}
