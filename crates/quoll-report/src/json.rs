//! Native JSON report.
//!
//! The document is the [`Report`](crate::Report) type itself, serialised with a stable
//! field order and pretty-printed so diffs and eyeballs both work. Consumers that want a
//! compact stream can re-serialise; the on-disk default optimises for humans reading CI
//! artifacts.

use quoll_core::Result;

use crate::Report;

/// Pretty-printed JSON of the full report document.
pub fn render(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Compact single-line JSON, for piping into another tool.
pub fn render_compact(report: &Report) -> Result<String> {
    Ok(serde_json::to_string(report)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_report;

    #[test]
    fn round_trips_through_serde() {
        let report = sample_report();
        let text = render(&report).unwrap();
        let back: Report = serde_json::from_str(&text).unwrap();
        assert_eq!(back.schema_version, report.schema_version);
        assert_eq!(back.findings.len(), report.findings.len());
        assert_eq!(back.findings[0].finding.title, report.findings[0].finding.title);
    }

    #[test]
    fn includes_verification_and_coverage() {
        let text = render(&sample_report()).unwrap();
        assert!(text.contains("\"schema_version\": 1"));
        assert!(text.contains("location_verified"));
        assert!(text.contains("verification"));
        assert!(text.contains("SQL injection"));
    }

    #[test]
    fn compact_is_one_line() {
        let text = render_compact(&sample_report()).unwrap();
        assert!(!text.contains('\n'));
        assert!(text.starts_with('{'));
    }
}
