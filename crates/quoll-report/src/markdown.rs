//! Human-readable Markdown report.
//!
//! Written for a pull-request comment or a ticket, not a dashboard. Worst findings first,
//! every citation a `path:line` a reader can click, evidence listed so a claim never
//! appears without its grounds.

use std::fmt::Write as _;

use crate::{Report, ReportedFinding};

/// Full Markdown document for the report.
pub fn render(report: &Report) -> String {
    let mut out = String::with_capacity(4 * 1024);
    header(&mut out, report);
    summary_table(&mut out, report);
    coverage_section(&mut out, report);

    if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "\n## Findings\n\nNo findings. {} file(s) scanned.\n",
            report.scan.files_scanned
        );
        return out;
    }

    let _ = writeln!(out, "\n## Findings\n");
    for (index, item) in report.findings.iter().enumerate() {
        finding_section(&mut out, index + 1, item);
    }
    out
}

fn header(out: &mut String, report: &Report) {
    let _ = writeln!(out, "# Quoll report\n");
    let _ = writeln!(out, "| | |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| **Tool** | {} {} |", report.tool.name, report.tool.version);
    let _ = writeln!(out, "| **Scan** | `{}` |", report.scan.id);
    let _ = writeln!(out, "| **Profile** | {} |", report.scan.profile);
    let _ = writeln!(out, "| **Root** | `{}` |", report.scan.root.display());
    if let Some(commit) = &report.scan.commit {
        let _ = writeln!(out, "| **Commit** | `{}` |", short_commit(commit));
    }
    let _ = writeln!(out, "| **Started** | {} |", report.scan.started_at);
    if let Some(done) = &report.scan.completed_at {
        let _ = writeln!(out, "| **Completed** | {done} |");
    }
    let _ = writeln!(out, "| **Files scanned** | {} |", report.scan.files_scanned);
    let _ = writeln!(out, "| **Summary** | {} |", report.summary());
}

fn summary_table(out: &mut String, report: &Report) {
    let counts = report.counts();
    if counts.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n## Severity\n");
    let _ = writeln!(out, "| Severity | Count |");
    let _ = writeln!(out, "|---|---:|");
    for severity in quoll_core::Severity::ALL.iter().rev() {
        if let Some(count) = counts.get(severity) {
            let _ = writeln!(out, "| {} | {count} |", severity.as_str());
        }
    }
}

fn coverage_section(out: &mut String, report: &Report) {
    let coverage = &report.coverage;
    let verification = &report.verification;

    let _ = writeln!(out, "\n## Coverage\n");
    let _ = writeln!(
        out,
        "- Plugins run: **{}** (skipped: {}, degraded: {})",
        coverage.plugins_run,
        coverage.plugins_skipped,
        coverage.plugins_degraded.len()
    );
    if !coverage.plugins_degraded.is_empty() {
        let _ = writeln!(
            out,
            "- Degraded plugins: {}",
            coverage
                .plugins_degraded
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !coverage.policy_packs_applied.is_empty() {
        let _ = writeln!(
            out,
            "- Policy packs: {} ({} node(s) evaluated)",
            coverage
                .policy_packs_applied
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(", "),
            coverage.policy_nodes_evaluated
        );
    }
    let _ = writeln!(
        out,
        "- AI used: **{}**",
        if coverage.ai_used { "yes" } else { "no" }
    );
    let _ = writeln!(
        out,
        "- Locations verified: **{}** (flagged: {}, dropped: {})",
        verification.verified, verification.flagged, verification.dropped
    );

    if coverage.is_degraded() {
        let _ = writeln!(
            out,
            "\n> **Degraded scan.** One or more plugins failed, timed out or were unavailable. A clean finding list from this run is not a clean bill of health.\n"
        );
    }
}

fn finding_section(out: &mut String, n: usize, item: &ReportedFinding) {
    let f = &item.finding;
    let _ = writeln!(
        out,
        "### {}. [{}] {}\n",
        n,
        f.severity.as_str().to_ascii_uppercase(),
        f.title
    );
    let _ = writeln!(out, "| | |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| **Id** | `{}` |", f.id);
    let _ = writeln!(out, "| **Location** | `{}` |", f.location.display());
    let _ = writeln!(
        out,
        "| **Confidence** | {}% ({}) |",
        f.confidence.percent(),
        f.confidence.label()
    );
    let _ = writeln!(out, "| **Status** | {} |", f.status.as_str());
    if !f.contributing_plugins.is_empty() {
        let _ = writeln!(
            out,
            "| **Plugins** | {} |",
            f.contributing_plugins
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !f.cwe.is_empty() {
        let _ = writeln!(out, "| **CWE** | {} |", f.cwe.join(", "));
    }
    if !f.cve.is_empty() {
        let _ = writeln!(out, "| **CVE** | {} |", f.cve.join(", "));
    }
    let _ = writeln!(
        out,
        "| **Location verified** | {} |",
        if item.location_verified {
            "yes"
        } else {
            "no"
        }
    );
    if let Some(note) = &item.verification_note {
        let _ = writeln!(out, "| **Verification** | {note} |");
    }
    if f.used_ai() {
        let _ = writeln!(out, "| **AI** | contributed (with deterministic evidence) |");
    }

    if !f.description.is_empty() {
        let _ = writeln!(out, "\n{}\n", f.description.trim());
    }

    if let Some(snippet) = &f.location.snippet {
        let _ = writeln!(out, "```");
        let _ = writeln!(out, "{snippet}");
        let _ = writeln!(out, "```\n");
    }

    if !f.evidence.is_empty() {
        let _ = writeln!(out, "**Evidence**\n");
        for evidence in &f.evidence {
            let kind = match evidence.kind {
                quoll_core::EvidenceKind::Supporting => "supporting",
                quoll_core::EvidenceKind::Refuting => "refuting",
                quoll_core::EvidenceKind::Contextual => "context",
            };
            let _ = writeln!(
                out,
                "- ({kind}, {}%) `{}` — {}",
                evidence.confidence.percent(),
                evidence.source.label(),
                evidence.description
            );
        }
        let _ = writeln!(out);
    }

    if let Some(remediation) = &f.remediation {
        let _ = writeln!(out, "**Remediation**\n");
        if !remediation.summary.is_empty() {
            let _ = writeln!(out, "{}\n", remediation.summary.trim());
        }
        for (i, step) in remediation.steps.iter().enumerate() {
            let _ = writeln!(out, "{}. {step}", i + 1);
        }
        if !remediation.steps.is_empty() {
            let _ = writeln!(out);
        }
        for fix in &remediation.fixes {
            let _ = writeln!(
                out,
                "- Fix at `{}`: {}",
                fix.location.display(),
                fix.description
            );
            if let Some(patch) = &fix.patch {
                let _ = writeln!(out, "\n```diff\n{}\n```\n", patch.trim_end());
            }
        }
    }

    if !f.references.is_empty() {
        let _ = writeln!(out, "**References**\n");
        for reference in &f.references {
            let _ = writeln!(out, "- {reference}");
        }
        let _ = writeln!(out);
    }
}

fn short_commit(commit: &str) -> &str {
    if commit.len() > 12 {
        &commit[..12]
    } else {
        commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample_report;
    use crate::{Report, ScanInfo};
    use quoll_core::Profile;

    #[test]
    fn empty_report_says_so() {
        let report = Report::unverified(
            ScanInfo::new("s", Profile::Fast, "/repo").completed(10),
            vec![],
        );
        let md = render(&report);
        assert!(md.contains("No findings"));
        assert!(md.contains("10 file(s)"));
    }

    #[test]
    fn findings_render_worst_first_with_locations() {
        let md = render(&sample_report());
        assert!(md.contains("# Quoll report"));
        assert!(md.contains("[CRITICAL] SQL injection"));
        assert!(md.contains("[HIGH] Missing auth"));
        assert!(md.contains("`src/api.rs:2`"));
        assert!(md.contains("**Evidence**"));
        assert!(md.contains("semgrep:"));
        // Critical section must appear before High.
        let critical = md.find("[CRITICAL]").unwrap();
        let high = md.find("[HIGH]").unwrap();
        assert!(critical < high);
    }

    #[test]
    fn degraded_coverage_warns_the_reader() {
        use quoll_plugin::{PluginRun, RunStatus};
        use std::time::Duration;

        let report = Report::unverified(ScanInfo::new("s", Profile::Fast, "/repo"), vec![])
            .with_plugin_runs(vec![PluginRun {
                plugin_id: "semgrep".into(),
                status: RunStatus::Failed {
                    error: "boom".into(),
                },
                duration: Duration::from_secs(1),
                findings_count: 0,
                diagnostics: vec![],
                tool_version: None,
            }]);
        let md = render(&report);
        assert!(md.contains("Degraded scan"));
        assert!(md.contains("`semgrep`"));
    }
}
