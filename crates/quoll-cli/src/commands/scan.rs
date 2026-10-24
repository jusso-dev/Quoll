use quoll_core::{Error, Result, Severity};
use quoll_engine::{run_scan, ScanOptions};
use quoll_report::Format;

use crate::cli::ScanArgs;
use crate::commands::{ensure_writable, Context};
use crate::exit::Exit;

pub async fn run(context: &Context, args: &ScanArgs) -> Result<Exit> {
    let printer = &context.printer;
    let mut config = context.config()?;
    if let Some(target) = &args.target {
        // A typo must not become a clean scan of nothing.
        config.root = match context.canonical_root()?.join(target).canonicalize() {
            Ok(canon) if canon.is_dir() => canon,
            _ => {
                return Err(Error::config(format!(
                    "scan target `{}` is not a directory",
                    target.display()
                )))
            }
        };
    }
    ensure_writable(&config)?;

    let mut options = ScanOptions::from_config(&config).with_offline(args.offline).with_no_ai(args.no_ai);

    if let Some(profile) = args.profile {
        options = options.with_profile(profile.into());
    }
    if let Some(fail_on) = &args.fail_on {
        options = options.with_fail_on(fail_on.parse::<Severity>()?);
    }
    if !args.format.is_empty() {
        let formats: Result<Vec<Format>> = args
            .format
            .iter()
            .map(|s| s.parse::<Format>())
            .collect();
        options = options.with_formats(formats?);
    }

    printer.progress(format!(
        "Scanning {} ({})",
        printer.dim(&options.config.root.display().to_string()),
        options.profile.as_str()
    ));

    let outcome = run_scan(options).await?;
    print_outcome(context, &outcome);
    Ok(outcome_exit(outcome.breaches_gate(), outcome.scanner_failures))
}

/// Exit code for a finished scan.
///
/// Findings over the gate win over scanner failures: they are the actionable signal, and a
/// broken scanner must not hide a real result behind code 3.
pub(crate) fn outcome_exit(breaches_gate: bool, scanner_failures: bool) -> Exit {
    if breaches_gate {
        Exit::FindingsThreshold
    } else if scanner_failures {
        Exit::ScannerFailed
    } else {
        Exit::Ok
    }
}

pub(crate) fn print_outcome(context: &Context, outcome: &quoll_engine::ScanOutcome) {
    let printer = &context.printer;
    printer.heading("Findings");
    printer.field("summary", outcome.report.summary());
    printer.field("actionable", outcome.report.actionable().count().to_string());
    if outcome.report.suppressed_count() > 0 {
        printer.field("suppressed", outcome.report.suppressed_count().to_string());
    }
    printer.field(
        "locations",
        format!(
            "{} verified, {} flagged, {} dropped",
            outcome.report.verification.verified,
            outcome.report.verification.flagged,
            outcome.report.verification.dropped
        ),
    );
    if outcome.report.coverage.is_degraded() {
        printer.warn(format!(
            "degraded plugins: {}",
            outcome.report.coverage.plugins_degraded.join(", ")
        ));
    }

    for item in outcome.report.findings.iter().take(20) {
        let f = &item.finding;
        printer.line(format!(
            "  [{}] {}  {}",
            f.severity.as_str().to_ascii_uppercase(),
            f.title,
            printer.dim(&f.location.display())
        ));
    }
    if outcome.report.findings.len() > 20 {
        printer.line(format!(
            "  {}",
            printer.dim(&format!(
                "… and {} more",
                outcome.report.findings.len() - 20
            ))
        ));
    }

    if !outcome.written.is_empty() {
        printer.heading("Reports");
        for path in &outcome.written {
            printer.line(format!("  {}", path.display()));
        }
    }
    printer.line(format!(
        "  {}",
        printer.dim(&format!("state: {}", outcome.stored_path.display()))
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::output::Printer;
    use clap::Parser;

    fn context(root: &std::path::Path) -> Context {
        Context {
            printer: Printer::plain(),
            root: root.to_path_buf(),
            config_override: None,
            trust_repo_config: false,
        }
    }

    fn scan_args(target: &str) -> ScanArgs {
        match Cli::try_parse_from(["quoll", "scan", target]).unwrap().command {
            crate::cli::Command::Scan(args) => args,
            other => panic!("expected scan, got {}", other.name()),
        }
    }

    #[test]
    fn findings_over_the_gate_win_over_scanner_failures() {
        assert_eq!(outcome_exit(true, true), Exit::FindingsThreshold);
        assert_eq!(outcome_exit(false, true), Exit::ScannerFailed);
        assert_eq!(outcome_exit(false, false), Exit::Ok);
    }

    #[tokio::test]
    async fn a_missing_target_is_a_usage_error_not_a_clean_scan() {
        let dir = tempfile::tempdir().unwrap();
        let error = run(&context(dir.path()), &scan_args("no-such-dir"))
            .await
            .unwrap_err();
        assert_eq!(Exit::from_error(&error), Exit::InvalidConfig);
    }

    #[tokio::test]
    async fn a_missing_root_is_a_usage_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = run(&context(&dir.path().join("gone")), &scan_args("."))
            .await
            .unwrap_err();
        assert_eq!(Exit::from_error(&error), Exit::InvalidConfig);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_planted_state_symlink_stops_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".quoll")).unwrap();
        std::os::unix::fs::symlink(&victim, repo.join(".quoll/last-scan.json")).unwrap();

        let error = run(&context(&repo), &scan_args(".")).await.unwrap_err();
        assert_eq!(Exit::from_error(&error), Exit::InvalidConfig);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }
}

