use quoll_core::{Result, Severity};
use quoll_engine::{run_scan, ScanOptions};
use quoll_report::Format;

use crate::cli::ScanArgs;
use crate::commands::Context;
use crate::exit::Exit;

pub async fn run(context: &Context, args: &ScanArgs) -> Result<Exit> {
    let printer = &context.printer;
    let mut config = context.config()?;
    if let Some(target) = &args.target {
        config.root = context.root.join(target);
        if let Ok(canon) = config.root.canonicalize() {
            config.root = canon;
        }
    }

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

    printer.line(format!(
        "Scanning {} ({})",
        printer.dim(&options.config.root.display().to_string()),
        options.profile.as_str()
    ));

    let outcome = run_scan(options).await?;
    print_outcome(context, &outcome);

    if outcome.scanner_failures {
        return Ok(Exit::ScannerFailed);
    }
    if outcome.breaches_gate() {
        return Ok(Exit::FindingsThreshold);
    }
    Ok(Exit::Ok)
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


