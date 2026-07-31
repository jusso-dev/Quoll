use quoll_core::{Result, Severity};
use quoll_engine::{run_scan, ScanOptions};
use quoll_report::Format;

use crate::cli::CiArgs;
use crate::commands::Context;
use crate::exit::Exit;

pub async fn run(context: &Context, args: &CiArgs) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;

    let mut options = ScanOptions::from_config(&config)
        .with_ci(true)
        .with_base_ref(args.base_ref.clone().or(config.scan.base_ref.clone()));

    if let Some(profile) = args.profile {
        options = options.with_profile(profile.into());
    }
    // CI defaults to writing SARIF for code scanning integrations.
    if let Some(path) = &args.sarif {
        options = options.with_sarif_path(Some(path.clone()));
    }
    if options.formats.is_empty() {
        options = options.with_formats(vec![Format::Sarif, Format::Json]);
    } else if !options.formats.contains(&Format::Sarif) {
        let mut formats = options.formats.clone();
        formats.push(Format::Sarif);
        options = options.with_formats(formats);
    }

    // Fail-on stays at config/profile default; CI is non-interactive.
    let _fail: Severity = options.fail_on;

    printer.line(format!(
        "CI scan {} ({})",
        printer.dim(&options.config.root.display().to_string()),
        options.profile.as_str()
    ));

    let outcome = run_scan(options).await?;
    crate::commands::scan::print_outcome(context, &outcome);

    if outcome.scanner_failures {
        return Ok(Exit::ScannerFailed);
    }
    if outcome.breaches_gate() {
        return Ok(Exit::FindingsThreshold);
    }
    Ok(Exit::Ok)
}
