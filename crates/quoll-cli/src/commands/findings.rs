use quoll_core::{Result, Severity};
use quoll_engine::load_last_scan;

use crate::cli::{FindingsCommand, FindingsListArgs};
use crate::commands::Context;
use crate::exit::Exit;

pub fn run(context: &Context, command: &FindingsCommand) -> Result<Exit> {
    match command {
        FindingsCommand::List(args) => list(context, args),
        FindingsCommand::Show { id } => show(context, id),
    }
}

fn list(context: &Context, args: &FindingsListArgs) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;
    let stored = load_last_scan(&config.state_dir())?;

    let min = args
        .severity
        .as_deref()
        .map(|s| s.parse::<Severity>())
        .transpose()?;

    printer.heading("Findings");
    let mut count = 0;
    for finding in &stored.findings {
        if !args.all && !finding.status.is_actionable() {
            continue;
        }
        if let Some(min) = min {
            if finding.severity < min {
                continue;
            }
        }
        count += 1;
        printer.line(format!(
            "  [{}] {}  {}  {}",
            finding.severity.as_str().to_ascii_uppercase(),
            finding.id,
            finding.title,
            printer.dim(&finding.location.display())
        ));
    }
    if count == 0 {
        printer.line(format!("  {}", printer.dim("no findings")));
    }
    Ok(Exit::Ok)
}

fn show(context: &Context, id: &str) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;
    let stored = load_last_scan(&config.state_dir())?;
    let finding = stored.finding(id).ok_or_else(|| {
        quoll_core::Error::other(format!("no finding `{id}` in the last scan"))
    })?;

    printer.heading(&finding.title);
    printer.field("id", &finding.id);
    printer.field("severity", finding.severity.as_str());
    printer.field("status", finding.status.as_str());
    printer.field("confidence", format!("{}%", finding.confidence.percent()));
    printer.field("location", finding.location.display());
    if !finding.description.is_empty() {
        printer.line("");
        printer.line(format!("  {}", finding.description));
    }
    if !finding.evidence.is_empty() {
        printer.heading("Evidence");
        for e in &finding.evidence {
            printer.line(format!(
                "  - {} — {}",
                printer.dim(&e.source.label()),
                e.description
            ));
        }
    }
    Ok(Exit::Ok)
}
