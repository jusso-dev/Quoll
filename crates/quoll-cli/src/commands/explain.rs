use quoll_core::Result;
use quoll_engine::load_last_scan;

use crate::cli::ExplainArgs;
use crate::commands::Context;
use crate::exit::Exit;

pub fn run(context: &Context, args: &ExplainArgs) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;
    let stored = load_last_scan(&config.state_dir())?;

    if let Some(finding) = stored.finding(&args.id) {
        printer.heading(&finding.title);
        printer.field("kind", "finding");
        printer.field("id", &finding.id);
        printer.field("severity", finding.severity.as_str());
        printer.field("status", finding.status.as_str());
        printer.field("location", finding.location.display());
        if !finding.description.is_empty() {
            printer.line("");
            for line in finding.description.lines() {
                printer.line(format!("  {line}"));
            }
        }
        printer.heading("Evidence");
        for e in &finding.evidence {
            printer.line(format!(
                "  - [{}] {} — {}",
                if e.is_deterministic() { "det" } else { "ai" },
                e.source.label(),
                e.description
            ));
        }
        return Ok(Exit::Ok);
    }

    if let Some(hyp) = stored.hypothesis(&args.id) {
        printer.heading(&hyp.title);
        printer.field("kind", "hypothesis");
        printer.field("id", &hyp.id);
        printer.field("class", hyp.class.as_str());
        printer.field("status", hyp.status.as_str());
        printer.field("confidence", format!("{:.2}", hyp.confidence.value()));
        printer.field("location", hyp.location.display());
        if !hyp.narrative.is_empty() {
            printer.line("");
            printer.line(format!("  {}", hyp.narrative));
        }
        printer.heading("Evidence");
        for e in &hyp.evidence {
            printer.line(format!("  - {} — {}", e.source.label(), e.description));
        }
        return Ok(Exit::Ok);
    }

    Err(quoll_core::Error::other(format!(
        "no finding or hypothesis `{}` in the last scan",
        args.id
    )))
}
