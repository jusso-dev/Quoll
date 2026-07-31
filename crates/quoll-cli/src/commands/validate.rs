use quoll_core::{Error, Profile, Result};
use quoll_engine::load_last_scan;
use quoll_plugin::ScanContext;
use quoll_plugins::{check_target, TargetPolicy};

use crate::cli::ValidateArgs;
use crate::commands::Context;
use crate::exit::Exit;

pub async fn run(context: &Context, args: &ValidateArgs) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;

    let hosts = config
        .plugins
        .settings_for("strix")
        .map(|s| s.config.clone())
        .unwrap_or_default();
    let policy = TargetPolicy::new(hosts);

    if let Err(refusal) = check_target(Some(&args.target_url), &policy) {
        return Err(Error::DynamicValidation(refusal.to_string()));
    }

    if let Some(id) = &args.id {
        if let Ok(stored) = load_last_scan(&config.state_dir()) {
            if stored.hypothesis(id).is_none() && stored.finding(id).is_none() {
                return Err(Error::other(format!(
                    "no hypothesis or finding `{id}` in the last scan"
                )));
            }
        }
    }

    let registry = quoll_plugins::registry();
    let strix = registry
        .get("strix")
        .ok_or_else(|| Error::other("strix plugin is not registered"))?;

    let availability = strix.availability().await;
    if !availability.is_ready() {
        printer.warn("strix is not installed; target gate passed but validation was not run");
        printer.line(format!(
            "  {}",
            printer.dim("install strix and re-run `quoll validate --target-url …`")
        ));
        return Ok(Exit::Ok);
    }

    let ctx = ScanContext::new(&config.root, Profile::Release)
        .with_target_url(Some(args.target_url.clone()));

    printer.line(format!(
        "Validating against {} …",
        printer.dim(&args.target_url)
    ));
    match strix.run(&ctx).await {
        Ok(output) => {
            printer.success(format!(
                "strix finished with {} finding(s)",
                output.findings.len()
            ));
            for raw in output.findings.iter().take(10) {
                printer.line(format!(
                    "  [{}] {}  {}",
                    raw.severity.as_str().to_ascii_uppercase(),
                    raw.title,
                    printer.dim(&raw.location.display())
                ));
            }
            Ok(Exit::Ok)
        }
        Err(err) => Err(err),
    }
}
