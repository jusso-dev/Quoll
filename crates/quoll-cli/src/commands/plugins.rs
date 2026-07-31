use quoll_core::Result;
use quoll_plugin::Registry;

use crate::cli::PluginsCommand;
use crate::commands::Context;
use crate::exit::Exit;
use crate::output::pad;

pub async fn run(context: &Context, command: &PluginsCommand) -> Result<Exit> {
    match command {
        PluginsCommand::List => list(context),
        PluginsCommand::Doctor => doctor(context).await,
    }
}

/// The plugins available to this build.
///
/// Fixed at compile time rather than discovered at runtime: Quoll does not load dynamic
/// libraries into its own process, so first-party adapters are linked in and external
/// plugins speak JSON over stdio instead.
fn registry() -> Registry {
    quoll_plugins::registry()
}

fn list(context: &Context) -> Result<Exit> {
    let printer = &context.printer;
    let registry = registry();

    if registry.is_empty() {
        printer.warn("no scanner plugins are registered in this build");
        return Ok(Exit::Ok);
    }

    let width = registry.ids().iter().map(|id| id.len()).max().unwrap_or(0);
    printer.heading("Plugins");
    for plugin in registry.all() {
        let manifest = plugin.manifest();
        let capabilities: Vec<&str> = manifest
            .capabilities
            .iter()
            .map(|capability| capability.as_str())
            .collect();
        printer.line(format!(
            "  {} {:<28} {}",
            pad(&manifest.id, width + 2),
            manifest.name,
            printer.dim(&format!(
                "{} · {}",
                manifest.cost.as_str(),
                capabilities.join(", ")
            ))
        ));
    }
    printer.line("");
    printer.line(format!(
        "  {}",
        printer.dim("`quoll plugins doctor` checks which of their binaries are installed")
    ));
    Ok(Exit::Ok)
}

/// Check whether each registered plugin can actually run.
///
/// Availability requires filesystem access and process spawning, which is why it is not
/// part of the registry's scheduling decision and why this is async.
async fn doctor(context: &Context) -> Result<Exit> {
    let printer = &context.printer;
    let registry = registry();

    if registry.is_empty() {
        printer.warn("no scanner plugins are registered in this build");
        printer.line("  Run `quoll doctor` to check the environment instead.");
        return Ok(Exit::Ok);
    }

    printer.heading("Plugin availability");
    let mut unavailable = 0;
    for plugin in registry.all() {
        let id = plugin.id();
        match plugin.availability().await {
            quoll_plugin::Availability::Ready { tool_version } => {
                let version = tool_version.unwrap_or_else(|| "installed".to_string());
                printer.line(format!(
                    "  {} {id}  {}",
                    printer.green("✓"),
                    printer.dim(&version)
                ));
            }
            quoll_plugin::Availability::Missing { reason, hint } => {
                unavailable += 1;
                printer.line(format!("  {} {id}  {}", printer.red("✗"), printer.dim(&reason)));
                if let Some(hint) = hint {
                    printer.line(format!("      {}", printer.dim(&hint)));
                }
            }
        }
    }

    if unavailable > 0 {
        // A missing scanner is a degraded scan, not a broken installation: Quoll reports
        // what it could run and says what it skipped.
        printer.warn(format!("{unavailable} plugin(s) unavailable"));
    }
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Printer;

    fn context() -> Context {
        Context {
            printer: Printer::plain(),
            root: std::path::PathBuf::from("."),
            config_override: None,
        }
    }

    #[test]
    fn listing_shows_the_first_party_adapters() {
        assert!(!registry().is_empty());
        assert_eq!(list(&context()).unwrap(), Exit::Ok);
    }

    #[tokio::test]
    async fn doctor_reports_availability_without_failing_when_tools_are_missing() {
        // A missing scanner is a degraded scan, not a broken installation, so the command
        // still succeeds on a machine with none of them installed.
        assert_eq!(doctor(&context()).await.unwrap(), Exit::Ok);
    }
}
