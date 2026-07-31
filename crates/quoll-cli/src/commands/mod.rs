pub mod doctor;
pub mod graph;
pub mod init;
pub mod pending;
pub mod plugins;
pub mod policy;

use std::path::PathBuf;

use quoll_core::config::Config;
use quoll_core::{Error, Result};

use crate::cli::{Cli, Command, GlobalArgs};
use crate::exit::Exit;
use crate::output::Printer;

/// Everything a command needs that is not its own arguments.
pub struct Context {
    pub printer: Printer,
    pub root: PathBuf,
    pub config_override: Option<PathBuf>,
}

impl Context {
    pub fn new(global: &GlobalArgs, printer: Printer) -> Context {
        Context {
            printer,
            root: global.root(),
            config_override: global.config.clone(),
        }
    }

    /// Load configuration for this invocation.
    ///
    /// An explicit `--config` is loaded verbatim; otherwise Quoll walks up from the target
    /// looking for `quoll.toml` and falls back to defaults, because a repository with no
    /// configuration is a supported configuration.
    pub fn config(&self) -> Result<Config> {
        match &self.config_override {
            Some(path) => {
                if !path.is_file() {
                    return Err(Error::config(format!(
                        "no configuration file at `{}`",
                        path.display()
                    )));
                }
                Config::load(path)
            }
            None => Config::discover(&self.root),
        }
    }
}

/// Run the parsed command.
///
/// Returns the process exit code. Commands signal failure by returning an `Err`, which is
/// classified centrally in [`Exit::from_error`], so no command has to know its own code.
pub async fn dispatch(cli: Cli, context: &Context) -> Result<Exit> {
    match cli.command {
        Command::Init(args) => init::run(context, &args),
        Command::Graph(command) => graph::run(context, &command),
        Command::Doctor => doctor::run(context),
        Command::Plugins(command) => plugins::run(context, &command).await,
        Command::Policy(command) => policy::run(context, &command),

        // Implemented as far as the crate behind them exists. Each of these reports what
        // is missing rather than failing with a generic message, because "not built yet"
        // and "broken" must never look the same to a user.
        Command::Scan(_) => Ok(pending::report(
            context,
            "scan",
            "quoll-engine",
            "orchestration, scanner adapters and hypothesis correlation",
        )),
        Command::Ci(_) => Ok(pending::report(
            context,
            "ci",
            "quoll-engine",
            "CI provider detection, base-ref resolution and SARIF output",
        )),
        Command::Explain(_) => Ok(pending::report(
            context,
            "explain",
            "quoll-engine",
            "stored findings and hypotheses to explain",
        )),
        Command::Investigate(_) => Ok(pending::report(
            context,
            "investigate",
            "quoll-ai",
            "model providers, role routing and token budgets",
        )),
        Command::Validate(_) => Ok(pending::report(
            context,
            "validate",
            "quoll-engine",
            "hypotheses to validate; the Strix adapter and its target guards are ready",
        )),
        Command::Findings(_) => Ok(pending::report(
            context,
            "findings",
            "quoll-engine",
            "finding normalisation and storage",
        )),
        Command::Export(args) => Ok(pending::report(
            context,
            "export",
            "quoll-report",
            &format!(
                "the {} writer, and source-location verification for every reported line",
                args.format.as_str()
            ),
        )),
        Command::Mcp(_) => Ok(pending::report(
            context,
            "mcp",
            "quoll-mcp",
            "the MCP server and its read-oriented tools",
        )),
    }
}
