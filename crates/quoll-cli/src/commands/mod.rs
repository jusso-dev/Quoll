pub mod ci;
pub mod doctor;
pub mod explain;
pub mod export;
pub mod findings;
pub mod graph;
pub mod init;
pub mod investigate;
pub mod mcp;
pub mod plugins;
pub mod policy;
pub mod scan;
pub mod validate;

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
        Command::Scan(args) => scan::run(context, &args).await,
        Command::Ci(args) => ci::run(context, &args).await,
        Command::Explain(args) => explain::run(context, &args),
        Command::Investigate(args) => investigate::run(context, &args).await,
        Command::Validate(args) => validate::run(context, &args).await,
        Command::Findings(command) => findings::run(context, &command),
        Command::Export(args) => export::run(context, &args),
        Command::Mcp(args) => mcp::run(context, &args),
    }
}
