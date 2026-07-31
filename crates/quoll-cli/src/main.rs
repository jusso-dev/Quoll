//! The `quoll` binary.
//!
//! This crate holds no business logic. It parses arguments, sets up logging and output,
//! calls a command, and maps the result to an exit code. Anything that decides what a scan
//! means lives in a library crate, so that the same behaviour is reachable from the MCP
//! server and from tests without a subprocess.

mod cli;
mod commands;
mod exit;
mod output;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::Cli;
use crate::commands::Context;
use crate::exit::Exit;
use crate::output::Printer;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let printer = Printer::new(cli.global.no_color, cli.global.quiet);
    init_logging(&cli);

    let context = Context::new(&cli.global, printer);
    let command = cli.command.name();

    match commands::dispatch(cli, &context).await {
        Ok(exit) => exit.into(),
        Err(error) => {
            tracing::debug!(command, ?error, "command failed");
            context.printer.error(&error);
            Exit::from_error(&error).into()
        }
    }
}

/// Configure `tracing`.
///
/// `RUST_LOG` wins when set, so that a user debugging a scan is not fighting the
/// verbosity flags. Logs go to stderr; stdout is reserved for results a pipeline may
/// consume.
fn init_logging(cli: &Cli) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(cli.global.log_filter()));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();
}
