use std::io::Write;

use quoll_core::{Error, Result};
use quoll_engine::load_last_scan;
use quoll_report::Format;

use crate::cli::ExportArgs;
use crate::commands::Context;
use crate::exit::Exit;

pub fn run(context: &Context, args: &ExportArgs) -> Result<Exit> {
    let config = context.config()?;
    let stored = load_last_scan(&config.state_dir())?;
    let format: Format = args.format.as_str().parse()?;
    let body = format.render(&stored.report)?;

    match &args.output {
        Some(path) => {
            format.write(&stored.report, path)?;
            context
                .printer
                .success(format!("wrote {}", path.display()));
        }
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(body.as_bytes()).map_err(Error::BareIo)?;
            if !body.ends_with('\n') {
                writeln!(out).map_err(Error::BareIo)?;
            }
        }
    }
    Ok(Exit::Ok)
}
