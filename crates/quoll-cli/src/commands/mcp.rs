use quoll_core::Result;

use crate::cli::McpArgs;
use crate::commands::Context;
use crate::exit::Exit;

/// `--stdio` is accepted but not read: stdio is the only transport in this build.
pub fn run(context: &Context, _args: &McpArgs) -> Result<Exit> {
    let root = context.canonical_root()?;
    // Blocks until stdin closes.
    quoll_mcp::serve_stdio(root)?;
    Ok(Exit::Ok)
}
