use quoll_core::Result;

use crate::cli::McpArgs;
use crate::commands::Context;
use crate::exit::Exit;

pub fn run(context: &Context, _args: &McpArgs) -> Result<Exit> {
    let root = context
        .root
        .canonicalize()
        .unwrap_or_else(|_| context.root.clone());
    // Blocks until stdin closes.
    quoll_mcp::serve_stdio(root)?;
    Ok(Exit::Ok)
}
