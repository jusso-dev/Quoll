//! Compact read-oriented MCP tools for Quoll.
//!
//! The server speaks JSON-RPC 2.0 over stdio (the only transport this build supports).
//! Tools are deliberately read-only: an agent can list findings and inspect the graph, but
//! cannot start a scan or change configuration. Write operations belong to the CLI.

pub mod server;
pub mod tools;

pub use server::{serve_stdio, Server};
