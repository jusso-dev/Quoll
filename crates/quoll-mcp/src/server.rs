//! JSON-RPC 2.0 MCP server over stdio.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use quoll_core::{Error, Result};
use serde_json::{json, Value};

use crate::tools;

/// MCP server bound to a repository root.
pub struct Server {
    root: PathBuf,
}

impl Server {
    pub fn new(root: impl Into<PathBuf>) -> Server {
        Server { root: root.into() }
    }

    pub fn handle(&self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("");

        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "quoll",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            })),
            "notifications/initialized" | "initialized" => {
                return json!({});
            }
            "ping" => Ok(json!({ })),
            "tools/list" => Ok(json!({
                "tools": tools::catalogue().iter().map(|t| json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                })).collect::<Vec<_>>()
            })),
            "tools/call" => {
                let params = request.get("params").cloned().unwrap_or(json!({}));
                let name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(json!({}));
                match tools::call(&self.root, name, &args) {
                    Ok(value) => Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&value).unwrap_or_default()
                        }],
                        "structuredContent": value,
                    })),
                    Err(err) => Err(err),
                }
            }
            other => Err(Error::other(format!("method not found: {other}"))),
        };

        match result {
            Ok(_value) if id.is_null() => json!({}),
            Ok(value) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": value,
            }),
            Err(err) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32000,
                    "message": err.to_string(),
                }
            }),
        }
    }
}

/// Serve until stdin closes. One JSON-RPC message per line (MCP stdio convention).
pub fn serve_stdio(root: impl Into<PathBuf>) -> Result<()> {
    let server = Server::new(root);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut lines = stdin.lock().lines();

    while let Some(line) = lines.next() {
        let line = line.map_err(Error::BareIo)?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Content-Length framed messages (full MCP) — extract body if present.
        let body = if line.to_ascii_lowercase().starts_with("content-length:") {
            let len: usize = line
                .split(':')
                .nth(1)
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            // skip blank line
            let _ = lines.next();
            let mut buf = String::new();
            for _ in 0..len {
                // read remaining as next lines until we have enough — simplified:
            }
            // Fallback: read next non-empty line as JSON body
            loop {
                match lines.next() {
                    Some(Ok(next)) if !next.trim().is_empty() => {
                        buf = next;
                        break;
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(Error::BareIo(e)),
                    None => break,
                }
            }
            buf
        } else {
            line.to_string()
        };

        if body.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(err) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("parse error: {err}") }
                });
                writeln!(stdout, "{err_resp}").ok();
                stdout.flush().ok();
                continue;
            }
        };

        let response = server.handle(&request);
        if response.as_object().map(|o| o.is_empty()).unwrap_or(false) {
            continue;
        }
        // Prefer line-delimited JSON; also acceptable to many MCP hosts.
        writeln!(stdout, "{response}").map_err(Error::BareIo)?;
        stdout.flush().map_err(Error::BareIo)?;
    }
    Ok(())
}
