//! Tool catalogue and handlers.

use std::path::Path;

use quoll_core::config::Config;
use quoll_core::{Error, Result, Severity};
use quoll_engine::load_last_scan;
use quoll_graph::{Graph, GraphOps};
use quoll_policy::Registry as PolicyRegistry;
use serde_json::{json, Value};

/// One MCP tool descriptor.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

pub fn catalogue() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "quoll_findings_list",
            description: "List findings from the last Quoll scan, optionally filtered by severity.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "Minimum severity (info, low, medium, high, critical)"
                    },
                    "all": {
                        "type": "boolean",
                        "description": "Include suppressed findings"
                    }
                }
            }),
        },
        ToolSpec {
            name: "quoll_finding_show",
            description: "Show one finding by id or fingerprint.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" }
                },
                "required": ["id"]
            }),
        },
        ToolSpec {
            name: "quoll_report_summary",
            description: "One-line summary and severity counts from the last scan.",
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        ToolSpec {
            name: "quoll_graph_stats",
            description: "Node, edge and file counts from the code graph.",
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        ToolSpec {
            name: "quoll_policy_list",
            description: "Policy packs that apply to this repository.",
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        ToolSpec {
            name: "quoll_explain",
            description: "Explain a finding or hypothesis id from the last scan.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" }
                },
                "required": ["id"]
            }),
        },
    ]
}

pub fn call(root: &Path, name: &str, arguments: &Value) -> Result<Value> {
    let config = Config::discover(root)?;
    match name {
        "quoll_findings_list" => findings_list(&config, arguments),
        "quoll_finding_show" => finding_show(&config, arguments),
        "quoll_report_summary" => report_summary(&config),
        "quoll_graph_stats" => graph_stats(&config),
        "quoll_policy_list" => policy_list(&config),
        "quoll_explain" => explain(&config, arguments),
        other => Err(Error::other(format!("unknown tool `{other}`"))),
    }
}

fn findings_list(config: &Config, args: &Value) -> Result<Value> {
    let stored = load_last_scan(&config.state_dir())?;
    let min = args
        .get("severity")
        .and_then(|v| v.as_str())
        .map(|s| s.parse::<Severity>())
        .transpose()?;
    let all = args.get("all").and_then(|v| v.as_bool()).unwrap_or(false);

    let items: Vec<Value> = stored
        .findings
        .iter()
        .filter(|f| all || f.status.is_actionable())
        .filter(|f| min.map(|m| f.severity >= m).unwrap_or(true))
        .map(|f| {
            json!({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.as_str(),
                "status": f.status.as_str(),
                "location": f.location.display(),
                "confidence": f.confidence.value(),
            })
        })
        .collect();
    Ok(json!({ "findings": items, "count": items.len() }))
}

fn finding_show(config: &Config, args: &Value) -> Result<Value> {
    let id = args
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::other("missing id"))?;
    let stored = load_last_scan(&config.state_dir())?;
    let finding = stored
        .finding(id)
        .ok_or_else(|| Error::other(format!("no finding `{id}`")))?;
    Ok(serde_json::to_value(finding)?)
}

fn report_summary(config: &Config) -> Result<Value> {
    let stored = load_last_scan(&config.state_dir())?;
    Ok(json!({
        "summary": stored.report.summary(),
        "counts": stored.report.counts().iter().map(|(s, n)| (s.as_str(), n)).collect::<Vec<_>>(),
        "files_scanned": stored.report.scan.files_scanned,
        "verification": stored.report.verification,
        "coverage": stored.report.coverage,
    }))
}

fn graph_stats(config: &Config) -> Result<Value> {
    let path = config.graph_path();
    if !path.is_file() {
        return Err(Error::other(format!(
            "no graph at `{}`; run `quoll graph build`",
            path.display()
        )));
    }
    let graph = Graph::open(&path)?;
    let stats = graph.stats()?;
    Ok(json!({
        "files": stats.files,
        "symbols": stats.symbols,
        "nodes": stats.nodes,
        "edges": stats.edges,
    }))
}

fn policy_list(config: &Config) -> Result<Value> {
    let registry = PolicyRegistry::from_config(config)?;
    let packs: Vec<Value> = registry
        .packs()
        .iter()
        .map(|pack| {
            json!({
                "id": pack.id,
                "version": pack.version,
                "description": pack.description,
                "invariants": pack.invariants.len(),
            })
        })
        .collect();
    Ok(json!({ "packs": packs, "count": packs.len() }))
}

fn explain(config: &Config, args: &Value) -> Result<Value> {
    let id = args
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::other("missing id"))?;
    let stored = load_last_scan(&config.state_dir())?;
    if let Some(finding) = stored.finding(id) {
        return Ok(json!({
            "kind": "finding",
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.as_str(),
            "location": finding.location.display(),
            "evidence": finding.evidence.iter().map(|e| json!({
                "source": e.source.label(),
                "description": e.description,
                "confidence": e.confidence.value(),
            })).collect::<Vec<_>>(),
        }));
    }
    if let Some(hyp) = stored.hypothesis(id) {
        return Ok(json!({
            "kind": "hypothesis",
            "id": hyp.id,
            "class": hyp.class.as_str(),
            "title": hyp.title,
            "status": hyp.status.as_str(),
            "confidence": hyp.confidence.value(),
            "narrative": hyp.narrative,
            "location": hyp.location.display(),
            "evidence": hyp.evidence.iter().map(|e| json!({
                "source": e.source.label(),
                "description": e.description,
            })).collect::<Vec<_>>(),
        }));
    }
    Err(Error::other(format!(
        "no finding or hypothesis `{id}` in the last scan"
    )))
}
