use quoll_core::{time_util, Result};
use quoll_graph::{Graph, GraphOps, IndexReport, Indexer, Walker};

use crate::cli::{GraphBuildArgs, GraphCommand};
use crate::commands::Context;
use crate::exit::Exit;
use crate::output::pad;

pub fn run(context: &Context, command: &GraphCommand) -> Result<Exit> {
    match command {
        GraphCommand::Build(args) => build(context, args),
        GraphCommand::Update => index(context, false),
        GraphCommand::Stats => stats(context),
    }
}

/// Index from scratch.
///
/// Discarding first is the default: `build` is what a user reaches for after upgrading
/// Quoll, and stored nodes produced by a different parser version would mix with new ones
/// to produce a graph that matches neither.
fn build(context: &Context, args: &GraphBuildArgs) -> Result<Exit> {
    index(context, !args.incremental)
}

fn index(context: &Context, rebuild: bool) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;
    let path = config.graph_path();

    printer.line(format!(
        "{} {}",
        if rebuild { "Building" } else { "Updating" },
        printer.dim(&config.root.display().to_string())
    ));

    let mut graph = Graph::open(&path)?;
    let scan_id = format!("graph-{}", time_util::now_unix());
    let report = Indexer::new(Walker::from_config(&config))
        .rebuild(rebuild)
        .index(&mut graph, &scan_id)?;

    print_index_report(context, &report);
    printer.success(format!("graph at {}", path.display()));
    Ok(Exit::Ok)
}

fn print_index_report(context: &Context, report: &IndexReport) {
    let printer = &context.printer;

    printer.heading("Files");
    printer.field("discovered", report.files_seen.to_string());
    printer.field("parsed", report.files_parsed.to_string());
    printer.field("unchanged", report.files_unchanged.to_string());
    if report.files_removed > 0 {
        printer.field("removed", report.files_removed.to_string());
    }
    if report.files_unsupported > 0 {
        printer.field(
            "no grammar",
            format!("{} (recorded, not parsed)", report.files_unsupported),
        );
    }

    // Written, not total. An incremental run that parsed nothing still rewrites the
    // repository node, and labelling that "nodes" would read as a graph of size one.
    printer.heading("Written this run");
    printer.field("symbols", report.symbols_written.to_string());
    printer.field("nodes", report.nodes_written.to_string());
    printer.field("edges", report.edges_written.to_string());
    printer.field(
        "elapsed",
        time_util::humanise(std::time::Duration::from_millis(report.duration_ms as u64)),
    );

    // Everything below is a caveat. Reporting counts without them would imply a
    // completeness the index does not have.
    let discovery = &report.discovery;
    let skipped = discovery.skipped_large + discovery.skipped_binary + discovery.skipped_symlinks;
    if skipped > 0 || report.calls_unresolved > 0 || !report.files_with_syntax_errors.is_empty() {
        printer.heading("Not indexed");
    }
    if discovery.skipped_large > 0 {
        printer.field("over size limit", discovery.skipped_large.to_string());
    }
    if discovery.skipped_binary > 0 {
        printer.field("binary", discovery.skipped_binary.to_string());
    }
    if discovery.skipped_symlinks > 0 {
        printer.field("symlinks", discovery.skipped_symlinks.to_string());
    }
    if report.calls_unresolved > 0 {
        printer.field(
            "ambiguous calls",
            format!("{} (no edge written)", report.calls_unresolved),
        );
    }
    if !report.files_with_syntax_errors.is_empty() {
        printer.field(
            "syntax errors",
            format!(
                "{} file(s), partially indexed",
                report.files_with_syntax_errors.len()
            ),
        );
        for path in report.files_with_syntax_errors.iter().take(5) {
            printer.line(format!("    {}", printer.dim(&path.display().to_string())));
        }
        if report.files_with_syntax_errors.len() > 5 {
            printer.line(format!(
                "    {}",
                printer.dim(&format!(
                    "… and {} more",
                    report.files_with_syntax_errors.len() - 5
                ))
            ));
        }
    }
}

fn stats(context: &Context) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;
    let path = config.graph_path();

    if !path.exists() {
        printer.warn(format!("no graph at {}", path.display()));
        printer.line("Run `quoll graph build` to create one.");
        return Ok(Exit::Ok);
    }

    let graph = Graph::open(&path)?;
    let stats = graph.stats()?;

    printer.heading("Graph");
    printer.field("path", path.display().to_string());
    printer.field("schema", format!("v{}", quoll_graph::SCHEMA_VERSION));
    printer.field("files", stats.files.to_string());
    printer.field("symbols", stats.symbols.to_string());
    printer.field("nodes", stats.nodes.to_string());
    printer.field("edges", stats.edges.to_string());

    if !stats.nodes_by_kind.is_empty() {
        printer.heading("Nodes by kind");
        let width = stats.nodes_by_kind.keys().map(|k| k.len()).max().unwrap_or(0);
        for (kind, count) in &stats.nodes_by_kind {
            printer.line(format!("  {} {count}", pad(kind, width + 2)));
        }
    }
    if !stats.edges_by_kind.is_empty() {
        printer.heading("Edges by kind");
        let width = stats.edges_by_kind.keys().map(|k| k.len()).max().unwrap_or(0);
        for (kind, count) in &stats.edges_by_kind {
            printer.line(format!("  {} {count}", pad(kind, width + 2)));
        }
    }
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Printer;
    use std::path::Path;

    fn context(root: &Path) -> Context {
        Context {
            printer: Printer::plain(),
            root: root.to_path_buf(),
            config_override: None,
        }
    }

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/main.rs"),
            "fn main() {\n  helper();\n}\nfn helper() {}\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn build_creates_a_graph_and_indexes_it() {
        let dir = repo();
        let context = context(dir.path());
        let args = GraphBuildArgs { incremental: false };

        assert_eq!(build(&context, &args).unwrap(), Exit::Ok);

        let graph = Graph::open(dir.path().join(".quoll/graph.db")).unwrap();
        let stats = graph.stats().unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.nodes_by_kind.get("function"), Some(&2));
    }

    #[test]
    fn update_reuses_the_existing_graph() {
        let dir = repo();
        let context = context(dir.path());
        build(&context, &GraphBuildArgs { incremental: false }).unwrap();

        assert_eq!(index(&context, false).unwrap(), Exit::Ok);
        let graph = Graph::open(dir.path().join(".quoll/graph.db")).unwrap();
        assert_eq!(graph.stats().unwrap().files, 1, "no duplicate file rows");
    }

    #[test]
    fn stats_on_a_missing_graph_is_guidance_not_a_failure() {
        let dir = repo();
        assert_eq!(stats(&context(dir.path())).unwrap(), Exit::Ok);
    }

    #[test]
    fn stats_reads_a_built_graph() {
        let dir = repo();
        let context = context(dir.path());
        build(&context, &GraphBuildArgs { incremental: false }).unwrap();
        assert_eq!(stats(&context).unwrap(), Exit::Ok);
    }
}
