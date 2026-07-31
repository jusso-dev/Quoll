//! Incremental indexing: walk, hash, parse only what changed, write one transaction.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use quoll_core::{time_util, Result};

use crate::model::{Edge, EdgeKind, FileRecord, Node, NodeId, NodeKind, Symbol};
use crate::parse::{Import, Parsers, Reference};
use crate::store::{FileState, Graph, GraphOps};
use crate::walk::{Discovery, Walker};

/// What an indexing run did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IndexReport {
    pub scan_id: String,
    pub files_seen: usize,
    /// Files parsed this run.
    pub files_parsed: usize,
    /// Files whose hash matched the stored one, so parsing was skipped entirely.
    pub files_unchanged: usize,
    /// Files removed from the graph because they are gone from the tree.
    pub files_removed: usize,
    /// Files with no tree-sitter grammar. Recorded, not parsed.
    pub files_unsupported: usize,
    pub symbols_written: usize,
    pub nodes_written: usize,
    pub edges_written: usize,
    /// Call sites whose target could not be identified unambiguously.
    pub calls_unresolved: usize,
    /// Files tree-sitter reported syntax errors in.
    pub files_with_syntax_errors: Vec<PathBuf>,
    pub discovery: Discovery,
    pub duration_ms: u128,
}

impl IndexReport {
    /// One line for `quoll graph update`.
    pub fn summary(&self) -> String {
        format!(
            "{} files ({} parsed, {} unchanged), {} nodes, {} edges",
            self.files_seen,
            self.files_parsed,
            self.files_unchanged,
            self.nodes_written,
            self.edges_written
        )
    }
}

/// Builds and updates the code graph.
pub struct Indexer {
    walker: Walker,
    parsers: Parsers,
    rebuild: bool,
}

impl Indexer {
    pub fn new(walker: Walker) -> Indexer {
        Indexer {
            walker,
            parsers: Parsers::new(),
            rebuild: false,
        }
    }

    /// Discard existing structure before indexing.
    ///
    /// Required after a parser change: stored nodes were produced by different extraction
    /// rules, and mixing the two silently produces a graph that matches neither.
    pub fn rebuild(mut self, rebuild: bool) -> Indexer {
        self.rebuild = rebuild;
        self
    }

    /// Index the repository into `graph`.
    ///
    /// The entire run is one transaction. A partially indexed graph is worse than an
    /// unchanged one: policy evaluation would see a route whose guard has not been written
    /// yet and report a missing control that exists.
    pub fn index(&mut self, graph: &mut Graph, scan_id: &str) -> Result<IndexReport> {
        let started = std::time::Instant::now();
        let discovery = self.walker.discover()?;

        if self.rebuild {
            graph.clear_structure()?;
        }

        let mut report = IndexReport {
            scan_id: scan_id.to_string(),
            files_seen: discovery.files.len(),
            ..Default::default()
        };
        let known: HashSet<PathBuf> = graph
            .all_files()?
            .into_iter()
            .map(|record| record.path)
            .collect();
        let present: HashSet<PathBuf> = discovery.files.iter().cloned().collect();

        let tx = graph.transaction()?;
        tx.begin_scan(scan_id, None, "index")?;

        // Files that vanished from the tree take their nodes and edges with them.
        for stale in known.difference(&present) {
            tx.forget_file(stale)?;
            report.files_removed += 1;
        }

        let repository = Node::new(
            NodeKind::Repository,
            &self.walker.root().to_string_lossy(),
            self.walker
                .root()
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "repository".to_string()),
        );
        tx.upsert_node(&repository)?;
        report.nodes_written += 1;

        // Symbol node ids by qualified name, per file, so call sites resolve to the node
        // that was just written rather than to a second lookup by name.
        let mut pending: Vec<(PathBuf, Reference)> = Vec::new();

        for relative in &discovery.files {
            let source = match self.walker.read(relative)? {
                Some(source) => source,
                // Disappeared between discovery and read, or is not UTF-8.
                None => continue,
            };
            tx.record_file_hash(scan_id, relative, &source.hash)?;

            if tx.file_state(relative, &source.hash)? == FileState::Unchanged {
                report.files_unchanged += 1;
                continue;
            }

            // Reparsing means every node derived from the old contents is now wrong.
            tx.forget_file(relative)?;
            tx.upsert_file(&FileRecord {
                path: relative.clone(),
                hash: source.hash.clone(),
                size: source.size,
                language: source.language.clone(),
                indexed_at: time_util::now_unix(),
            })?;

            let file_node = file_node(relative);
            tx.upsert_node(&file_node)?;
            report.nodes_written += 1;
            if tx.upsert_edge(&Edge::new(
                repository.id.clone(),
                file_node.id.clone(),
                EdgeKind::Contains,
            ).in_file(relative))? {
                report.edges_written += 1;
            }

            let parsed = match self.parsers.parse(&source)? {
                Some(parsed) => parsed,
                None => {
                    report.files_unsupported += 1;
                    continue;
                }
            };
            report.files_parsed += 1;
            if parsed.had_errors {
                report.files_with_syntax_errors.push(relative.clone());
            }

            for symbol in &parsed.symbols {
                write_symbol(&tx, &file_node, symbol, &mut report)?;
            }
            for import in &parsed.imports {
                write_import(&tx, &file_node, relative, import, &mut report)?;
            }
            pending.extend(
                parsed
                    .references
                    .into_iter()
                    .map(|reference| (relative.clone(), reference)),
            );
        }

        // Second pass. Call resolution needs every symbol in the repository to be visible,
        // including symbols written moments ago for other files in this same run.
        for (path, reference) in pending {
            if resolve_call(&tx, &path, &reference)? {
                report.edges_written += 1;
            } else {
                report.calls_unresolved += 1;
            }
        }

        tx.complete_scan(scan_id, "completed", report.files_seen, report.files_parsed)?;
        tx.commit()?;

        report.discovery = discovery;
        report.duration_ms = started.elapsed().as_millis();
        Ok(report)
    }
}

fn file_node(relative: &Path) -> Node {
    let key = relative.to_string_lossy().replace('\\', "/");
    let name = relative
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| key.clone());
    let mut node = Node::new(NodeKind::File, &key, name);
    node.path = Some(relative.to_path_buf());
    node.language = quoll_core::Language::from_path(relative);
    node
}

fn write_symbol<G: GraphOps>(
    graph: &G,
    file_node: &Node,
    symbol: &Symbol,
    report: &mut IndexReport,
) -> Result<()> {
    graph.insert_symbol(symbol)?;
    report.symbols_written += 1;

    let node = symbol.to_node();
    graph.upsert_node(&node)?;
    report.nodes_written += 1;

    if graph.upsert_edge(
        &Edge::new(file_node.id.clone(), node.id.clone(), EdgeKind::Contains)
            .at(&symbol.path, symbol.span),
    )? {
        report.edges_written += 1;
    }
    if symbol.exported
        && graph.upsert_edge(
            &Edge::new(file_node.id.clone(), node.id.clone(), EdgeKind::Defines)
                .at(&symbol.path, symbol.span),
        )?
    {
        report.edges_written += 1;
    }
    Ok(())
}

/// Record an external dependency edge.
///
/// Relative imports are skipped: they name a file, not a package, and the file already has
/// its own node. Turning `./db` into a dependency would create one node per import site.
fn write_import<G: GraphOps>(
    graph: &G,
    file_node: &Node,
    path: &Path,
    import: &Import,
    report: &mut IndexReport,
) -> Result<()> {
    if import.module.starts_with('.') || import.module.starts_with('/') {
        return Ok(());
    }
    let package = package_of(&import.module);
    let node = Node::new(NodeKind::Dependency, &package, package.clone());
    graph.upsert_node(&node)?;
    report.nodes_written += 1;

    if graph.upsert_edge(
        &Edge::new(file_node.id.clone(), node.id.clone(), EdgeKind::Imports)
            .at(path, import.span),
    )? {
        report.edges_written += 1;
    }
    Ok(())
}

/// Reduce an import path to the package that owns it.
///
/// `better-auth/next-js` and `better-auth/client` are the same dependency; `@scope/pkg/sub`
/// keeps two segments because the scope alone is not a package.
fn package_of(module: &str) -> String {
    // Rust paths use `::` and their first segment is the crate.
    if let Some((crate_name, _)) = module.split_once("::") {
        return crate_name.to_string();
    }
    let mut parts = module.split('/');
    let first = parts.next().unwrap_or(module);
    if first.starts_with('@') {
        match parts.next() {
            Some(second) => format!("{first}/{second}"),
            None => first.to_string(),
        }
    } else {
        first.to_string()
    }
}

/// Turn one call site into a `calls` edge, if the target can be identified.
///
/// Resolution is deliberately conservative, in this order:
///
/// 1. A callable declared in the same file wins. Same-file calls are the majority and the
///    match is unambiguous.
/// 2. Otherwise, a single callable with that name anywhere in the repository.
/// 3. Otherwise nothing. Two `execute` methods in different modules are not evidence that
///    this caller reaches either of them, and a guessed edge would put a fabricated attack
///    path in a report.
///
/// Returns whether an edge was written.
fn resolve_call<G: GraphOps>(graph: &G, path: &Path, reference: &Reference) -> Result<bool> {
    let from = match caller_node_id(graph, path, reference)? {
        Some(id) => id,
        None => return Ok(false),
    };

    let candidates: Vec<Symbol> = graph
        .symbols_named(&reference.name)?
        .into_iter()
        .filter(|symbol| symbol.kind.is_callable())
        .collect();

    let target = match candidates.iter().find(|symbol| symbol.path == path) {
        Some(local) => local,
        None if candidates.len() == 1 => &candidates[0],
        None => return Ok(false),
    };

    let to = target.to_node().id;
    if to == from {
        // Direct recursion adds a self-loop that no traversal benefits from.
        return Ok(false);
    }
    graph.upsert_edge(&Edge::new(from, to, EdgeKind::Calls).at(path, reference.span))
}

/// The node a call site belongs to: its enclosing function, or the file for top-level code.
fn caller_node_id<G: GraphOps>(
    graph: &G,
    path: &Path,
    reference: &Reference,
) -> Result<Option<NodeId>> {
    let caller = match &reference.caller {
        Some(caller) => caller,
        None => return Ok(Some(file_node(path).id)),
    };
    // The qualified name identifies the symbol; its kind decides whether the node is a
    // function or a method, and those hash to different ids.
    let lookup: HashMap<String, Symbol> = graph
        .symbols_in(path)?
        .into_iter()
        .map(|symbol| (symbol.qualified_name(), symbol))
        .collect();
    Ok(lookup.get(caller).map(|symbol| symbol.to_node().id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{self, Direction, Limits};
    use std::fs;

    struct Fixture {
        dir: tempfile::TempDir,
        graph: Graph,
    }

    impl Fixture {
        fn new() -> Fixture {
            Fixture {
                dir: tempfile::tempdir().unwrap(),
                graph: Graph::open_in_memory().unwrap(),
            }
        }

        fn write(&self, path: &str, contents: &str) {
            let full = self.dir.path().join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, contents).unwrap();
        }

        fn remove(&self, path: &str) {
            fs::remove_file(self.dir.path().join(path)).unwrap();
        }

        fn index(&mut self, scan_id: &str) -> IndexReport {
            let walker = Walker::new(self.dir.path()).exclude(vec!["**/.quoll/**".into()]);
            Indexer::new(walker)
                .index(&mut self.graph, scan_id)
                .unwrap()
        }
    }

    #[test]
    fn indexes_a_rust_repository_into_nodes_and_edges() {
        let mut fixture = Fixture::new();
        fixture.write(
            "src/api.rs",
            "pub fn create_user() {\n  insert_user();\n}\n\nfn insert_user() {}\n",
        );
        let report = fixture.index("scan-1");

        assert_eq!(report.files_seen, 1);
        assert_eq!(report.files_parsed, 1);
        assert_eq!(report.symbols_written, 2);

        let stats = fixture.graph.stats().unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.nodes_by_kind.get("function"), Some(&2));
        assert_eq!(stats.nodes_by_kind.get("repository"), Some(&1));
        assert_eq!(stats.edges_by_kind.get("calls"), Some(&1));
    }

    #[test]
    fn unchanged_files_are_not_reparsed() {
        let mut fixture = Fixture::new();
        fixture.write("src/main.rs", "fn main() {}\n");

        let first = fixture.index("scan-1");
        assert_eq!(first.files_parsed, 1);
        assert_eq!(first.files_unchanged, 0);

        let second = fixture.index("scan-2");
        assert_eq!(second.files_parsed, 0);
        assert_eq!(second.files_unchanged, 1);
        assert_eq!(fixture.graph.stats().unwrap().symbols, 1);
    }

    #[test]
    fn changed_files_are_reparsed_and_stale_symbols_disappear() {
        let mut fixture = Fixture::new();
        fixture.write("src/main.rs", "fn old_name() {}\n");
        fixture.index("scan-1");

        fixture.write("src/main.rs", "fn new_name() {}\n");
        let report = fixture.index("scan-2");

        assert_eq!(report.files_parsed, 1);
        let symbols = fixture
            .graph
            .symbols_in(Path::new("src/main.rs"))
            .unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "new_name");
    }

    #[test]
    fn deleted_files_are_removed_from_the_graph() {
        let mut fixture = Fixture::new();
        fixture.write("src/keep.rs", "fn keep() {}\n");
        fixture.write("src/gone.rs", "fn gone() {}\n");
        fixture.index("scan-1");
        assert_eq!(fixture.graph.stats().unwrap().files, 2);

        fixture.remove("src/gone.rs");
        let report = fixture.index("scan-2");

        assert_eq!(report.files_removed, 1);
        assert_eq!(fixture.graph.stats().unwrap().files, 1);
        assert!(fixture
            .graph
            .symbols_in(Path::new("src/gone.rs"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn call_edges_cross_files_when_the_target_is_unique() {
        let mut fixture = Fixture::new();
        fixture.write("src/api.rs", "pub fn handler() {\n  run_query();\n}\n");
        fixture.write("src/db.rs", "pub fn run_query() {}\n");
        fixture.index("scan-1");

        let handler = Node::at(NodeKind::Function, Path::new("src/api.rs"), "handler");
        let reached = query::reachable(
            &fixture.graph,
            &handler.id,
            Direction::Forward,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(
            reached.nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            vec!["run_query"]
        );
    }

    #[test]
    fn ambiguous_call_targets_are_left_unresolved() {
        let mut fixture = Fixture::new();
        fixture.write("src/a.rs", "pub fn execute() {}\n");
        fixture.write("src/b.rs", "pub fn execute() {}\n");
        fixture.write("src/c.rs", "pub fn go() {\n  execute();\n}\n");
        let report = fixture.index("scan-1");

        assert!(report.calls_unresolved >= 1);
        assert_eq!(fixture.graph.stats().unwrap().edges_by_kind.get("calls"), None);
    }

    #[test]
    fn same_file_targets_win_over_repository_wide_ones() {
        let mut fixture = Fixture::new();
        fixture.write("src/a.rs", "pub fn helper() {}\n");
        fixture.write(
            "src/b.rs",
            "pub fn helper() {}\npub fn caller() {\n  helper();\n}\n",
        );
        fixture.index("scan-1");

        let caller = Node::at(NodeKind::Function, Path::new("src/b.rs"), "caller");
        let edges = fixture.graph.edges_from(&caller.id).unwrap();
        let target = fixture.graph.node(&edges[0].to).unwrap().unwrap();
        assert_eq!(target.path.unwrap(), Path::new("src/b.rs"));
    }

    #[test]
    fn typescript_and_rust_index_side_by_side() {
        let mut fixture = Fixture::new();
        fixture.write("src/main.rs", "fn main() {}\n");
        fixture.write("web/app/page.tsx", "export function Page() {}\n");
        let report = fixture.index("scan-1");

        assert_eq!(report.files_parsed, 2);
        let stats = fixture.graph.stats().unwrap();
        assert_eq!(stats.symbols, 2);
    }

    #[test]
    fn imports_become_dependency_nodes_collapsed_to_their_package() {
        let mut fixture = Fixture::new();
        fixture.write(
            "src/auth.ts",
            "import { auth } from 'better-auth/next-js';\nimport { db } from './db';\n",
        );
        fixture.index("scan-1");

        let deps = fixture.graph.nodes_of_kind(NodeKind::Dependency).unwrap();
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["better-auth"]);
    }

    #[test]
    fn non_source_files_are_recorded_without_being_parsed() {
        let mut fixture = Fixture::new();
        fixture.write("README.md", "# hi\n");
        fixture.write("config.yaml", "a: 1\n");
        let report = fixture.index("scan-1");

        assert_eq!(report.files_seen, 2);
        assert_eq!(report.files_parsed, 0);
        assert_eq!(report.files_unsupported, 2);
        assert_eq!(fixture.graph.stats().unwrap().files, 2);
    }

    #[test]
    fn rebuild_discards_previous_structure() {
        let mut fixture = Fixture::new();
        fixture.write("src/main.rs", "fn main() {}\n");
        fixture.index("scan-1");

        let walker = Walker::new(fixture.dir.path());
        let report = Indexer::new(walker)
            .rebuild(true)
            .index(&mut fixture.graph, "scan-2")
            .unwrap();

        assert_eq!(report.files_parsed, 1);
        assert_eq!(report.files_unchanged, 0);
        assert_eq!(fixture.graph.stats().unwrap().symbols, 1);
    }

    #[test]
    fn a_scan_snapshot_is_recorded_and_completed() {
        let mut fixture = Fixture::new();
        fixture.write("src/main.rs", "fn main() {}\n");
        fixture.index("scan-1");

        let status: String = fixture
            .graph
            .conn()
            .query_row(
                "SELECT status FROM scan_snapshots WHERE id = 'scan-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "completed");
    }

    #[test]
    fn file_hashes_are_recorded_per_scan() {
        let mut fixture = Fixture::new();
        fixture.write("src/main.rs", "fn main() {}\n");
        fixture.index("scan-1");
        fixture.index("scan-2");

        let count: i64 = fixture
            .graph
            .conn()
            .query_row("SELECT COUNT(*) FROM file_hashes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2, "one row per scan per file");
    }

    #[test]
    fn syntax_errors_are_reported_without_failing_the_index() {
        let mut fixture = Fixture::new();
        fixture.write("src/broken.rs", "fn good() {}\nfn broken( {\n");
        let report = fixture.index("scan-1");

        assert_eq!(report.files_parsed, 1);
        assert_eq!(report.files_with_syntax_errors.len(), 1);
        assert!(!fixture
            .graph
            .symbols_in(Path::new("src/broken.rs"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn packages_collapse_scoped_and_pathed_modules() {
        assert_eq!(package_of("better-auth/next-js"), "better-auth");
        assert_eq!(package_of("@scope/pkg/sub"), "@scope/pkg");
        assert_eq!(package_of("std::process::Command"), "std");
        assert_eq!(package_of("axum"), "axum");
    }
}
