use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use quoll_core::{time_util, Error, Language, Result, Span};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::model::{Edge, EdgeKind, FileRecord, Node, NodeId, NodeKind, Symbol, SymbolKind};
use crate::schema::{self, to_graph_error};

/// Counts describing the current graph, surfaced by `quoll graph stats`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphStats {
    pub files: i64,
    pub symbols: i64,
    pub nodes: i64,
    pub edges: i64,
    pub nodes_by_kind: BTreeMap<String, i64>,
    pub edges_by_kind: BTreeMap<String, i64>,
}

/// Outcome of comparing a file on disk against what the graph already holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// Not in the graph at all.
    New,
    /// Present with a different hash.
    Changed,
    /// Present with the same hash — the expensive parse can be skipped entirely.
    Unchanged,
}

/// The persistent code graph.
///
/// Holds a single SQLite connection. Concurrency is handled by doing parse work in
/// parallel and writes serially through one connection, rather than by opening many
/// writers: SQLite serialises writers anyway, and one connection keeps transaction
/// boundaries obvious.
pub struct Graph {
    conn: Connection,
    path: Option<PathBuf>,
}

impl Graph {
    /// Open (or create) a graph at `path`, running any outstanding migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Graph> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let conn = Connection::open(&path).map_err(to_graph_error)?;
        schema::apply_pragmas(&conn)?;
        schema::migrate(&conn)?;
        Ok(Graph {
            conn,
            path: Some(path),
        })
    }

    /// An ephemeral graph. Used by tests and by `--no-cache` runs.
    pub fn open_in_memory() -> Result<Graph> {
        let conn = Connection::open_in_memory().map_err(to_graph_error)?;
        schema::apply_pragmas(&conn)?;
        schema::migrate(&conn)?;
        Ok(Graph { conn, path: None })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Start a write transaction.
    ///
    /// Indexing a repository is thousands of small inserts; outside a transaction SQLite
    /// would fsync after each one and indexing would be disk-bound rather than CPU-bound.
    pub fn transaction(&mut self) -> Result<Tx<'_>> {
        let tx = self.conn.transaction().map_err(to_graph_error)?;
        Ok(Tx(tx))
    }

    /// Drop every node, edge and symbol, keeping scan history.
    ///
    /// Used by `quoll graph build --rebuild` when the parser has changed and previously
    /// stored structure can no longer be trusted.
    pub fn clear_structure(&mut self) -> Result<()> {
        self.conn
            .execute_batch("DELETE FROM edges; DELETE FROM nodes; DELETE FROM symbols; DELETE FROM files;")
            .map_err(to_graph_error)
    }

    /// Reclaim space after a large deletion.
    pub fn vacuum(&self) -> Result<()> {
        self.conn.execute_batch("VACUUM").map_err(to_graph_error)
    }
}

impl GraphOps for Graph {
    fn conn(&self) -> &Connection {
        &self.conn
    }
}

/// An open write transaction. Dropping without [`Tx::commit`] rolls back.
pub struct Tx<'a>(rusqlite::Transaction<'a>);

impl Tx<'_> {
    pub fn commit(self) -> Result<()> {
        self.0.commit().map_err(to_graph_error)
    }
}

impl GraphOps for Tx<'_> {
    fn conn(&self) -> &Connection {
        &self.0
    }
}

/// Every read and write the graph supports.
///
/// Defined as a trait with default methods so that [`Graph`] and [`Tx`] share one
/// implementation: callers write the same code whether or not they are batching.
pub trait GraphOps {
    fn conn(&self) -> &Connection;

    // ---- files -----------------------------------------------------------------

    fn upsert_file(&self, record: &FileRecord) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO files (path, hash, size, language, indexed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(path) DO UPDATE SET
                     hash = excluded.hash,
                     size = excluded.size,
                     language = excluded.language,
                     indexed_at = excluded.indexed_at",
                params![
                    path_key(&record.path),
                    record.hash,
                    record.size as i64,
                    record.language.as_ref().map(|l| l.as_str().to_string()),
                    record.indexed_at,
                ],
            )
            .map_err(to_graph_error)?;
        Ok(())
    }

    fn file(&self, path: &Path) -> Result<Option<FileRecord>> {
        self.conn()
            .query_row(
                "SELECT path, hash, size, language, indexed_at FROM files WHERE path = ?1",
                params![path_key(path)],
                row_to_file,
            )
            .optional()
            .map_err(to_graph_error)
    }

    fn all_files(&self) -> Result<Vec<FileRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT path, hash, size, language, indexed_at FROM files ORDER BY path")
            .map_err(to_graph_error)?;
        let rows = stmt.query_map([], row_to_file).map_err(to_graph_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(to_graph_error)
    }

    /// Whether a file needs reparsing, given the hash of its current contents.
    fn file_state(&self, path: &Path, hash: &str) -> Result<FileState> {
        Ok(match self.file(path)? {
            None => FileState::New,
            Some(record) if record.hash == hash => FileState::Unchanged,
            Some(_) => FileState::Changed,
        })
    }

    /// Remove everything derived from a file: its record, symbols, nodes and the edges
    /// those nodes participate in.
    ///
    /// Called before reparsing a changed file and when a file disappears from the tree.
    /// Without it the graph accumulates nodes for code that no longer exists, and reports
    /// cite line numbers that moved.
    fn forget_file(&self, path: &Path) -> Result<()> {
        let key = path_key(path);
        let conn = self.conn();
        // Edges anchored in this file go first: an edge may point at a node owned by
        // another file, which must survive.
        conn.execute("DELETE FROM edges WHERE path = ?1", params![key])
            .map_err(to_graph_error)?;
        conn.execute("DELETE FROM nodes WHERE path = ?1", params![key])
            .map_err(to_graph_error)?;
        conn.execute("DELETE FROM symbols WHERE path = ?1", params![key])
            .map_err(to_graph_error)?;
        conn.execute("DELETE FROM files WHERE path = ?1", params![key])
            .map_err(to_graph_error)?;
        Ok(())
    }

    /// Record the hash a file had during a given scan.
    fn record_file_hash(&self, scan_id: &str, path: &Path, hash: &str) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO file_hashes (scan_id, path, hash) VALUES (?1, ?2, ?3)
                 ON CONFLICT(scan_id, path) DO UPDATE SET hash = excluded.hash",
                params![scan_id, path_key(path), hash],
            )
            .map_err(to_graph_error)?;
        Ok(())
    }

    // ---- symbols ---------------------------------------------------------------

    fn insert_symbol(&self, symbol: &Symbol) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO symbols
                     (path, name, kind, container, exported, start_line, end_line, start_column, end_column)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    path_key(&symbol.path),
                    symbol.name,
                    symbol.kind.as_str(),
                    symbol.container,
                    symbol.exported as i32,
                    symbol.span.start_line,
                    symbol.span.end_line,
                    symbol.span.start_column,
                    symbol.span.end_column,
                ],
            )
            .map_err(to_graph_error)?;
        Ok(())
    }

    fn symbols_in(&self, path: &Path) -> Result<Vec<Symbol>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT path, name, kind, container, exported, start_line, end_line, start_column, end_column
                 FROM symbols WHERE path = ?1 ORDER BY start_line",
            )
            .map_err(to_graph_error)?;
        let rows = stmt
            .query_map(params![path_key(path)], row_to_symbol)
            .map_err(to_graph_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(to_graph_error)
    }

    /// Every declaration with this name, across the repository.
    ///
    /// The MVP resolves calls by name. That is imprecise for overloaded or shadowed
    /// names, which is why call edges are treated as evidence rather than proof.
    fn symbols_named(&self, name: &str) -> Result<Vec<Symbol>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT path, name, kind, container, exported, start_line, end_line, start_column, end_column
                 FROM symbols WHERE name = ?1 ORDER BY path, start_line",
            )
            .map_err(to_graph_error)?;
        let rows = stmt
            .query_map(params![name], row_to_symbol)
            .map_err(to_graph_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(to_graph_error)
    }

    // ---- nodes -----------------------------------------------------------------

    fn upsert_node(&self, node: &Node) -> Result<()> {
        let attributes =
            serde_json::to_string(&node.attributes).unwrap_or_else(|_| "{}".to_string());
        self.conn()
            .execute(
                "INSERT INTO nodes
                     (id, kind, name, path, language, start_line, end_line, start_column, end_column, attributes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id) DO UPDATE SET
                     name = excluded.name,
                     path = excluded.path,
                     language = excluded.language,
                     start_line = excluded.start_line,
                     end_line = excluded.end_line,
                     start_column = excluded.start_column,
                     end_column = excluded.end_column,
                     attributes = excluded.attributes",
                params![
                    node.id.as_str(),
                    node.kind.as_str(),
                    node.name,
                    node.path.as_deref().map(path_key),
                    node.language.as_ref().map(|l| l.as_str().to_string()),
                    node.span.map(|s| s.start_line),
                    node.span.and_then(|s| s.end_line),
                    node.span.and_then(|s| s.start_column),
                    node.span.and_then(|s| s.end_column),
                    attributes,
                ],
            )
            .map_err(to_graph_error)?;
        Ok(())
    }

    fn node(&self, id: &NodeId) -> Result<Option<Node>> {
        self.conn()
            .query_row(
                "SELECT id, kind, name, path, language, start_line, end_line, start_column, end_column, attributes
                 FROM nodes WHERE id = ?1",
                params![id.as_str()],
                row_to_node,
            )
            .optional()
            .map_err(to_graph_error)
    }

    fn nodes_of_kind(&self, kind: NodeKind) -> Result<Vec<Node>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, name, path, language, start_line, end_line, start_column, end_column, attributes
                 FROM nodes WHERE kind = ?1 ORDER BY path, start_line",
            )
            .map_err(to_graph_error)?;
        let rows = stmt
            .query_map(params![kind.as_str()], row_to_node)
            .map_err(to_graph_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(to_graph_error)
    }

    fn nodes_in_file(&self, path: &Path) -> Result<Vec<Node>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, name, path, language, start_line, end_line, start_column, end_column, attributes
                 FROM nodes WHERE path = ?1 ORDER BY start_line",
            )
            .map_err(to_graph_error)?;
        let rows = stmt
            .query_map(params![path_key(path)], row_to_node)
            .map_err(to_graph_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(to_graph_error)
    }

    /// The innermost node whose span covers a line — how a scanner finding at
    /// `src/api.rs:42` is attributed to the function containing it.
    fn node_covering(&self, path: &Path, line: u32) -> Result<Option<Node>> {
        let candidates = self.nodes_in_file(path)?;
        Ok(candidates
            .into_iter()
            .filter(|node| match node.span {
                Some(span) => span.start_line <= line && line <= span.last_line(),
                None => false,
            })
            .min_by_key(|node| {
                node.span
                    .map(|s| s.last_line().saturating_sub(s.start_line))
                    .unwrap_or(u32::MAX)
            }))
    }

    // ---- edges -----------------------------------------------------------------

    /// Insert an edge, ignoring it when either endpoint is absent.
    ///
    /// Returns whether the edge was stored. Unresolved call targets are the common case —
    /// a call into a dependency has no node — and are not an error.
    fn upsert_edge(&self, edge: &Edge) -> Result<bool> {
        let result = self.conn().execute(
            "INSERT INTO edges (from_id, to_id, kind, path, start_line, end_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(from_id, to_id, kind) DO UPDATE SET
                 path = excluded.path,
                 start_line = excluded.start_line,
                 end_line = excluded.end_line",
            params![
                edge.from.as_str(),
                edge.to.as_str(),
                edge.kind.as_str(),
                edge.path.as_deref().map(path_key),
                edge.span.map(|s| s.start_line),
                edge.span.and_then(|s| s.end_line),
            ],
        );
        match result {
            Ok(_) => Ok(true),
            // A missing endpoint trips the foreign key; that is expected, not fatal.
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Ok(false)
            }
            Err(err) => Err(to_graph_error(err)),
        }
    }

    fn edges_from(&self, id: &NodeId) -> Result<Vec<Edge>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT from_id, to_id, kind, path, start_line, end_line
                 FROM edges WHERE from_id = ?1 ORDER BY kind, to_id",
            )
            .map_err(to_graph_error)?;
        let rows = stmt
            .query_map(params![id.as_str()], row_to_edge)
            .map_err(to_graph_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(to_graph_error)
    }

    fn edges_to(&self, id: &NodeId) -> Result<Vec<Edge>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT from_id, to_id, kind, path, start_line, end_line
                 FROM edges WHERE to_id = ?1 ORDER BY kind, from_id",
            )
            .map_err(to_graph_error)?;
        let rows = stmt
            .query_map(params![id.as_str()], row_to_edge)
            .map_err(to_graph_error)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(to_graph_error)
    }

    /// Whether a node has an outgoing edge of a kind pointing at a node of a kind.
    ///
    /// This is the primitive every policy invariant is built on: "does this route have a
    /// `guarded_by` edge to an `auth_guard`".
    fn has_edge_to_kind(&self, from: &NodeId, edge: EdgeKind, target: NodeKind) -> Result<bool> {
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM edges
                 JOIN nodes ON nodes.id = edges.to_id
                 WHERE edges.from_id = ?1 AND edges.kind = ?2 AND nodes.kind = ?3",
                params![from.as_str(), edge.as_str(), target.as_str()],
                |row| row.get(0),
            )
            .map_err(to_graph_error)?;
        Ok(count > 0)
    }

    // ---- scans -----------------------------------------------------------------

    fn begin_scan(&self, scan_id: &str, commit: Option<&str>, profile: &str) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO scan_snapshots (id, commit_sha, profile, started_at, status)
                 VALUES (?1, ?2, ?3, ?4, 'running')
                 ON CONFLICT(id) DO UPDATE SET status = 'running'",
                params![scan_id, commit, profile, time_util::now_unix()],
            )
            .map_err(to_graph_error)?;
        Ok(())
    }

    fn complete_scan(
        &self,
        scan_id: &str,
        status: &str,
        files_seen: usize,
        files_parsed: usize,
    ) -> Result<()> {
        self.conn()
            .execute(
                "UPDATE scan_snapshots
                 SET status = ?2, completed_at = ?3, files_seen = ?4, files_parsed = ?5
                 WHERE id = ?1",
                params![
                    scan_id,
                    status,
                    time_util::now_unix(),
                    files_seen as i64,
                    files_parsed as i64
                ],
            )
            .map_err(to_graph_error)?;
        Ok(())
    }

    /// The most recent completed scan of a commit, used to decide whether a CI run can
    /// reuse cached results instead of reindexing.
    fn last_scan_for_commit(&self, commit: &str) -> Result<Option<String>> {
        self.conn()
            .query_row(
                "SELECT id FROM scan_snapshots
                 WHERE commit_sha = ?1 AND status = 'completed'
                 ORDER BY completed_at DESC LIMIT 1",
                params![commit],
                |row| row.get(0),
            )
            .optional()
            .map_err(to_graph_error)
    }

    // ---- suppressions ----------------------------------------------------------

    fn suppress(&self, fingerprint: &str, reason: Option<&str>, expires_at: Option<i64>) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO suppressions (fingerprint, reason, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(fingerprint) DO UPDATE SET
                     reason = excluded.reason,
                     expires_at = excluded.expires_at",
                params![fingerprint, reason, time_util::now_unix(), expires_at],
            )
            .map_err(to_graph_error)?;
        Ok(())
    }

    /// Whether a finding is currently suppressed. Expired suppressions do not count, so a
    /// time-boxed exception re-opens the finding on its own.
    fn is_suppressed(&self, fingerprint: &str) -> Result<bool> {
        let now = time_util::now_unix();
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM suppressions
                 WHERE fingerprint = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
                params![fingerprint, now],
                |row| row.get(0),
            )
            .map_err(to_graph_error)?;
        Ok(count > 0)
    }

    // ---- stats -----------------------------------------------------------------

    fn stats(&self) -> Result<GraphStats> {
        let conn = self.conn();
        let scalar = |sql: &str| -> Result<i64> {
            conn.query_row(sql, [], |row| row.get(0))
                .map_err(to_graph_error)
        };
        let mut stats = GraphStats {
            files: scalar("SELECT COUNT(*) FROM files")?,
            symbols: scalar("SELECT COUNT(*) FROM symbols")?,
            nodes: scalar("SELECT COUNT(*) FROM nodes")?,
            edges: scalar("SELECT COUNT(*) FROM edges")?,
            ..Default::default()
        };
        let group = |sql: &str| -> Result<BTreeMap<String, i64>> {
            let mut stmt = conn.prepare(sql).map_err(to_graph_error)?;
            let rows = stmt
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
                .map_err(to_graph_error)?;
            rows.collect::<rusqlite::Result<BTreeMap<_, _>>>()
                .map_err(to_graph_error)
        };
        stats.nodes_by_kind = group("SELECT kind, COUNT(*) FROM nodes GROUP BY kind")?;
        stats.edges_by_kind = group("SELECT kind, COUNT(*) FROM edges GROUP BY kind")?;
        Ok(stats)
    }
}

/// Normalise a path to its storage form.
///
/// Backslashes become forward slashes so that a graph built on Windows and one built on
/// Linux produce the same node ids for the same repository.
fn path_key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn optional_span(row: &Row<'_>, start: usize) -> rusqlite::Result<Option<Span>> {
    let start_line: Option<u32> = row.get(start)?;
    Ok(start_line.map(|line| Span {
        start_line: line,
        end_line: row.get(start + 1).ok().flatten(),
        start_column: row.get(start + 2).ok().flatten(),
        end_column: row.get(start + 3).ok().flatten(),
        start_byte: None,
        end_byte: None,
    }))
}

fn row_to_file(row: &Row<'_>) -> rusqlite::Result<FileRecord> {
    let language: Option<String> = row.get(3)?;
    Ok(FileRecord {
        path: PathBuf::from(row.get::<_, String>(0)?),
        hash: row.get(1)?,
        size: row.get::<_, i64>(2)? as u64,
        language: language.map(|l| Language::from_str(&l).unwrap_or(Language::Other(l))),
        indexed_at: row.get(4)?,
    })
}

fn row_to_symbol(row: &Row<'_>) -> rusqlite::Result<Symbol> {
    let kind: String = row.get(2)?;
    Ok(Symbol {
        path: PathBuf::from(row.get::<_, String>(0)?),
        name: row.get(1)?,
        kind: SymbolKind::from_str(&kind).unwrap_or(SymbolKind::Variable),
        container: row.get(3)?,
        exported: row.get::<_, i32>(4)? != 0,
        span: Span {
            start_line: row.get(5)?,
            end_line: row.get(6)?,
            start_column: row.get(7)?,
            end_column: row.get(8)?,
            start_byte: None,
            end_byte: None,
        },
    })
}

fn row_to_node(row: &Row<'_>) -> rusqlite::Result<Node> {
    let kind: String = row.get(1)?;
    let path: Option<String> = row.get(3)?;
    let language: Option<String> = row.get(4)?;
    let attributes: String = row.get(9)?;
    Ok(Node {
        id: NodeId::from_raw(row.get::<_, String>(0)?),
        kind: NodeKind::from_str(&kind).unwrap_or(NodeKind::Module),
        name: row.get(2)?,
        path: path.map(PathBuf::from),
        language: language.map(|l| Language::from_str(&l).unwrap_or(Language::Other(l))),
        span: optional_span(row, 5)?,
        attributes: serde_json::from_str(&attributes).unwrap_or_default(),
    })
}

fn row_to_edge(row: &Row<'_>) -> rusqlite::Result<Edge> {
    let kind: String = row.get(2)?;
    let path: Option<String> = row.get(3)?;
    let start_line: Option<u32> = row.get(4)?;
    Ok(Edge {
        from: NodeId::from_raw(row.get::<_, String>(0)?),
        to: NodeId::from_raw(row.get::<_, String>(1)?),
        kind: EdgeKind::from_str(&kind).unwrap_or(EdgeKind::Contains),
        path: path.map(PathBuf::from),
        span: start_line.map(|line| Span {
            start_line: line,
            end_line: row.get(5).ok().flatten(),
            start_column: None,
            end_column: None,
            start_byte: None,
            end_byte: None,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> Graph {
        Graph::open_in_memory().unwrap()
    }

    fn function(path: &str, name: &str, line: u32) -> Node {
        Node::at(NodeKind::Function, Path::new(path), name).with_span(Span::lines(line, line + 5))
    }

    #[test]
    fn nodes_round_trip() {
        let graph = graph();
        let node = function("src/api.rs", "create_user", 10)
            .with_attribute("http_method", "POST");
        graph.upsert_node(&node).unwrap();

        let loaded = graph.node(&node.id).unwrap().unwrap();
        assert_eq!(loaded.name, "create_user");
        assert_eq!(loaded.kind, NodeKind::Function);
        assert_eq!(loaded.attribute_str("http_method"), Some("POST"));
        assert_eq!(loaded.span.unwrap().start_line, 10);
        assert_eq!(loaded.language, Some(Language::Rust));
    }

    #[test]
    fn upserting_a_node_twice_does_not_duplicate_it() {
        let graph = graph();
        let node = function("src/api.rs", "handler", 1);
        graph.upsert_node(&node).unwrap();
        graph.upsert_node(&node).unwrap();
        assert_eq!(graph.stats().unwrap().nodes, 1);
    }

    #[test]
    fn edges_to_unknown_nodes_are_dropped_not_errors() {
        let graph = graph();
        let from = function("src/a.rs", "caller", 1);
        graph.upsert_node(&from).unwrap();
        let edge = Edge::new(
            from.id.clone(),
            NodeId::new(NodeKind::Function, "does/not/exist"),
            EdgeKind::Calls,
        );
        assert!(!graph.upsert_edge(&edge).unwrap());
        assert_eq!(graph.stats().unwrap().edges, 0);
    }

    #[test]
    fn edges_round_trip_between_known_nodes() {
        let graph = graph();
        let caller = function("src/a.rs", "caller", 1);
        let callee = function("src/b.rs", "callee", 1);
        graph.upsert_node(&caller).unwrap();
        graph.upsert_node(&callee).unwrap();
        let edge = Edge::new(caller.id.clone(), callee.id.clone(), EdgeKind::Calls)
            .at("src/a.rs", Span::line(3));
        assert!(graph.upsert_edge(&edge).unwrap());

        let out = graph.edges_from(&caller.id).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EdgeKind::Calls);
        assert_eq!(graph.edges_to(&callee.id).unwrap().len(), 1);
    }

    #[test]
    fn policy_primitive_answers_guarded_by_questions() {
        let graph = graph();
        let route = Node::at(NodeKind::Route, Path::new("src/api.rs"), "POST /users");
        let guard = Node::at(NodeKind::AuthGuard, Path::new("src/auth.rs"), "require_session");
        graph.upsert_node(&route).unwrap();
        graph.upsert_node(&guard).unwrap();

        assert!(!graph
            .has_edge_to_kind(&route.id, EdgeKind::GuardedBy, NodeKind::AuthGuard)
            .unwrap());
        graph
            .upsert_edge(&Edge::new(route.id.clone(), guard.id.clone(), EdgeKind::GuardedBy))
            .unwrap();
        assert!(graph
            .has_edge_to_kind(&route.id, EdgeKind::GuardedBy, NodeKind::AuthGuard)
            .unwrap());
    }

    #[test]
    fn file_state_drives_incremental_work() {
        let graph = graph();
        let path = Path::new("src/main.rs");
        assert_eq!(graph.file_state(path, "aaa").unwrap(), FileState::New);

        graph
            .upsert_file(&FileRecord {
                path: path.to_path_buf(),
                hash: "aaa".into(),
                size: 12,
                language: Some(Language::Rust),
                indexed_at: 0,
            })
            .unwrap();
        assert_eq!(graph.file_state(path, "aaa").unwrap(), FileState::Unchanged);
        assert_eq!(graph.file_state(path, "bbb").unwrap(), FileState::Changed);
    }

    #[test]
    fn forgetting_a_file_removes_its_nodes_but_spares_its_neighbours() {
        let graph = graph();
        let a = function("src/a.rs", "caller", 1);
        let b = function("src/b.rs", "callee", 1);
        graph.upsert_node(&a).unwrap();
        graph.upsert_node(&b).unwrap();
        graph
            .upsert_edge(&Edge::new(a.id.clone(), b.id.clone(), EdgeKind::Calls).in_file("src/a.rs"))
            .unwrap();

        graph.forget_file(Path::new("src/a.rs")).unwrap();

        assert!(graph.node(&a.id).unwrap().is_none());
        assert!(graph.node(&b.id).unwrap().is_some());
        assert_eq!(graph.stats().unwrap().edges, 0);
    }

    #[test]
    fn node_covering_picks_the_innermost_span() {
        let graph = graph();
        let outer = Node::at(NodeKind::Module, Path::new("src/a.rs"), "outer")
            .with_span(Span::lines(1, 100));
        let inner = function("src/a.rs", "inner", 40);
        graph.upsert_node(&outer).unwrap();
        graph.upsert_node(&inner).unwrap();

        let hit = graph.node_covering(Path::new("src/a.rs"), 42).unwrap().unwrap();
        assert_eq!(hit.name, "inner");
        let hit = graph.node_covering(Path::new("src/a.rs"), 90).unwrap().unwrap();
        assert_eq!(hit.name, "outer");
        assert!(graph.node_covering(Path::new("src/a.rs"), 500).unwrap().is_none());
    }

    #[test]
    fn transactions_roll_back_on_drop() {
        let mut graph = graph();
        {
            let tx = graph.transaction().unwrap();
            tx.upsert_node(&function("src/a.rs", "doomed", 1)).unwrap();
            // Dropped without commit.
        }
        assert_eq!(graph.stats().unwrap().nodes, 0);

        {
            let tx = graph.transaction().unwrap();
            tx.upsert_node(&function("src/a.rs", "kept", 1)).unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(graph.stats().unwrap().nodes, 1);
    }

    #[test]
    fn symbols_are_queryable_by_file_and_name() {
        let graph = graph();
        let symbol = Symbol::new("create", SymbolKind::Method, "src/db.rs", Span::lines(3, 9))
            .in_container("UserRepo")
            .exported(true);
        graph.insert_symbol(&symbol).unwrap();

        let in_file = graph.symbols_in(Path::new("src/db.rs")).unwrap();
        assert_eq!(in_file.len(), 1);
        assert!(in_file[0].exported);
        assert_eq!(in_file[0].container.as_deref(), Some("UserRepo"));
        assert_eq!(graph.symbols_named("create").unwrap().len(), 1);
        assert!(graph.symbols_named("missing").unwrap().is_empty());
    }

    #[test]
    fn expired_suppressions_stop_suppressing() {
        let graph = graph();
        graph.suppress("fp-live", Some("accepted risk"), None).unwrap();
        graph.suppress("fp-stale", None, Some(1)).unwrap();
        assert!(graph.is_suppressed("fp-live").unwrap());
        assert!(!graph.is_suppressed("fp-stale").unwrap());
        assert!(!graph.is_suppressed("fp-unknown").unwrap());
    }

    #[test]
    fn only_completed_scans_are_reusable() {
        let graph = graph();
        graph.begin_scan("scan-1", Some("abc123"), "fast").unwrap();
        assert!(graph.last_scan_for_commit("abc123").unwrap().is_none());
        graph.complete_scan("scan-1", "completed", 10, 4).unwrap();
        assert_eq!(
            graph.last_scan_for_commit("abc123").unwrap().as_deref(),
            Some("scan-1")
        );
    }

    #[test]
    fn stats_break_down_by_kind() {
        let graph = graph();
        graph.upsert_node(&function("src/a.rs", "f", 1)).unwrap();
        graph
            .upsert_node(&Node::at(NodeKind::Route, Path::new("src/a.rs"), "GET /"))
            .unwrap();
        let stats = graph.stats().unwrap();
        assert_eq!(stats.nodes, 2);
        assert_eq!(stats.nodes_by_kind.get("function"), Some(&1));
        assert_eq!(stats.nodes_by_kind.get("route"), Some(&1));
    }
}
