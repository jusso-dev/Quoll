use quoll_core::{Error, Result};
use rusqlite::Connection;

/// Schema version this build expects.
///
/// Bumping it requires appending to [`MIGRATIONS`]. Opening a database written by a newer
/// Quoll is a hard error rather than a best-effort read, because a silently-ignored column
/// produces a graph that is wrong instead of a graph that is missing.
pub const SCHEMA_VERSION: i32 = 1;

/// Ordered, append-only migrations. Index + 1 is the version each one produces.
///
/// Migrations are never edited after release. A mistake in a shipped migration is fixed by
/// appending a corrective one, so that databases in the field converge on the same shape as
/// databases built from scratch.
const MIGRATIONS: &[&str] = &[V1];

const V1: &str = r#"
CREATE TABLE repositories (
    id           INTEGER PRIMARY KEY,
    root         TEXT NOT NULL UNIQUE,
    name         TEXT,
    created_at   INTEGER NOT NULL
);

-- Current state of every indexed file. `hash` is what makes incremental indexing work:
-- an unchanged hash means the parse output is still valid and the file is skipped.
CREATE TABLE files (
    path         TEXT PRIMARY KEY,
    hash         TEXT NOT NULL,
    size         INTEGER NOT NULL,
    language     TEXT,
    indexed_at   INTEGER NOT NULL
);
CREATE INDEX idx_files_language ON files(language);

-- Per-scan record of what each file hashed to, so two scans can be diffed after the fact
-- without re-reading the working tree.
CREATE TABLE file_hashes (
    scan_id      TEXT NOT NULL,
    path         TEXT NOT NULL,
    hash         TEXT NOT NULL,
    PRIMARY KEY (scan_id, path)
);

CREATE TABLE symbols (
    id           INTEGER PRIMARY KEY,
    path         TEXT NOT NULL,
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL,
    container    TEXT,
    exported     INTEGER NOT NULL DEFAULT 0,
    start_line   INTEGER NOT NULL,
    end_line     INTEGER,
    start_column INTEGER,
    end_column   INTEGER
);
CREATE INDEX idx_symbols_path ON symbols(path);
CREATE INDEX idx_symbols_name ON symbols(name);

CREATE TABLE nodes (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    name         TEXT NOT NULL,
    path         TEXT,
    language     TEXT,
    start_line   INTEGER,
    end_line     INTEGER,
    start_column INTEGER,
    end_column   INTEGER,
    attributes   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_nodes_kind ON nodes(kind);
CREATE INDEX idx_nodes_path ON nodes(path);
CREATE INDEX idx_nodes_name ON nodes(name);

-- `path` records which file justified the edge. Deleting a file's rows by path is what
-- keeps the graph free of edges whose evidence no longer exists.
CREATE TABLE edges (
    from_id      TEXT NOT NULL,
    to_id        TEXT NOT NULL,
    kind         TEXT NOT NULL,
    path         TEXT,
    start_line   INTEGER,
    end_line     INTEGER,
    PRIMARY KEY (from_id, to_id, kind),
    FOREIGN KEY (from_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (to_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE INDEX idx_edges_from ON edges(from_id, kind);
CREATE INDEX idx_edges_to ON edges(to_id, kind);
CREATE INDEX idx_edges_path ON edges(path);

CREATE TABLE scan_snapshots (
    id           TEXT PRIMARY KEY,
    commit_sha   TEXT,
    profile      TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    completed_at INTEGER,
    status       TEXT NOT NULL,
    files_seen   INTEGER NOT NULL DEFAULT 0,
    files_parsed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_snapshots_commit ON scan_snapshots(commit_sha);

CREATE TABLE scanner_findings (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    plugin       TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    title        TEXT NOT NULL,
    path         TEXT,
    start_line   INTEGER,
    end_line     INTEGER,
    fingerprint  TEXT NOT NULL,
    raw          TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_snapshots(id) ON DELETE CASCADE
);
CREATE INDEX idx_findings_scan ON scanner_findings(scan_id);
CREATE INDEX idx_findings_fingerprint ON scanner_findings(fingerprint);

CREATE TABLE evidence (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    source       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    description  TEXT NOT NULL,
    path         TEXT,
    start_line   INTEGER,
    end_line     INTEGER,
    confidence   REAL NOT NULL
);
CREATE INDEX idx_evidence_scan ON evidence(scan_id);

CREATE TABLE hypotheses (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    class        TEXT NOT NULL,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    confidence   REAL NOT NULL,
    status       TEXT NOT NULL,
    path         TEXT,
    start_line   INTEGER,
    payload      TEXT NOT NULL
);
CREATE INDEX idx_hypotheses_scan ON hypotheses(scan_id);
CREATE INDEX idx_hypotheses_status ON hypotheses(status);

-- Cache key for AI work. `evidence_digest` is a hash of the exact bundle sent to the
-- model: identical evidence reuses the stored verdict instead of spending tokens again.
CREATE TABLE investigations (
    hypothesis_id   TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    confidence      REAL NOT NULL,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    evidence_digest TEXT NOT NULL,
    payload         TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);
CREATE INDEX idx_investigations_digest ON investigations(evidence_digest);

CREATE TABLE suppressions (
    fingerprint  TEXT PRIMARY KEY,
    reason       TEXT,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER
);
"#;

/// Bring a connection up to [`SCHEMA_VERSION`], creating the schema if it is empty.
pub fn migrate(conn: &Connection) -> Result<()> {
    let current: i32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(to_graph_error)?;

    if current > SCHEMA_VERSION {
        return Err(Error::Graph(format!(
            "graph was written by a newer Quoll (schema v{current}, this build supports v{SCHEMA_VERSION}); \
             delete .quoll/graph.db or upgrade Quoll"
        )));
    }
    if current == SCHEMA_VERSION {
        return Ok(());
    }

    // One transaction for the whole upgrade: a half-migrated graph is worse than no graph.
    conn.execute_batch("BEGIN").map_err(to_graph_error)?;
    for (index, migration) in MIGRATIONS.iter().enumerate() {
        let version = index as i32 + 1;
        if version <= current {
            continue;
        }
        if let Err(err) = conn.execute_batch(migration) {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(Error::Graph(format!("migration to v{version} failed: {err}")));
        }
    }
    conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}; COMMIT"))
        .map_err(to_graph_error)?;
    Ok(())
}

/// Pragmas applied to every connection.
///
/// WAL keeps a `quoll graph stats` readable while a scan writes. `foreign_keys` is off by
/// default in SQLite and must be enabled per connection, which is what makes the cascade
/// deletes in the schema actually fire.
pub fn apply_pragmas(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(to_graph_error)
}

pub(crate) fn to_graph_error(err: rusqlite::Error) -> Error {
    Error::Graph(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrated() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        apply_pragmas(&conn).unwrap();
        migrate(&conn).unwrap();
        conn
    }

    fn table_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    #[test]
    fn migration_creates_every_documented_table() {
        let conn = migrated();
        let tables = table_names(&conn);
        for expected in [
            "repositories",
            "files",
            "file_hashes",
            "symbols",
            "nodes",
            "edges",
            "scan_snapshots",
            "scanner_findings",
            "evidence",
            "hypotheses",
            "investigations",
            "suppressions",
        ] {
            assert!(tables.iter().any(|t| t == expected), "missing {expected}");
        }
    }

    #[test]
    fn migration_records_the_schema_version() {
        let conn = migrated();
        let version: i32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = migrated();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        assert_eq!(table_names(&conn).len(), table_names(&conn).len());
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_downgraded() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 999").unwrap();
        let err = migrate(&conn).unwrap_err();
        assert!(err.to_string().contains("newer Quoll"), "{err}");
    }

    #[test]
    fn deleting_a_node_removes_its_edges() {
        let conn = migrated();
        conn.execute_batch(
            "INSERT INTO nodes (id, kind, name) VALUES ('a', 'function', 'a'), ('b', 'function', 'b');
             INSERT INTO edges (from_id, to_id, kind) VALUES ('a', 'b', 'calls');
             DELETE FROM nodes WHERE id = 'a';",
        )
        .unwrap();
        let edges: i64 = conn
            .query_row("SELECT COUNT(*) FROM edges", [], |r| r.get(0))
            .unwrap();
        assert_eq!(edges, 0);
    }
}
