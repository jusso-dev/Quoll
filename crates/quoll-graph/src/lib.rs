//! The persistent code graph.
//!
//! Quoll's central claim is that a security finding should rest on structural facts, not
//! on pattern matches. This crate produces those facts: it walks a repository, parses the
//! files that changed since last time, and stores declarations, imports and call sites as
//! nodes and edges in SQLite at `.quoll/graph.db`.
//!
//! Two properties are deliberate and load-bearing:
//!
//! * **Bounded.** Every traversal is capped on depth, visited nodes and returned paths.
//!   A repository is untrusted input and must never be able to make a scan hang.
//! * **Honest.** Call edges are resolved by name, and only when the target is
//!   unambiguous. Quoll does not perform whole-program data-flow analysis, and this crate
//!   does not pretend to: an unresolved call is counted and dropped, never guessed.
//!
//! ```no_run
//! use quoll_graph::{Graph, Indexer, Walker};
//!
//! let mut graph = Graph::open(".quoll/graph.db")?;
//! let report = Indexer::new(Walker::new(".")).index(&mut graph, "scan-1")?;
//! println!("{}", report.summary());
//! # Ok::<(), quoll_core::Error>(())
//! ```

pub mod index;
pub mod model;
pub mod parse;
pub mod query;
pub mod schema;
pub mod store;
pub mod walk;

pub use index::{IndexReport, Indexer};
pub use model::{Edge, EdgeKind, FileRecord, Node, NodeId, NodeKind, Symbol, SymbolKind};
pub use parse::{Import, ParsedFile, Parsers, Reference};
pub use query::{Direction, GraphPath, Limits, Traversal};
pub use schema::SCHEMA_VERSION;
pub use store::{FileState, Graph, GraphOps, GraphStats, Tx};
pub use walk::{Discovery, SourceFile, Walker};
