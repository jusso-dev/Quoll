//! Deterministic security invariants, evaluated against the code graph.
//!
//! This is where Quoll finds what pattern matching cannot: the *absence* of a control. No
//! regex matches a missing authentication check, because there is nothing there to match.
//! A policy pack states what must be true of a route or a query, and evaluation asks the
//! graph whether it is.
//!
//! Evaluation is a pure function of the graph and the detected stack. There is no "maybe"
//! outcome and no scoring: a selector either matched a node or it did not, and a matched
//! node either satisfies the requirement or does not. Two runs over the same commit produce
//! byte-identical results, which is what lets a CI baseline mean anything.
//!
//! # The attribute vocabulary
//!
//! Policy reads node attributes that framework-aware indexing writes. This is the contract
//! between the two:
//!
//! | Node kind            | Attribute    | Meaning                                       |
//! |----------------------|--------------|-----------------------------------------------|
//! | `route`              | `method`     | HTTP method, e.g. `POST`                      |
//! | `route`              | `path`       | URL path the route serves                     |
//! | `database_operation` | `operation`  | `select`, `insert`, `update`, `delete`        |
//! | `database_operation` | `table`      | Table or model being operated on              |
//! | `database_operation` | `predicates` | Column names in the where clause, as an array |
//!
//! An operation carrying no `predicates` attribute is unfiltered — which is precisely the
//! case a tenant-scoping invariant exists to catch.
//!
//! ```no_run
//! use quoll_policy::Registry;
//! use quoll_graph::Graph;
//!
//! # let detection = quoll_detect::Detection::default();
//! let graph = Graph::open(".quoll/graph.db")?;
//! let report = Registry::builtin()?.evaluate(&graph, &detection)?;
//!
//! for violation in report.violations() {
//!     println!("{}: {}", violation.severity, violation.describe());
//! }
//! # Ok::<(), quoll_core::Error>(())
//! ```

pub mod evaluate;
pub mod pack;
pub mod registry;

pub use evaluate::{evaluate, Outcome, Report, Skipped, Status};
pub use pack::{
    Applicability, Condition, Invariant, Pack, Requirement, Selector, SCHEMA_VERSION,
};
pub use registry::{Registry, USER_POLICY_DIR};
