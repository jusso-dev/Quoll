use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use quoll_core::{ids, Language, Span};
use serde::{Deserialize, Serialize};

/// Stable, content-derived node identifier.
///
/// Deliberately a string rather than a rowid: node identity has to survive a database
/// rebuild, be quotable from a policy pack and be comparable across two machines that
/// indexed the same commit. Rowids satisfy none of those.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Derive an id from the node's kind and its natural key.
    ///
    /// The natural key is whatever makes the node unique within its kind: a path for a
    /// file, `path::symbol` for a function, `METHOD /path` for a route.
    pub fn new(kind: NodeKind, key: &str) -> NodeId {
        NodeId(ids::stable_id(kind.prefix(), &[kind.as_str(), key]))
    }

    /// Wrap an id read back out of storage.
    pub fn from_raw(raw: impl Into<String>) -> NodeId {
        NodeId(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a node represents.
///
/// The list is closed on purpose. An open string kind would let every plugin invent its
/// own vocabulary, and policy packs would then have to match on spelling rather than
/// meaning. Adding a kind is a deliberate schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Repository,
    Package,
    File,
    Module,
    Function,
    Method,
    /// An HTTP entry point: an Axum handler registration, a Next.js route file, an
    /// Express `app.get`.
    Route,
    Middleware,
    /// A control that establishes *who* the caller is.
    AuthGuard,
    /// A control that decides *what* the caller may do.
    AuthorisationGuard,
    DatabaseOperation,
    DatabaseTable,
    ExternalRequest,
    FilesystemOperation,
    ProcessExecution,
    Secret,
    Dependency,
    ScannerFinding,
    SecurityControl,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Repository => "repository",
            NodeKind::Package => "package",
            NodeKind::File => "file",
            NodeKind::Module => "module",
            NodeKind::Function => "function",
            NodeKind::Method => "method",
            NodeKind::Route => "route",
            NodeKind::Middleware => "middleware",
            NodeKind::AuthGuard => "auth_guard",
            NodeKind::AuthorisationGuard => "authorisation_guard",
            NodeKind::DatabaseOperation => "database_operation",
            NodeKind::DatabaseTable => "database_table",
            NodeKind::ExternalRequest => "external_request",
            NodeKind::FilesystemOperation => "filesystem_operation",
            NodeKind::ProcessExecution => "process_execution",
            NodeKind::Secret => "secret",
            NodeKind::Dependency => "dependency",
            NodeKind::ScannerFinding => "scanner_finding",
            NodeKind::SecurityControl => "security_control",
        }
    }

    /// Short prefix used in node ids, so a raw id is readable in a log line.
    fn prefix(self) -> &'static str {
        match self {
            NodeKind::Repository => "repo",
            NodeKind::Package => "pkg",
            NodeKind::File => "file",
            NodeKind::Module => "mod",
            NodeKind::Function | NodeKind::Method => "fn",
            NodeKind::Route => "route",
            NodeKind::Middleware => "mw",
            NodeKind::AuthGuard => "authn",
            NodeKind::AuthorisationGuard => "authz",
            NodeKind::DatabaseOperation => "dbop",
            NodeKind::DatabaseTable => "table",
            NodeKind::ExternalRequest => "http",
            NodeKind::FilesystemOperation => "fs",
            NodeKind::ProcessExecution => "exec",
            NodeKind::Secret => "secret",
            NodeKind::Dependency => "dep",
            NodeKind::ScannerFinding => "sf",
            NodeKind::SecurityControl => "ctrl",
        }
    }

    /// Whether attacker-controlled input can arrive at this node from outside.
    ///
    /// Traversals start here when answering "what can an unauthenticated caller reach".
    pub fn is_entry_point(self) -> bool {
        matches!(self, NodeKind::Route | NodeKind::Middleware)
    }

    /// Whether reaching this node unguarded is worth reporting.
    pub fn is_sink(self) -> bool {
        matches!(
            self,
            NodeKind::DatabaseOperation
                | NodeKind::FilesystemOperation
                | NodeKind::ProcessExecution
                | NodeKind::ExternalRequest
                | NodeKind::Secret
        )
    }

    /// Whether this node is a control that a policy invariant can require.
    pub fn is_control(self) -> bool {
        matches!(
            self,
            NodeKind::AuthGuard | NodeKind::AuthorisationGuard | NodeKind::SecurityControl
        )
    }
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NodeKind {
    type Err = quoll_core::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "repository" => NodeKind::Repository,
            "package" => NodeKind::Package,
            "file" => NodeKind::File,
            "module" => NodeKind::Module,
            "function" => NodeKind::Function,
            "method" => NodeKind::Method,
            "route" => NodeKind::Route,
            "middleware" => NodeKind::Middleware,
            "auth_guard" => NodeKind::AuthGuard,
            "authorisation_guard" => NodeKind::AuthorisationGuard,
            "database_operation" => NodeKind::DatabaseOperation,
            "database_table" => NodeKind::DatabaseTable,
            "external_request" => NodeKind::ExternalRequest,
            "filesystem_operation" => NodeKind::FilesystemOperation,
            "process_execution" => NodeKind::ProcessExecution,
            "secret" => NodeKind::Secret,
            "dependency" => NodeKind::Dependency,
            "scanner_finding" => NodeKind::ScannerFinding,
            "security_control" => NodeKind::SecurityControl,
            other => {
                return Err(quoll_core::Error::Graph(format!(
                    "unknown node kind `{other}`"
                )))
            }
        })
    }
}

/// How two nodes relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Structural containment: repository → file → function.
    Contains,
    Imports,
    /// A file or module declares a symbol.
    Defines,
    Calls,
    /// A route registration binds a path to a handler.
    RoutesTo,
    /// A handler is protected by a control.
    GuardedBy,
    Authenticates,
    Authorises,
    Reads,
    Writes,
    Queries,
    /// Value flow. In the MVP this is only ever recorded for relationships the indexer
    /// proved directly; it is never inferred transitively.
    FlowsTo,
    DependsOn,
    /// A scanner finding is anchored at a code node.
    FindingAt,
    /// Evidence that a control is effective.
    Supports,
    EvidenceFor,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Contains => "contains",
            EdgeKind::Imports => "imports",
            EdgeKind::Defines => "defines",
            EdgeKind::Calls => "calls",
            EdgeKind::RoutesTo => "routes_to",
            EdgeKind::GuardedBy => "guarded_by",
            EdgeKind::Authenticates => "authenticates",
            EdgeKind::Authorises => "authorises",
            EdgeKind::Reads => "reads",
            EdgeKind::Writes => "writes",
            EdgeKind::Queries => "queries",
            EdgeKind::FlowsTo => "flows_to",
            EdgeKind::DependsOn => "depends_on",
            EdgeKind::FindingAt => "finding_at",
            EdgeKind::Supports => "supports",
            EdgeKind::EvidenceFor => "evidence_for",
        }
    }

    /// Edges worth following when tracing reachability from an entry point.
    ///
    /// Containment and evidence edges are excluded: they connect everything to everything
    /// and would turn a bounded walk into a full table scan.
    pub fn is_traversable(self) -> bool {
        matches!(
            self,
            EdgeKind::Calls
                | EdgeKind::RoutesTo
                | EdgeKind::FlowsTo
                | EdgeKind::Queries
                | EdgeKind::Reads
                | EdgeKind::Writes
        )
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EdgeKind {
    type Err = quoll_core::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "contains" => EdgeKind::Contains,
            "imports" => EdgeKind::Imports,
            "defines" => EdgeKind::Defines,
            "calls" => EdgeKind::Calls,
            "routes_to" => EdgeKind::RoutesTo,
            "guarded_by" => EdgeKind::GuardedBy,
            "authenticates" => EdgeKind::Authenticates,
            "authorises" => EdgeKind::Authorises,
            "reads" => EdgeKind::Reads,
            "writes" => EdgeKind::Writes,
            "queries" => EdgeKind::Queries,
            "flows_to" => EdgeKind::FlowsTo,
            "depends_on" => EdgeKind::DependsOn,
            "finding_at" => EdgeKind::FindingAt,
            "supports" => EdgeKind::Supports,
            "evidence_for" => EdgeKind::EvidenceFor,
            other => {
                return Err(quoll_core::Error::Graph(format!(
                    "unknown edge kind `{other}`"
                )))
            }
        })
    }
}

/// A vertex in the code graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    /// Display name: the function name, the route path, the dependency name.
    pub name: String,
    /// Repository-relative path, absent for nodes with no single home (a dependency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    /// Kind-specific attributes: HTTP method for a route, table name for a query.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

impl Node {
    /// Build a node whose identity derives from its kind and natural key.
    pub fn new(kind: NodeKind, key: &str, name: impl Into<String>) -> Node {
        Node {
            id: NodeId::new(kind, key),
            kind,
            name: name.into(),
            path: None,
            span: None,
            language: None,
            attributes: serde_json::Map::new(),
        }
    }

    /// A node anchored at a source location. The path is part of the natural key.
    pub fn at(kind: NodeKind, path: &Path, name: impl Into<String>) -> Node {
        let name = name.into();
        let key = format!("{}::{name}", path.display());
        Node {
            id: NodeId::new(kind, &key),
            kind,
            name,
            path: Some(path.to_path_buf()),
            span: None,
            language: Language::from_path(path),
            attributes: serde_json::Map::new(),
        }
    }

    pub fn with_span(mut self, span: Span) -> Node {
        self.span = Some(span);
        self
    }

    pub fn with_language(mut self, language: Language) -> Node {
        self.language = Some(language);
        self
    }

    pub fn with_attribute(mut self, key: &str, value: impl Into<serde_json::Value>) -> Node {
        self.attributes.insert(key.to_string(), value.into());
        self
    }

    pub fn attribute(&self, key: &str) -> Option<&serde_json::Value> {
        self.attributes.get(key)
    }

    pub fn attribute_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(|v| v.as_str())
    }

    /// `path:line` for terminal and report output.
    pub fn location_label(&self) -> String {
        match (&self.path, &self.span) {
            (Some(path), Some(span)) => format!("{}:{span}", path.display()),
            (Some(path), None) => path.display().to_string(),
            (None, _) => self.name.clone(),
        }
    }
}

/// A directed relationship between two nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    /// The file that justified this edge, so stale edges can be deleted when it changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,
}

impl Edge {
    pub fn new(from: NodeId, to: NodeId, kind: EdgeKind) -> Edge {
        Edge {
            from,
            to,
            kind,
            path: None,
            span: None,
        }
    }

    pub fn at(mut self, path: impl Into<PathBuf>, span: Span) -> Edge {
        self.path = Some(path.into());
        self.span = Some(span);
        self
    }

    pub fn in_file(mut self, path: impl Into<PathBuf>) -> Edge {
        self.path = Some(path.into());
        self
    }
}

/// What a parsed declaration is, before it is promoted to a semantic node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Struct,
    Interface,
    Enum,
    Trait,
    Module,
    Constant,
    Variable,
    Import,
    TypeAlias,
}

impl SymbolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SymbolKind::Function => "function",
            SymbolKind::Method => "method",
            SymbolKind::Class => "class",
            SymbolKind::Struct => "struct",
            SymbolKind::Interface => "interface",
            SymbolKind::Enum => "enum",
            SymbolKind::Trait => "trait",
            SymbolKind::Module => "module",
            SymbolKind::Constant => "constant",
            SymbolKind::Variable => "variable",
            SymbolKind::Import => "import",
            SymbolKind::TypeAlias => "type_alias",
        }
    }

    /// Whether this declaration can contain executable statements.
    pub fn is_callable(self) -> bool {
        matches!(self, SymbolKind::Function | SymbolKind::Method)
    }

    /// The node kind this symbol becomes in the graph.
    pub fn node_kind(self) -> NodeKind {
        match self {
            SymbolKind::Method => NodeKind::Method,
            SymbolKind::Function => NodeKind::Function,
            SymbolKind::Module => NodeKind::Module,
            _ => NodeKind::Module,
        }
    }
}

impl FromStr for SymbolKind {
    type Err = quoll_core::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "function" => SymbolKind::Function,
            "method" => SymbolKind::Method,
            "class" => SymbolKind::Class,
            "struct" => SymbolKind::Struct,
            "interface" => SymbolKind::Interface,
            "enum" => SymbolKind::Enum,
            "trait" => SymbolKind::Trait,
            "module" => SymbolKind::Module,
            "constant" => SymbolKind::Constant,
            "variable" => SymbolKind::Variable,
            "import" => SymbolKind::Import,
            "type_alias" => SymbolKind::TypeAlias,
            other => {
                return Err(quoll_core::Error::Graph(format!(
                    "unknown symbol kind `{other}`"
                )))
            }
        })
    }
}

/// A declaration found by the parser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub path: PathBuf,
    pub span: Span,
    /// Enclosing declaration, e.g. the `impl` block or class a method belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Whether the declaration is visible outside its module.
    #[serde(default)]
    pub exported: bool,
}

impl Symbol {
    pub fn new(name: impl Into<String>, kind: SymbolKind, path: impl Into<PathBuf>, span: Span) -> Symbol {
        Symbol {
            name: name.into(),
            kind,
            path: path.into(),
            span,
            container: None,
            exported: false,
        }
    }

    pub fn in_container(mut self, container: impl Into<String>) -> Symbol {
        self.container = Some(container.into());
        self
    }

    pub fn exported(mut self, exported: bool) -> Symbol {
        self.exported = exported;
        self
    }

    /// Fully qualified name: `Container::name` when there is a container.
    pub fn qualified_name(&self) -> String {
        match &self.container {
            Some(container) => format!("{container}::{}", self.name),
            None => self.name.clone(),
        }
    }

    /// The graph node this symbol becomes.
    pub fn to_node(&self) -> Node {
        Node::at(self.kind.node_kind(), &self.path, self.qualified_name())
            .with_span(self.span)
    }
}

/// A file as the graph knows it, with the hash that decides whether to reparse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    pub indexed_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ids_are_stable_across_construction() {
        let a = Node::at(NodeKind::Function, Path::new("src/main.rs"), "handler");
        let b = Node::at(NodeKind::Function, Path::new("src/main.rs"), "handler");
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn node_ids_separate_kinds_at_the_same_location() {
        let function = Node::at(NodeKind::Function, Path::new("a.rs"), "x");
        let route = Node::at(NodeKind::Route, Path::new("a.rs"), "x");
        assert_ne!(function.id, route.id);
    }

    #[test]
    fn node_ids_carry_a_readable_prefix() {
        let node = Node::at(NodeKind::Route, Path::new("a.rs"), "x");
        assert!(node.id.as_str().starts_with("route-"), "{}", node.id);
    }

    #[test]
    fn kinds_round_trip_through_strings() {
        for kind in [
            NodeKind::Repository,
            NodeKind::AuthorisationGuard,
            NodeKind::ProcessExecution,
            NodeKind::SecurityControl,
        ] {
            assert_eq!(NodeKind::from_str(kind.as_str()).unwrap(), kind);
        }
        for kind in [EdgeKind::Contains, EdgeKind::RoutesTo, EdgeKind::EvidenceFor] {
            assert_eq!(EdgeKind::from_str(kind.as_str()).unwrap(), kind);
        }
    }

    #[test]
    fn unknown_kinds_are_rejected_rather_than_defaulted() {
        assert!(NodeKind::from_str("nonsense").is_err());
        assert!(EdgeKind::from_str("nonsense").is_err());
    }

    #[test]
    fn containment_edges_are_not_traversed() {
        assert!(!EdgeKind::Contains.is_traversable());
        assert!(!EdgeKind::EvidenceFor.is_traversable());
        assert!(EdgeKind::Calls.is_traversable());
    }

    #[test]
    fn symbols_qualify_names_with_their_container() {
        let symbol = Symbol::new("create", SymbolKind::Method, "src/db.rs", Span::line(4))
            .in_container("UserRepo");
        assert_eq!(symbol.qualified_name(), "UserRepo::create");
        assert_eq!(symbol.to_node().kind, NodeKind::Method);
    }

    #[test]
    fn nodes_infer_language_from_their_path() {
        let node = Node::at(NodeKind::Function, Path::new("app/page.tsx"), "Page");
        assert_eq!(node.language, Some(Language::Tsx));
    }
}
