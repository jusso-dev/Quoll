//! Bounded traversal.
//!
//! Every walk here is capped on depth, visited nodes and returned paths. Nothing in this
//! module can run unbounded, because the graph is built from untrusted repositories and a
//! pathological one — generated code, a cyclic dependency web — must degrade into a
//! truncated answer rather than an unresponsive scan.

use std::collections::{HashMap, HashSet, VecDeque};

use quoll_core::Result;
use serde::{Deserialize, Serialize};

use crate::model::{Edge, EdgeKind, Node, NodeId, NodeKind};
use crate::store::GraphOps;

/// Caps applied to a traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum edges followed from the start node.
    pub max_depth: usize,
    /// Maximum nodes visited before the walk stops early.
    pub max_nodes: usize,
    /// Maximum paths returned by a path search.
    pub max_paths: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // Tuned for the evidence bundles sent to a model: deep enough to cross a
        // route → service → repository layering, shallow enough that the result still
        // fits in a prompt.
        Limits {
            max_depth: 6,
            max_nodes: 2_000,
            max_paths: 10,
        }
    }
}

impl Limits {
    pub fn depth(mut self, depth: usize) -> Limits {
        self.max_depth = depth;
        self
    }

    pub fn nodes(mut self, nodes: usize) -> Limits {
        self.max_nodes = nodes;
        self
    }

    pub fn paths(mut self, paths: usize) -> Limits {
        self.max_paths = paths;
        self
    }
}

/// A route from one node to another, with the relationship taken at each step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphPath {
    pub nodes: Vec<Node>,
    pub edges: Vec<EdgeKind>,
}

impl GraphPath {
    /// Number of edges traversed.
    pub fn length(&self) -> usize {
        self.edges.len()
    }

    pub fn start(&self) -> Option<&Node> {
        self.nodes.first()
    }

    pub fn end(&self) -> Option<&Node> {
        self.nodes.last()
    }

    /// `a -calls-> b -queries-> c`, the form reports and prompts render.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        for (index, node) in self.nodes.iter().enumerate() {
            if index > 0 {
                out.push_str(&format!(" -{}-> ", self.edges[index - 1]));
            }
            out.push_str(&node.name);
        }
        out
    }

    /// Whether any node on this path is a control of the given kind.
    pub fn passes_through(&self, kind: NodeKind) -> bool {
        self.nodes.iter().any(|node| node.kind == kind)
    }
}

/// The result of a traversal, including whether it was cut short.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Traversal {
    pub nodes: Vec<Node>,
    /// True when a limit stopped the walk. Callers must not report the result as complete.
    pub truncated: bool,
}

/// Direction to follow edges in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Follow `from → to`: what this node reaches.
    Forward,
    /// Follow `to → from`: what reaches this node.
    Reverse,
}

/// Nodes reachable from `start`, breadth-first, within `limits`.
///
/// Only edges [`EdgeKind::is_traversable`] accepts are followed, so containment and
/// evidence edges cannot turn the walk into a scan of the whole graph.
pub fn reachable<G: GraphOps>(
    graph: &G,
    start: &NodeId,
    direction: Direction,
    limits: Limits,
) -> Result<Traversal> {
    let mut seen: HashSet<NodeId> = HashSet::from([start.clone()]);
    let mut queue: VecDeque<(NodeId, usize)> = VecDeque::from([(start.clone(), 0)]);
    let mut out = Traversal::default();

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= limits.max_depth {
            // Reaching the depth cap is only a truncation if this node had somewhere left
            // to go; checking that is cheaper than reporting a false truncation.
            if !neighbours(graph, &current, direction)?.is_empty() {
                out.truncated = true;
            }
            continue;
        }
        for (next, _) in neighbours(graph, &current, direction)? {
            if !seen.insert(next.clone()) {
                continue;
            }
            if seen.len() > limits.max_nodes {
                out.truncated = true;
                return Ok(out);
            }
            if let Some(node) = graph.node(&next)? {
                out.nodes.push(node);
            }
            queue.push_back((next, depth + 1));
        }
    }
    Ok(out)
}

/// Shortest paths from `start` to nodes of `target`, up to `limits.max_paths`.
///
/// Breadth-first, so the first path found to any node is a shortest one. Only one path per
/// destination is returned: a second route to the same sink adds prompt tokens without
/// adding information.
pub fn paths_to_kind<G: GraphOps>(
    graph: &G,
    start: &NodeId,
    target: NodeKind,
    limits: Limits,
) -> Result<Vec<GraphPath>> {
    let mut parents: HashMap<NodeId, (NodeId, EdgeKind)> = HashMap::new();
    let mut seen: HashSet<NodeId> = HashSet::from([start.clone()]);
    let mut queue: VecDeque<(NodeId, usize)> = VecDeque::from([(start.clone(), 0)]);
    let mut found = Vec::new();

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= limits.max_depth || found.len() >= limits.max_paths {
            continue;
        }
        for (next, kind) in neighbours(graph, &current, Direction::Forward)? {
            if !seen.insert(next.clone()) {
                continue;
            }
            if seen.len() > limits.max_nodes {
                return Ok(found);
            }
            parents.insert(next.clone(), (current.clone(), kind));
            let node = match graph.node(&next)? {
                Some(node) => node,
                None => continue,
            };
            if node.kind == target {
                found.push(rebuild_path(graph, start, &next, &parents)?);
                if found.len() >= limits.max_paths {
                    return Ok(found);
                }
            }
            queue.push_back((next, depth + 1));
        }
    }
    Ok(found)
}

/// Entry points from which `sink` can be reached.
///
/// The question policy evaluation actually asks: not "what does this route touch" but
/// "can an outside caller get here at all".
pub fn entry_points_reaching<G: GraphOps>(
    graph: &G,
    sink: &NodeId,
    limits: Limits,
) -> Result<Vec<Node>> {
    let upstream = reachable(graph, sink, Direction::Reverse, limits)?;
    Ok(upstream
        .nodes
        .into_iter()
        .filter(|node| node.kind.is_entry_point())
        .collect())
}

/// Sinks reachable from an entry point, grouped with the path that gets there.
pub fn sinks_from<G: GraphOps>(
    graph: &G,
    entry: &NodeId,
    limits: Limits,
) -> Result<Vec<GraphPath>> {
    let mut paths = Vec::new();
    for kind in [
        NodeKind::DatabaseOperation,
        NodeKind::ProcessExecution,
        NodeKind::FilesystemOperation,
        NodeKind::ExternalRequest,
        NodeKind::Secret,
    ] {
        if paths.len() >= limits.max_paths {
            break;
        }
        let remaining = limits.max_paths - paths.len();
        paths.extend(paths_to_kind(graph, entry, kind, limits.paths(remaining))?);
    }
    Ok(paths)
}

/// Direct callers of a node, one hop back.
pub fn callers<G: GraphOps>(graph: &G, node: &NodeId) -> Result<Vec<Node>> {
    let mut out = Vec::new();
    for edge in graph.edges_to(node)? {
        if edge.kind == EdgeKind::Calls {
            if let Some(caller) = graph.node(&edge.from)? {
                out.push(caller);
            }
        }
    }
    Ok(out)
}

fn neighbours<G: GraphOps>(
    graph: &G,
    node: &NodeId,
    direction: Direction,
) -> Result<Vec<(NodeId, EdgeKind)>> {
    let edges: Vec<Edge> = match direction {
        Direction::Forward => graph.edges_from(node)?,
        Direction::Reverse => graph.edges_to(node)?,
    };
    Ok(edges
        .into_iter()
        .filter(|edge| edge.kind.is_traversable())
        .map(|edge| match direction {
            Direction::Forward => (edge.to, edge.kind),
            Direction::Reverse => (edge.from, edge.kind),
        })
        .collect())
}

fn rebuild_path<G: GraphOps>(
    graph: &G,
    start: &NodeId,
    end: &NodeId,
    parents: &HashMap<NodeId, (NodeId, EdgeKind)>,
) -> Result<GraphPath> {
    let mut ids = vec![end.clone()];
    let mut kinds = Vec::new();
    let mut current = end.clone();
    while current != *start {
        let (parent, kind) = match parents.get(&current) {
            Some(entry) => entry.clone(),
            None => break,
        };
        ids.push(parent.clone());
        kinds.push(kind);
        current = parent;
    }
    ids.reverse();
    kinds.reverse();

    let mut nodes = Vec::with_capacity(ids.len());
    for id in &ids {
        if let Some(node) = graph.node(id)? {
            nodes.push(node);
        }
    }
    Ok(GraphPath {
        nodes,
        edges: kinds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Edge;
    use crate::store::Graph;
    use quoll_core::Span;
    use std::path::Path;

    /// route → handler → service → query, plus an unrelated branch.
    fn chain() -> (Graph, Vec<Node>) {
        let graph = Graph::open_in_memory().unwrap();
        let nodes = vec![
            Node::at(NodeKind::Route, Path::new("src/api.rs"), "POST /users"),
            Node::at(NodeKind::Function, Path::new("src/api.rs"), "create_user"),
            Node::at(NodeKind::Function, Path::new("src/svc.rs"), "insert_user"),
            Node::at(NodeKind::DatabaseOperation, Path::new("src/db.rs"), "insert"),
        ];
        for node in &nodes {
            graph.upsert_node(node).unwrap();
        }
        graph
            .upsert_edge(&Edge::new(
                nodes[0].id.clone(),
                nodes[1].id.clone(),
                EdgeKind::RoutesTo,
            ))
            .unwrap();
        graph
            .upsert_edge(&Edge::new(
                nodes[1].id.clone(),
                nodes[2].id.clone(),
                EdgeKind::Calls,
            ))
            .unwrap();
        graph
            .upsert_edge(&Edge::new(
                nodes[2].id.clone(),
                nodes[3].id.clone(),
                EdgeKind::Queries,
            ))
            .unwrap();
        (graph, nodes)
    }

    #[test]
    fn reaches_the_whole_chain_forward() {
        let (graph, nodes) = chain();
        let found = reachable(&graph, &nodes[0].id, Direction::Forward, Limits::default()).unwrap();
        let names: Vec<&str> = found.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["create_user", "insert_user", "insert"]);
        assert!(!found.truncated);
    }

    #[test]
    fn depth_limit_truncates_and_says_so() {
        let (graph, nodes) = chain();
        let found = reachable(
            &graph,
            &nodes[0].id,
            Direction::Forward,
            Limits::default().depth(1),
        )
        .unwrap();
        assert_eq!(found.nodes.len(), 1);
        assert!(found.truncated);
    }

    #[test]
    fn node_limit_truncates() {
        let (graph, nodes) = chain();
        let found = reachable(
            &graph,
            &nodes[0].id,
            Direction::Forward,
            Limits::default().nodes(2),
        )
        .unwrap();
        assert!(found.truncated);
    }

    #[test]
    fn containment_edges_are_not_followed() {
        let graph = Graph::open_in_memory().unwrap();
        let file = Node::at(NodeKind::File, Path::new("src/a.rs"), "a.rs");
        let function = Node::at(NodeKind::Function, Path::new("src/a.rs"), "f");
        graph.upsert_node(&file).unwrap();
        graph.upsert_node(&function).unwrap();
        graph
            .upsert_edge(&Edge::new(
                file.id.clone(),
                function.id.clone(),
                EdgeKind::Contains,
            ))
            .unwrap();

        let found = reachable(&graph, &file.id, Direction::Forward, Limits::default()).unwrap();
        assert!(found.nodes.is_empty());
        assert!(!found.truncated);
    }

    #[test]
    fn reverse_traversal_finds_entry_points() {
        let (graph, nodes) = chain();
        let entries = entry_points_reaching(&graph, &nodes[3].id, Limits::default()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "POST /users");
    }

    #[test]
    fn paths_carry_the_edge_kinds_taken() {
        let (graph, nodes) = chain();
        let paths = paths_to_kind(
            &graph,
            &nodes[0].id,
            NodeKind::DatabaseOperation,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].length(), 3);
        assert_eq!(
            paths[0].describe(),
            "POST /users -routes_to-> create_user -calls-> insert_user -queries-> insert"
        );
        assert_eq!(paths[0].end().unwrap().name, "insert");
    }

    #[test]
    fn cycles_terminate() {
        let graph = Graph::open_in_memory().unwrap();
        let ring: Vec<Node> = ["a", "b", "c"]
            .iter()
            .map(|name| {
                Node::at(NodeKind::Function, Path::new("ring.rs"), *name).with_span(Span::line(1))
            })
            .collect();
        for node in &ring {
            graph.upsert_node(node).unwrap();
        }
        for index in 0..ring.len() {
            let next = (index + 1) % ring.len();
            graph
                .upsert_edge(&Edge::new(
                    ring[index].id.clone(),
                    ring[next].id.clone(),
                    EdgeKind::Calls,
                ))
                .unwrap();
        }

        // The start node is not re-emitted when the cycle closes back onto it.
        let found = reachable(&graph, &ring[0].id, Direction::Forward, Limits::default()).unwrap();
        assert_eq!(
            found.nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            vec!["b", "c"]
        );
        assert!(!found.truncated);
    }

    #[test]
    fn path_search_respects_the_path_cap() {
        let graph = Graph::open_in_memory().unwrap();
        let entry = Node::at(NodeKind::Route, Path::new("api.rs"), "GET /");
        graph.upsert_node(&entry).unwrap();
        for index in 0..5 {
            let sink = Node::at(
                NodeKind::DatabaseOperation,
                Path::new("db.rs"),
                format!("q{index}"),
            );
            graph.upsert_node(&sink).unwrap();
            graph
                .upsert_edge(&Edge::new(entry.id.clone(), sink.id.clone(), EdgeKind::Queries))
                .unwrap();
        }
        let paths = paths_to_kind(
            &graph,
            &entry.id,
            NodeKind::DatabaseOperation,
            Limits::default().paths(2),
        )
        .unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn direct_callers_are_one_hop_back() {
        let (graph, nodes) = chain();
        let found = callers(&graph, &nodes[2].id).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "create_user");
    }

    #[test]
    fn sinks_from_an_entry_point_cover_every_sink_kind() {
        let (graph, nodes) = chain();
        let paths = sinks_from(&graph, &nodes[0].id, Limits::default()).unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].passes_through(NodeKind::DatabaseOperation));
    }
}
