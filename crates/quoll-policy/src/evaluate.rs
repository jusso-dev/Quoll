use quoll_core::{Confidence, Evidence, EvidenceSource, Location, Result, Severity};
use quoll_detect::{Detection, Role};
use quoll_graph::{EdgeKind, GraphOps, Node, NodeId};
use serde::{Deserialize, Serialize};

use crate::pack::{Applicability, Condition, Invariant, Pack, Requirement, Selector};

/// Whether a node met an invariant.
///
/// There is no "unknown". A selector either matched a node or it did not, and a matched
/// node either satisfies the requirement or does not — evaluation is a pure function of the
/// graph, and a policy that could answer "maybe" would be reporting a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Satisfied,
    Violated,
}

/// One invariant judged against one node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub pack: String,
    pub invariant: String,
    pub title: String,
    pub severity: Severity,
    pub status: Status,
    pub node: NodeId,
    pub node_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// What the invariant expected and did not find. Empty when satisfied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Outcome {
    pub fn is_violation(&self) -> bool {
        self.status == Status::Violated
    }

    pub fn control_id(&self) -> String {
        format!("{}/{}", self.pack, self.invariant)
    }

    /// One sentence naming the node and what it lacks.
    pub fn describe(&self) -> String {
        match self.status {
            Status::Satisfied => format!("`{}` satisfies {}", self.node_name, self.control_id()),
            Status::Violated => format!(
                "`{}` does not have {}",
                self.node_name,
                self.missing.join(" or ")
            ),
        }
    }

    /// Turn this outcome into evidence a hypothesis can cite.
    ///
    /// A satisfied invariant is refuting evidence, not silence: a route that *is* guarded is
    /// the strongest argument against a report that it is not.
    pub fn to_evidence(&self) -> Evidence {
        let source = EvidenceSource::Policy {
            pack: self.pack.clone(),
            control: self.invariant.clone(),
        };
        let evidence = match self.status {
            Status::Violated => Evidence::supporting(source, self.describe(), Confidence::new(0.9)),
            Status::Satisfied => Evidence::refuting(source, self.describe(), Confidence::new(0.9)),
        };
        match &self.location {
            Some(location) => evidence.at(location.clone()),
            None => evidence,
        }
    }
}

/// Why a pack did not run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Skipped {
    pub pack: String,
    pub reason: String,
}

/// The result of evaluating every pack against a graph.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub outcomes: Vec<Outcome>,
    pub packs_applied: Vec<String>,
    /// Packs that did not apply, and why. Recorded so `quoll policy list` can answer
    /// "why wasn't my pack used?" without a debug build.
    pub packs_skipped: Vec<Skipped>,
    pub nodes_evaluated: usize,
}

impl Report {
    pub fn violations(&self) -> impl Iterator<Item = &Outcome> {
        self.outcomes.iter().filter(|o| o.is_violation())
    }

    pub fn satisfied(&self) -> impl Iterator<Item = &Outcome> {
        self.outcomes.iter().filter(|o| !o.is_violation())
    }

    pub fn violation_count(&self) -> usize {
        self.violations().count()
    }

    /// Highest severity among violations.
    pub fn worst_severity(&self) -> Option<Severity> {
        self.violations().map(|o| o.severity).max()
    }

    pub fn summary(&self) -> String {
        format!(
            "{} pack(s), {} node(s) evaluated, {} violation(s)",
            self.packs_applied.len(),
            self.nodes_evaluated,
            self.violation_count()
        )
    }
}

/// Evaluate every applicable pack against the graph.
///
/// Deterministic by construction: node selection comes back from the graph in a stable
/// order, and outcomes are sorted before returning, so two runs over the same commit
/// produce byte-identical results.
pub fn evaluate<G: GraphOps>(
    graph: &G,
    packs: &[Pack],
    detection: &Detection,
) -> Result<Report> {
    let mut report = Report::default();

    for pack in packs {
        match applicability_reason(&pack.applies_when, detection) {
            Some(reason) => {
                report.packs_skipped.push(Skipped {
                    pack: pack.id.clone(),
                    reason,
                });
                continue;
            }
            None => report.packs_applied.push(pack.id.clone()),
        }

        for invariant in &pack.invariants {
            let nodes = select(graph, &invariant.applies_to)?;
            report.nodes_evaluated += nodes.len();
            for node in nodes {
                report.outcomes.push(judge(graph, pack, invariant, &node)?);
            }
        }
    }

    report.outcomes.sort_by(|a, b| {
        a.pack
            .cmp(&b.pack)
            .then(a.invariant.cmp(&b.invariant))
            .then(a.node.as_str().cmp(b.node.as_str()))
    });
    report.packs_applied.sort();
    report.packs_skipped.sort();
    Ok(report)
}

/// Why a pack does not apply, or `None` when it does.
fn applicability_reason(applicability: &Applicability, detection: &Detection) -> Option<String> {
    if applicability.is_unconditional() {
        return None;
    }
    for condition in &applicability.all {
        if let Some(reason) = unmet(condition, detection) {
            return Some(reason);
        }
    }
    if !applicability.any.is_empty()
        && applicability
            .any
            .iter()
            .all(|condition| unmet(condition, detection).is_some())
    {
        return Some("none of the `any` conditions matched".to_string());
    }
    None
}

/// Why one condition is not met, or `None` when it is.
fn unmet(condition: &Condition, detection: &Detection) -> Option<String> {
    // An empty condition matches everything, which is almost certainly an authoring
    // mistake — but refusing to evaluate is the pack author's problem, not the user's.
    if condition.is_empty() {
        return None;
    }

    let mut named: Option<&str> = None;

    for (field, id, role) in [
        ("framework", &condition.framework, Some(Role::Framework)),
        ("auth", &condition.auth, Some(Role::Auth)),
        ("orm", &condition.orm, Some(Role::Orm)),
        ("component", &condition.component, None),
    ] {
        let id = match id {
            Some(id) => id,
            None => continue,
        };
        named = Some(id);
        let found = detection.get(id).filter(|component| match role {
            Some(role) => component.role == role,
            None => true,
        });
        if found.is_none() {
            return Some(format!("no {field} `{id}` detected"));
        }
    }

    if let Some(language) = &condition.language {
        // `Language::from_str` is infallible: an unrecognised name becomes `Other`, which
        // then simply fails to match anything the repository actually contains.
        let wanted: quoll_core::Language = language.parse().unwrap_or(quoll_core::Language::Other(language.clone()));
        if !detection.languages.iter().any(|(l, _)| *l == wanted) {
            return Some(format!("no {language} in this repository"));
        }
    }

    if let Some(ecosystem) = &condition.ecosystem {
        if !detection
            .ecosystems
            .iter()
            .any(|e| e.as_str() == ecosystem.as_str())
        {
            return Some(format!("no {ecosystem} ecosystem detected"));
        }
    }

    if let Some(minimum) = condition.min_version {
        let id = named?;
        let component = detection.get(id)?;
        match component.major_version() {
            Some(major) if major >= minimum => {}
            // An unknown version is treated as satisfying the floor. Refusing to evaluate
            // because a workspace-inherited dependency has no literal version would silently
            // disable policy on real repositories.
            None => {}
            Some(major) => {
                return Some(format!(
                    "`{id}` is major version {major}, pack needs {minimum} or newer"
                ))
            }
        }
    }

    None
}

/// Nodes an invariant judges.
fn select<G: GraphOps>(graph: &G, selector: &Selector) -> Result<Vec<Node>> {
    let mut nodes = graph.nodes_of_kind(selector.node_kind)?;

    nodes.retain(|node| {
        if !selector.methods.is_empty() {
            let method = node.attribute_str("method").unwrap_or_default();
            if !selector
                .methods
                .iter()
                .any(|wanted| wanted.eq_ignore_ascii_case(method))
            {
                return false;
            }
        }
        if !selector.operations.is_empty() {
            let operation = node.attribute_str("operation").unwrap_or_default();
            if !selector
                .operations
                .iter()
                .any(|wanted| wanted.eq_ignore_ascii_case(operation))
            {
                return false;
            }
        }
        if let Some(fragment) = &selector.path_contains {
            let path = node
                .path
                .as_ref()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            if !path.contains(fragment.as_str()) {
                return false;
            }
        }
        if let Some(fragment) = &selector.name_contains {
            if !node.name.contains(fragment.as_str()) {
                return false;
            }
        }
        true
    });

    Ok(nodes)
}

fn judge<G: GraphOps>(
    graph: &G,
    pack: &Pack,
    invariant: &Invariant,
    node: &Node,
) -> Result<Outcome> {
    let mut missing = Vec::new();

    if let Some(requirement) = &invariant.requires {
        if !meets(graph, node, requirement)? {
            missing.push(requirement.describe());
        }
    }
    for requirement in &invariant.requires_all {
        if !meets(graph, node, requirement)? {
            missing.push(requirement.describe());
        }
    }
    if !invariant.requires_any.is_empty() {
        let mut satisfied = false;
        for requirement in &invariant.requires_any {
            if meets(graph, node, requirement)? {
                satisfied = true;
                break;
            }
        }
        if !satisfied {
            // Reported as alternatives, so the message reads "does not have A or B".
            missing.extend(invariant.requires_any.iter().map(Requirement::describe));
        }
    }
    if let Some(forbidden) = &invariant.forbids {
        if meets(graph, node, forbidden)? {
            missing.push(format!("the absence of {}", forbidden.describe()));
        }
    }

    let status = if missing.is_empty() {
        Status::Satisfied
    } else {
        Status::Violated
    };

    Ok(Outcome {
        pack: pack.id.clone(),
        invariant: invariant.id.clone(),
        title: invariant.title.clone(),
        severity: invariant.severity,
        status,
        node: node.id.clone(),
        node_name: node.name.clone(),
        location: location_of(node),
        missing,
        remediation: invariant.remediation.clone(),
    })
}

fn meets<G: GraphOps>(graph: &G, node: &Node, requirement: &Requirement) -> Result<bool> {
    if let Some(edge) = requirement.edge {
        let satisfied = match requirement.target_kind {
            Some(kind) => graph.has_edge_to_kind(&node.id, edge, kind)?,
            None => has_edge(graph, &node.id, edge)?,
        };
        if !satisfied {
            return Ok(false);
        }
    }

    if let Some(field) = &requirement.predicate_field {
        if !has_predicate(node, field) {
            return Ok(false);
        }
    }

    if let Some(attribute) = &requirement.attribute {
        match (node.attribute(attribute), &requirement.attribute_equals) {
            (None, _) => return Ok(false),
            (Some(value), Some(expected)) => {
                let actual = value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string());
                if !actual.eq_ignore_ascii_case(expected) {
                    return Ok(false);
                }
            }
            (Some(_), None) => {}
        }
    }

    Ok(true)
}

fn has_edge<G: GraphOps>(graph: &G, node: &NodeId, kind: EdgeKind) -> Result<bool> {
    Ok(graph.edges_from(node)?.iter().any(|e| e.kind == kind))
}

/// Whether a database operation is filtered by a column.
///
/// The `predicates` attribute is a list of column names appearing in the operation's
/// `where` clause, populated when the graph is enriched with framework knowledge. An
/// operation with no `predicates` attribute at all is unfiltered, which is exactly the case
/// a tenant-scoping invariant exists to catch.
fn has_predicate(node: &Node, field: &str) -> bool {
    match node.attribute("predicates") {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str())
            .any(|name| name.eq_ignore_ascii_case(field)),
        Some(serde_json::Value::String(single)) => single.eq_ignore_ascii_case(field),
        _ => false,
    }
}

fn location_of(node: &Node) -> Option<Location> {
    let path = node.path.as_ref()?;
    let mut location = Location::file(path.clone()).with_symbol(node.name.clone());
    if let Some(span) = node.span {
        location = location.with_span(span);
    }
    Some(location)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Confidence, Language};
    use quoll_detect::Component;
    use quoll_core::Span;
    use quoll_graph::{Edge, Graph, NodeKind};
    use std::path::Path;

    const PACK: &str = r#"
schema_version: 1
id: nextjs-better-auth-drizzle
version: 1.0.0
applies_when:
  all:
    - framework: nextjs-app-router
    - auth: better-auth
invariants:
  - id: authenticated-mutation
    title: State-changing routes require authentication
    severity: high
    remediation: Wrap the handler in the Better Auth session guard.
    applies_to:
      node_kind: route
      methods: [POST, PUT, PATCH, DELETE]
    requires:
      edge: guarded_by
      target_kind: auth_guard
  - id: tenant-scoped-write
    title: Tenant-owned writes must enforce tenant scope
    severity: high
    applies_to:
      node_kind: database_operation
      operations: [update, delete]
    requires_any:
      - predicate_field: organisation_id
      - predicate_field: tenant_id
"#;

    fn pack() -> Pack {
        Pack::parse(PACK).unwrap()
    }

    fn detection() -> Detection {
        Detection {
            components: vec![
                Component::new("nextjs-app-router", "Next.js App Router", Role::Framework)
                    .with_confidence(Confidence::CERTAIN)
                    .with_version(Some("^15.0.0".into())),
                Component::new("better-auth", "Better Auth", Role::Auth)
                    .with_confidence(Confidence::CERTAIN),
            ],
            languages: vec![(Language::TypeScript, 12)],
            ..Default::default()
        }
    }

    fn route(graph: &Graph, name: &str, method: &str, line: u32) -> Node {
        let node = Node::at(NodeKind::Route, Path::new("app/api/users/route.ts"), name)
            .with_attribute("method", method)
            .with_span(Span::line(line));
        graph.upsert_node(&node).unwrap();
        node
    }

    fn guard(graph: &Graph) -> Node {
        let node = Node::at(NodeKind::AuthGuard, Path::new("lib/auth.ts"), "requireSession");
        graph.upsert_node(&node).unwrap();
        node
    }

    fn db_op(graph: &Graph, name: &str, operation: &str, predicates: Vec<&str>) -> Node {
        let node = Node::at(NodeKind::DatabaseOperation, Path::new("src/db.ts"), name)
            .with_attribute("operation", operation)
            .with_attribute(
                "predicates",
                serde_json::Value::Array(
                    predicates.into_iter().map(serde_json::Value::from).collect(),
                ),
            );
        graph.upsert_node(&node).unwrap();
        node
    }

    #[test]
    fn an_unguarded_mutation_is_a_violation() {
        let graph = Graph::open_in_memory().unwrap();
        route(&graph, "POST /api/users", "POST", 4);

        let report = evaluate(&graph, &[pack()], &detection()).unwrap();
        let violations: Vec<&Outcome> = report.violations().collect();

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].invariant, "authenticated-mutation");
        assert_eq!(violations[0].severity, Severity::High);
        assert_eq!(violations[0].location.as_ref().unwrap().line(), 4);
        assert!(violations[0].remediation.is_some());
    }

    #[test]
    fn a_guarded_mutation_satisfies_the_invariant() {
        let graph = Graph::open_in_memory().unwrap();
        let route = route(&graph, "POST /api/users", "POST", 4);
        let guard = guard(&graph);
        graph
            .upsert_edge(&Edge::new(route.id.clone(), guard.id, EdgeKind::GuardedBy))
            .unwrap();

        let report = evaluate(&graph, &[pack()], &detection()).unwrap();
        assert_eq!(report.violation_count(), 0);
        assert_eq!(report.satisfied().count(), 1);
    }

    #[test]
    fn read_only_routes_are_not_selected() {
        let graph = Graph::open_in_memory().unwrap();
        route(&graph, "GET /api/users", "GET", 1);

        let report = evaluate(&graph, &[pack()], &detection()).unwrap();
        assert_eq!(report.outcomes.len(), 0, "GET must not be judged");
    }

    #[test]
    fn methods_match_case_insensitively() {
        let graph = Graph::open_in_memory().unwrap();
        route(&graph, "post /api/users", "post", 1);
        let report = evaluate(&graph, &[pack()], &detection()).unwrap();
        assert_eq!(report.violation_count(), 1);
    }

    #[test]
    fn an_unscoped_write_violates_the_tenant_invariant() {
        let graph = Graph::open_in_memory().unwrap();
        db_op(&graph, "update users", "update", vec!["id"]);

        let report = evaluate(&graph, &[pack()], &detection()).unwrap();
        let violation = report
            .violations()
            .find(|o| o.invariant == "tenant-scoped-write")
            .expect("violation");
        assert_eq!(violation.missing.len(), 2, "both alternatives are reported");
        assert!(violation.describe().contains("organisation_id"));
    }

    #[test]
    fn either_tenant_column_satisfies_the_invariant() {
        for column in ["organisation_id", "tenant_id"] {
            let graph = Graph::open_in_memory().unwrap();
            db_op(&graph, "update users", "update", vec!["id", column]);
            let report = evaluate(&graph, &[pack()], &detection()).unwrap();
            assert_eq!(report.violation_count(), 0, "{column} should satisfy");
        }
    }

    #[test]
    fn an_operation_with_no_predicates_at_all_is_a_violation() {
        let graph = Graph::open_in_memory().unwrap();
        let node = Node::at(NodeKind::DatabaseOperation, Path::new("src/db.ts"), "delete all")
            .with_attribute("operation", "delete");
        graph.upsert_node(&node).unwrap();

        let report = evaluate(&graph, &[pack()], &detection()).unwrap();
        assert_eq!(report.violation_count(), 1);
    }

    #[test]
    fn a_pack_whose_stack_is_absent_is_skipped_with_a_reason() {
        let graph = Graph::open_in_memory().unwrap();
        route(&graph, "POST /api/users", "POST", 1);

        let report = evaluate(&graph, &[pack()], &Detection::default()).unwrap();
        assert!(report.packs_applied.is_empty());
        assert_eq!(report.packs_skipped.len(), 1);
        assert!(
            report.packs_skipped[0].reason.contains("nextjs-app-router"),
            "{:?}",
            report.packs_skipped[0]
        );
        assert_eq!(report.outcomes.len(), 0);
    }

    #[test]
    fn a_component_in_the_wrong_role_does_not_satisfy_a_condition() {
        let mut detection = Detection::default();
        // Present, but recorded as a library rather than as the auth provider.
        detection.components.push(
            Component::new("better-auth", "Better Auth", Role::Library)
                .with_confidence(Confidence::CERTAIN),
        );
        detection.components.push(
            Component::new("nextjs-app-router", "Next.js App Router", Role::Framework)
                .with_confidence(Confidence::CERTAIN),
        );

        let graph = Graph::open_in_memory().unwrap();
        let report = evaluate(&graph, &[pack()], &detection).unwrap();
        assert_eq!(report.packs_skipped.len(), 1);
    }

    #[test]
    fn an_unconditional_pack_always_applies() {
        let text = r#"
schema_version: 1
id: baseline
version: 1.0.0
invariants:
  - id: x
    title: X
    severity: low
    applies_to: { node_kind: route }
    requires: { edge: guarded_by }
"#;
        let graph = Graph::open_in_memory().unwrap();
        let report = evaluate(&graph, &[Pack::parse(text).unwrap()], &Detection::default()).unwrap();
        assert_eq!(report.packs_applied, vec!["baseline"]);
    }

    #[test]
    fn min_version_gates_a_pack() {
        let text = r#"
schema_version: 1
id: modern-next
version: 1.0.0
applies_when:
  all:
    - framework: nextjs-app-router
      min_version: 99
invariants:
  - id: x
    title: X
    severity: low
    applies_to: { node_kind: route }
    requires: { edge: guarded_by }
"#;
        let graph = Graph::open_in_memory().unwrap();
        let report = evaluate(&graph, &[Pack::parse(text).unwrap()], &detection()).unwrap();
        assert!(report.packs_skipped[0].reason.contains("99"), "{:?}", report.packs_skipped);
    }

    #[test]
    fn a_forbidding_invariant_fires_when_the_edge_exists() {
        let text = r#"
schema_version: 1
id: no-direct-db
version: 1.0.0
invariants:
  - id: routes-must-not-query-directly
    title: Routes must not query the database directly
    severity: medium
    applies_to: { node_kind: route }
    forbids:
      edge: queries
      describe: a direct database query
"#;
        let graph = Graph::open_in_memory().unwrap();
        let route = route(&graph, "POST /api/users", "POST", 1);
        let query = db_op(&graph, "insert users", "insert", vec![]);
        graph
            .upsert_edge(&Edge::new(route.id.clone(), query.id, EdgeKind::Queries))
            .unwrap();

        let report = evaluate(&graph, &[Pack::parse(text).unwrap()], &Detection::default()).unwrap();
        assert_eq!(report.violation_count(), 1);
        assert!(report.violations().next().unwrap().missing[0].contains("absence"));
    }

    #[test]
    fn violations_become_supporting_evidence_and_passes_become_refuting() {
        let graph = Graph::open_in_memory().unwrap();
        let route = route(&graph, "POST /a", "POST", 1);
        route_with_guard(&graph, "POST /b", 2);

        let report = evaluate(&graph, &[pack()], &detection()).unwrap();
        let violation = report.violations().next().unwrap().to_evidence();
        let satisfied = report.satisfied().next().unwrap().to_evidence();

        assert_eq!(violation.kind, quoll_core::EvidenceKind::Supporting);
        assert_eq!(satisfied.kind, quoll_core::EvidenceKind::Refuting);
        assert!(violation.location.is_some());
        assert!(matches!(
            violation.source,
            EvidenceSource::Policy { .. }
        ));
        let _ = route;
    }

    fn route_with_guard(graph: &Graph, name: &str, line: u32) {
        let route = route(graph, name, "POST", line);
        let guard = guard(graph);
        graph
            .upsert_edge(&Edge::new(route.id, guard.id, EdgeKind::GuardedBy))
            .unwrap();
    }

    #[test]
    fn evaluation_is_deterministic() {
        let graph = Graph::open_in_memory().unwrap();
        for index in 0..5 {
            route(&graph, &format!("POST /api/{index}"), "POST", index + 1);
        }
        let first = evaluate(&graph, &[pack()], &detection()).unwrap();
        let second = evaluate(&graph, &[pack()], &detection()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn the_report_summarises_itself() {
        let graph = Graph::open_in_memory().unwrap();
        route(&graph, "POST /a", "POST", 1);
        let report = evaluate(&graph, &[pack()], &detection()).unwrap();

        assert_eq!(report.worst_severity(), Some(Severity::High));
        assert!(report.summary().contains("1 violation"), "{}", report.summary());
    }

    #[test]
    fn path_and_name_filters_narrow_the_selection() {
        let text = r#"
schema_version: 1
id: admin-only
version: 1.0.0
invariants:
  - id: admin-routes-guarded
    title: Admin routes require authorisation
    severity: critical
    applies_to:
      node_kind: route
      path_contains: /admin/
    requires:
      edge: guarded_by
      target_kind: authorisation_guard
"#;
        let graph = Graph::open_in_memory().unwrap();
        graph
            .upsert_node(
                &Node::at(NodeKind::Route, Path::new("app/api/admin/route.ts"), "POST /admin")
                    .with_attribute("method", "POST"),
            )
            .unwrap();
        graph
            .upsert_node(
                &Node::at(NodeKind::Route, Path::new("app/api/public/route.ts"), "GET /public")
                    .with_attribute("method", "GET"),
            )
            .unwrap();

        let report = evaluate(&graph, &[Pack::parse(text).unwrap()], &Detection::default()).unwrap();
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.violations().next().unwrap().node_name, "POST /admin");
    }
}
