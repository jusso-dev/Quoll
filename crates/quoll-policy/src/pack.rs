use std::collections::BTreeSet;
use std::path::Path;

use quoll_core::{Error, Result, Severity};
use quoll_graph::{EdgeKind, NodeKind};
use serde::{Deserialize, Serialize};

/// Pack format this build understands.
///
/// A pack declaring a newer version is refused rather than read on a best-effort basis: a
/// silently-ignored `requires` clause turns an invariant that should fail into one that
/// quietly passes, which is the worst failure mode a security tool has.
pub const SCHEMA_VERSION: u32 = 1;

/// A set of security invariants that apply to one technology stack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub schema_version: u32,
    /// Stable identifier, e.g. `nextjs-better-auth-drizzle`.
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// When this pack is relevant. An empty condition set means "always".
    #[serde(default)]
    pub applies_when: Applicability,
    pub invariants: Vec<Invariant>,
}

impl Pack {
    pub fn parse(text: &str) -> Result<Pack> {
        let pack: Pack = serde_yaml_ng::from_str(text)
            .map_err(|err| Error::Policy(format!("could not parse policy pack: {err}")))?;
        pack.validate()?;
        Ok(pack)
    }

    pub fn load(path: &Path) -> Result<Pack> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path.to_path_buf(), e))?;
        Pack::parse(&text)
            .map_err(|err| Error::Policy(format!("{}: {err}", path.display())))
    }

    /// Reject packs that would evaluate to nothing, or to something unintended.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(Error::Policy(format!(
                "pack `{}` declares schema_version {} but this build supports {SCHEMA_VERSION}",
                self.id, self.schema_version
            )));
        }
        if self.id.trim().is_empty() {
            return Err(Error::Policy("pack id must not be empty".into()));
        }
        if self.invariants.is_empty() {
            return Err(Error::Policy(format!(
                "pack `{}` declares no invariants",
                self.id
            )));
        }

        let mut seen = BTreeSet::new();
        for invariant in &self.invariants {
            if !seen.insert(invariant.id.as_str()) {
                return Err(Error::Policy(format!(
                    "pack `{}` declares invariant `{}` more than once",
                    self.id, invariant.id
                )));
            }
            invariant.validate(&self.id)?;
        }
        Ok(())
    }

    pub fn invariant(&self, id: &str) -> Option<&Invariant> {
        self.invariants.iter().find(|i| i.id == id)
    }
}

/// Conditions under which a pack applies.
///
/// `all` must every match; `any` needs one. Both empty means the pack is unconditional,
/// which is how baseline packs that apply to every repository are expressed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<Condition>,
}

impl Applicability {
    pub fn is_unconditional(&self) -> bool {
        self.all.is_empty() && self.any.is_empty()
    }
}

/// One condition on the detected stack.
///
/// Every field is optional and all present fields must match, so
/// `{ framework: nextjs, min_version: 15 }` reads as one clause rather than two.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    /// Any detected component with this id, whatever role it plays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    /// Lowest major version of the named component that satisfies this condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<u32>,
}

impl Condition {
    pub fn is_empty(&self) -> bool {
        self.framework.is_none()
            && self.auth.is_none()
            && self.orm.is_none()
            && self.language.is_none()
            && self.ecosystem.is_none()
            && self.component.is_none()
    }
}

/// A single security expectation, checked against the code graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invariant {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// What to do about a violation. Rendered verbatim in reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Which graph nodes this invariant judges.
    pub applies_to: Selector,

    /// The selected node must satisfy this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<Requirement>,
    /// The selected node must satisfy at least one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_any: Vec<Requirement>,
    /// The selected node must satisfy every one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_all: Vec<Requirement>,
    /// The selected node must satisfy none of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbids: Option<Requirement>,
}

impl Invariant {
    fn validate(&self, pack: &str) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(Error::Policy(format!(
                "pack `{pack}` declares an invariant with no id"
            )));
        }
        if self.title.trim().is_empty() {
            return Err(Error::Policy(format!(
                "invariant `{pack}/{}` has no title; a violation with no title is unreportable",
                self.id
            )));
        }
        if self.requires.is_none()
            && self.requires_any.is_empty()
            && self.requires_all.is_empty()
            && self.forbids.is_none()
        {
            return Err(Error::Policy(format!(
                "invariant `{pack}/{}` states no requirement, so it can never fail",
                self.id
            )));
        }

        for requirement in self.requirements() {
            requirement.validate(pack, &self.id)?;
        }
        Ok(())
    }

    /// Every requirement clause, in evaluation order.
    pub fn requirements(&self) -> Vec<&Requirement> {
        self.requires
            .iter()
            .chain(&self.requires_any)
            .chain(&self.requires_all)
            .chain(&self.forbids)
            .collect()
    }

    /// Fully qualified name, e.g. `nextjs-app-router/authenticated-mutation`.
    pub fn qualified_id(&self, pack: &str) -> String {
        format!("{pack}/{}", self.id)
    }
}

/// Which nodes an invariant judges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub node_kind: NodeKind,
    /// HTTP methods, matched against the node's `method` attribute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Database operations, matched against the node's `operation` attribute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
    /// Substring the node's repository-relative path must contain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_contains: Option<String>,
    /// Substring the node's name must contain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_contains: Option<String>,
}

impl Selector {
    pub fn of(node_kind: NodeKind) -> Selector {
        Selector {
            node_kind,
            methods: Vec::new(),
            operations: Vec::new(),
            path_contains: None,
            name_contains: None,
        }
    }
}

/// One condition a selected node must meet.
///
/// The fields are alternatives, not a conjunction of unrelated ideas: a requirement either
/// asks for an edge, or for a query predicate, or for an attribute value.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    /// An outgoing edge of this kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<EdgeKind>,
    /// The edge must land on a node of this kind. Requires `edge`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<NodeKind>,
    /// A column named in the operation's `predicates` attribute — how "this update is
    /// scoped to a tenant" is expressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_field: Option<String>,
    /// An attribute that must be present on the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    /// Value that attribute must hold. Requires `attribute`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute_equals: Option<String>,
    /// Human phrasing used in the report when this requirement is unmet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub describe: Option<String>,
}

impl Requirement {
    fn validate(&self, pack: &str, invariant: &str) -> Result<()> {
        // Dependent-field errors are reported before the general one. A pack that sets
        // `target_kind` alone has made a specific mistake, and "states no condition" would
        // send the author looking in the wrong place.
        if self.target_kind.is_some() && self.edge.is_none() {
            return Err(Error::Policy(format!(
                "requirement in `{pack}/{invariant}` sets target_kind without edge"
            )));
        }
        if self.attribute_equals.is_some() && self.attribute.is_none() {
            return Err(Error::Policy(format!(
                "requirement in `{pack}/{invariant}` sets attribute_equals without attribute"
            )));
        }
        if self.edge.is_none() && self.predicate_field.is_none() && self.attribute.is_none() {
            return Err(Error::Policy(format!(
                "requirement in `{pack}/{invariant}` states no condition"
            )));
        }
        Ok(())
    }

    /// One clause of prose for a report.
    pub fn describe(&self) -> String {
        if let Some(described) = &self.describe {
            return described.clone();
        }
        if let Some(edge) = self.edge {
            return match self.target_kind {
                Some(kind) => format!("an outgoing `{edge}` edge to a `{kind}` node"),
                None => format!("an outgoing `{edge}` edge"),
            };
        }
        if let Some(field) = &self.predicate_field {
            return format!("the query to be filtered by `{field}`");
        }
        match (&self.attribute, &self.attribute_equals) {
            (Some(attribute), Some(value)) => format!("`{attribute}` to be `{value}`"),
            (Some(attribute), None) => format!("`{attribute}` to be set"),
            _ => "an unstated condition".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema_version: 1
id: test-pack
version: 1.0.0
invariants:
  - id: authenticated-mutation
    title: State-changing routes require authentication
    severity: high
    applies_to:
      node_kind: route
      methods: [POST, PUT, PATCH, DELETE]
    requires:
      edge: guarded_by
      target_kind: auth_guard
"#;

    #[test]
    fn parses_the_specified_pack_format() {
        let pack = Pack::parse(MINIMAL).unwrap();
        assert_eq!(pack.id, "test-pack");
        assert_eq!(pack.invariants.len(), 1);

        let invariant = pack.invariant("authenticated-mutation").unwrap();
        assert_eq!(invariant.severity, Severity::High);
        assert_eq!(invariant.applies_to.node_kind, NodeKind::Route);
        assert_eq!(invariant.applies_to.methods, vec!["POST", "PUT", "PATCH", "DELETE"]);

        let requires = invariant.requires.as_ref().unwrap();
        assert_eq!(requires.edge, Some(EdgeKind::GuardedBy));
        assert_eq!(requires.target_kind, Some(NodeKind::AuthGuard));
    }

    #[test]
    fn parses_applies_when_conditions() {
        let text = r#"
schema_version: 1
id: nextjs-better-auth-drizzle
version: 1.0.0
applies_when:
  all:
    - framework: nextjs-app-router
    - auth: better-auth
    - orm: drizzle
invariants:
  - id: x
    title: X
    severity: low
    applies_to: { node_kind: route }
    requires: { edge: guarded_by }
"#;
        let pack = Pack::parse(text).unwrap();
        assert_eq!(pack.applies_when.all.len(), 3);
        assert_eq!(
            pack.applies_when.all[0].framework.as_deref(),
            Some("nextjs-app-router")
        );
        assert_eq!(pack.applies_when.all[1].auth.as_deref(), Some("better-auth"));
        assert!(!pack.applies_when.is_unconditional());
    }

    #[test]
    fn parses_requires_any_predicates() {
        let text = r#"
schema_version: 1
id: p
version: 1.0.0
invariants:
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
        let pack = Pack::parse(text).unwrap();
        let invariant = &pack.invariants[0];
        assert_eq!(invariant.requires_any.len(), 2);
        assert_eq!(
            invariant.requires_any[0].predicate_field.as_deref(),
            Some("organisation_id")
        );
    }

    #[test]
    fn a_newer_schema_version_is_refused() {
        let text = MINIMAL.replace("schema_version: 1", "schema_version: 99");
        let err = Pack::parse(&text).unwrap_err();
        assert!(err.to_string().contains("this build supports"), "{err}");
    }

    #[test]
    fn an_invariant_with_no_requirement_is_refused() {
        let text = r#"
schema_version: 1
id: p
version: 1.0.0
invariants:
  - id: toothless
    title: Does nothing
    severity: low
    applies_to: { node_kind: route }
"#;
        let err = Pack::parse(text).unwrap_err();
        assert!(err.to_string().contains("can never fail"), "{err}");
    }

    #[test]
    fn duplicate_invariant_ids_are_refused() {
        let text = r#"
schema_version: 1
id: p
version: 1.0.0
invariants:
  - id: same
    title: A
    severity: low
    applies_to: { node_kind: route }
    requires: { edge: guarded_by }
  - id: same
    title: B
    severity: low
    applies_to: { node_kind: route }
    requires: { edge: guarded_by }
"#;
        let err = Pack::parse(text).unwrap_err();
        assert!(err.to_string().contains("more than once"), "{err}");
    }

    #[test]
    fn a_pack_with_no_invariants_is_refused() {
        let text = "schema_version: 1\nid: p\nversion: 1.0.0\ninvariants: []\n";
        assert!(Pack::parse(text).unwrap_err().to_string().contains("no invariants"));
    }

    #[test]
    fn target_kind_without_an_edge_is_refused() {
        let text = r#"
schema_version: 1
id: p
version: 1.0.0
invariants:
  - id: x
    title: X
    severity: low
    applies_to: { node_kind: route }
    requires: { target_kind: auth_guard }
"#;
        let err = Pack::parse(text).unwrap_err();
        assert!(err.to_string().contains("target_kind without edge"), "{err}");
    }

    #[test]
    fn unknown_keys_are_refused_rather_than_ignored() {
        let text = MINIMAL.replace("    requires:", "    reqiures:\n      edge: calls\n    requires:");
        assert!(Pack::parse(&text).is_err(), "a typo must not silently disable a check");
    }

    #[test]
    fn unknown_node_kinds_are_refused() {
        let text = MINIMAL.replace("node_kind: route", "node_kind: teapot");
        assert!(Pack::parse(&text).is_err());
    }

    #[test]
    fn requirements_describe_themselves_for_reports() {
        let edge = Requirement {
            edge: Some(EdgeKind::GuardedBy),
            target_kind: Some(NodeKind::AuthGuard),
            ..Default::default()
        };
        assert_eq!(
            edge.describe(),
            "an outgoing `guarded_by` edge to a `auth_guard` node"
        );

        let predicate = Requirement {
            predicate_field: Some("tenant_id".into()),
            ..Default::default()
        };
        assert_eq!(predicate.describe(), "the query to be filtered by `tenant_id`");

        let custom = Requirement {
            edge: Some(EdgeKind::GuardedBy),
            describe: Some("an authentication check".into()),
            ..Default::default()
        };
        assert_eq!(custom.describe(), "an authentication check");
    }

    #[test]
    fn a_pack_round_trips_through_yaml() {
        let pack = Pack::parse(MINIMAL).unwrap();
        let text = serde_yaml_ng::to_string(&pack).unwrap();
        assert_eq!(Pack::parse(&text).unwrap(), pack);
    }
}
