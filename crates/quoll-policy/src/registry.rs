use std::path::Path;

use quoll_core::config::Config;
use quoll_core::{Error, Result};
use quoll_detect::Detection;

use crate::pack::Pack;

/// Built-in packs, compiled into the binary.
///
/// Embedded rather than read from disk so that a single downloaded binary is a complete
/// installation. User-authored packs are loaded from `policies/` and from any directory
/// named in `policy.search_paths`.
const BUILTIN: &[(&str, &str)] = &[
    (
        "nextjs-app-router",
        include_str!("../policies/nextjs-app-router.yaml"),
    ),
    (
        "nextjs-better-auth-drizzle",
        include_str!("../policies/nextjs-better-auth-drizzle.yaml"),
    ),
    ("axum", include_str!("../policies/axum.yaml")),
    ("express", include_str!("../policies/express.yaml")),
];

/// Directory searched for user-authored packs, relative to the repository root.
pub const USER_POLICY_DIR: &str = "policies";

/// The packs available to an evaluation.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    packs: Vec<Pack>,
    /// Invariant ids switched off in configuration, as `pack/invariant`.
    disabled_controls: Vec<String>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry::default()
    }

    /// Every pack Quoll ships.
    ///
    /// A malformed built-in pack is a build defect, not a user problem, and the test suite
    /// catches it — but returning `Result` keeps the failure visible rather than panicking
    /// inside a scan.
    pub fn builtin() -> Result<Registry> {
        let mut registry = Registry::new();
        for (id, text) in BUILTIN {
            let pack = Pack::parse(text)
                .map_err(|err| Error::Policy(format!("built-in pack `{id}` is invalid: {err}")))?;
            registry.add(pack);
        }
        Ok(registry)
    }

    /// Built-in packs plus whatever the configuration points at.
    pub fn from_config(config: &Config) -> Result<Registry> {
        let mut registry = Registry::builtin()?;
        registry.disabled_controls = config.policy.disabled_controls.clone();

        // The repository's own `policies/` directory is searched without being configured:
        // a pack a user has written next to their code is one they mean to run.
        let default_dir = config.root.join(USER_POLICY_DIR);
        if default_dir.is_dir() {
            registry.load_dir(&default_dir)?;
        }
        for dir in &config.policy.search_paths {
            let dir = config.resolve(dir);
            if dir.is_dir() {
                registry.load_dir(&dir)?;
            } else {
                tracing::warn!(path = %dir.display(), "policy search path does not exist");
            }
        }

        registry.retain_configured(config);
        Ok(registry)
    }

    /// Add a pack. A later pack with the same id replaces an earlier one, which is how a
    /// user overrides a built-in without forking it.
    pub fn add(&mut self, pack: Pack) -> &mut Self {
        match self.packs.iter_mut().find(|p| p.id == pack.id) {
            Some(existing) => *existing = pack,
            None => self.packs.push(pack),
        }
        self
    }

    /// Load every `.yaml`/`.yml` pack in a directory. Returns how many were added.
    ///
    /// Not recursive: a policy directory is a flat set of packs, and descending would pick
    /// up fixtures and vendored copies.
    pub fn load_dir(&mut self, dir: &Path) -> Result<usize> {
        let entries = std::fs::read_dir(dir).map_err(|e| Error::io(dir.to_path_buf(), e))?;
        let mut paths: Vec<_> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && matches!(
                        path.extension().and_then(|e| e.to_str()),
                        Some("yaml" | "yml")
                    )
            })
            .collect();
        // Sorted so that two machines loading the same directory get the same override order.
        paths.sort();

        let mut loaded = 0;
        for path in paths {
            self.add(Pack::load(&path)?);
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Apply the allowlist and denylist from configuration.
    fn retain_configured(&mut self, config: &Config) {
        let allowed = &config.policy.packs;
        let denied = &config.policy.disabled;
        self.packs.retain(|pack| {
            if denied.iter().any(|id| id == &pack.id) {
                return false;
            }
            allowed.is_empty() || allowed.iter().any(|id| id == &pack.id)
        });

        // Drop individually disabled invariants, and then any pack left with none. An empty
        // pack would otherwise be reported as applied while checking nothing.
        for pack in &mut self.packs {
            let pack_id = pack.id.clone();
            pack.invariants.retain(|invariant| {
                !self
                    .disabled_controls
                    .iter()
                    .any(|disabled| *disabled == invariant.qualified_id(&pack_id) || *disabled == invariant.id)
            });
        }
        self.packs.retain(|pack| !pack.invariants.is_empty());
    }

    pub fn packs(&self) -> &[Pack] {
        &self.packs
    }

    pub fn is_empty(&self) -> bool {
        self.packs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.packs.len()
    }

    pub fn get(&self, id: &str) -> Option<&Pack> {
        self.packs.iter().find(|pack| pack.id == id)
    }

    pub fn ids(&self) -> Vec<&str> {
        self.packs.iter().map(|pack| pack.id.as_str()).collect()
    }

    /// Total invariants across every pack.
    pub fn invariant_count(&self) -> usize {
        self.packs.iter().map(|pack| pack.invariants.len()).sum()
    }

    /// Evaluate this registry against a graph.
    pub fn evaluate<G: quoll_graph::GraphOps>(
        &self,
        graph: &G,
        detection: &Detection,
    ) -> Result<crate::evaluate::Report> {
        crate::evaluate::evaluate(graph, &self.packs, detection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::Confidence;
    use quoll_detect::{Component, Role};

    fn detection(ids: &[(&str, Role)]) -> Detection {
        Detection {
            components: ids
                .iter()
                .map(|(id, role)| {
                    Component::new(*id, *id, *role).with_confidence(Confidence::CERTAIN)
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn every_builtin_pack_parses_and_validates() {
        let registry = Registry::builtin().unwrap();
        assert_eq!(registry.len(), BUILTIN.len());
        for pack in registry.packs() {
            pack.validate().unwrap();
        }
    }

    #[test]
    fn builtin_pack_ids_match_their_file_names() {
        let registry = Registry::builtin().unwrap();
        for (name, _) in BUILTIN {
            assert!(
                registry.get(name).is_some(),
                "pack file `{name}` declares a different id"
            );
        }
    }

    #[test]
    fn the_mvp_stack_has_a_pack() {
        let registry = Registry::builtin().unwrap();
        for id in ["nextjs-app-router", "nextjs-better-auth-drizzle", "axum", "express"] {
            assert!(registry.get(id).is_some(), "missing pack `{id}`");
        }
        assert!(registry.invariant_count() >= 8);
    }

    #[test]
    fn every_builtin_invariant_states_a_remediation() {
        for pack in Registry::builtin().unwrap().packs() {
            for invariant in &pack.invariants {
                assert!(
                    invariant.remediation.is_some(),
                    "`{}` tells the user what is wrong but not what to do",
                    invariant.qualified_id(&pack.id)
                );
            }
        }
    }

    #[test]
    fn a_user_pack_overrides_a_builtin_with_the_same_id() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("axum.yaml"),
            "schema_version: 1\nid: axum\nversion: 9.9.9\ninvariants:\n  - id: mine\n    title: Mine\n    severity: low\n    applies_to: { node_kind: route }\n    requires: { edge: guarded_by }\n",
        )
        .unwrap();

        let mut registry = Registry::builtin().unwrap();
        let before = registry.len();
        assert_eq!(registry.load_dir(dir.path()).unwrap(), 1);

        assert_eq!(registry.len(), before, "override, not addition");
        assert_eq!(registry.get("axum").unwrap().version, "9.9.9");
    }

    #[test]
    fn non_yaml_files_in_a_policy_directory_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "# packs\n").unwrap();
        let mut registry = Registry::new();
        assert_eq!(registry.load_dir(dir.path()).unwrap(), 0);
    }

    #[test]
    fn a_malformed_user_pack_names_its_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.yaml"), "schema_version: 1\nid: x\n").unwrap();
        let err = Registry::new().load_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("broken.yaml"), "{err}");
    }

    #[test]
    fn configuration_can_disable_a_pack() {
        let mut config = Config::default();
        config.policy.disabled = vec!["axum".into()];

        let mut registry = Registry::builtin().unwrap();
        registry.retain_configured(&config);
        assert!(registry.get("axum").is_none());
        assert!(registry.get("express").is_some());
    }

    #[test]
    fn an_allowlist_excludes_everything_else() {
        let mut config = Config::default();
        config.policy.packs = vec!["axum".into()];

        let mut registry = Registry::builtin().unwrap();
        registry.retain_configured(&config);
        assert_eq!(registry.ids(), vec!["axum"]);
    }

    #[test]
    fn configuration_can_disable_a_single_control() {
        let mut config = Config::default();
        config.policy.disabled_controls = vec!["axum/mutation-runs-authorisation".into()];

        let mut registry = Registry::builtin().unwrap();
        registry.disabled_controls = config.policy.disabled_controls.clone();
        registry.retain_configured(&config);

        let axum = registry.get("axum").unwrap();
        assert!(axum.invariant("authenticated-mutation").is_some());
        assert!(axum.invariant("mutation-runs-authorisation").is_none());
    }

    #[test]
    fn a_pack_with_every_control_disabled_is_dropped_entirely() {
        let mut config = Config::default();
        config.policy.disabled_controls = vec![
            "axum/authenticated-mutation".into(),
            "axum/mutation-runs-authorisation".into(),
        ];

        let mut registry = Registry::builtin().unwrap();
        registry.disabled_controls = config.policy.disabled_controls.clone();
        registry.retain_configured(&config);

        assert!(
            registry.get("axum").is_none(),
            "an empty pack must not be reported as applied"
        );
    }

    #[test]
    fn evaluating_through_the_registry_selects_the_right_packs() {
        let graph = quoll_graph::Graph::open_in_memory().unwrap();
        let registry = Registry::builtin().unwrap();
        let detection = detection(&[("axum", Role::Framework)]);

        let report = registry.evaluate(&graph, &detection).unwrap();
        assert_eq!(report.packs_applied, vec!["axum"]);
        assert_eq!(report.packs_skipped.len(), BUILTIN.len() - 1);
    }

    #[test]
    fn the_combined_pack_needs_all_three_components() {
        let graph = quoll_graph::Graph::open_in_memory().unwrap();
        let registry = Registry::builtin().unwrap();

        let partial = detection(&[
            ("nextjs-app-router", Role::Framework),
            ("better-auth", Role::Auth),
        ]);
        let report = registry.evaluate(&graph, &partial).unwrap();
        assert!(report.packs_applied.contains(&"nextjs-app-router".to_string()));
        assert!(!report
            .packs_applied
            .contains(&"nextjs-better-auth-drizzle".to_string()));

        let full = detection(&[
            ("nextjs-app-router", Role::Framework),
            ("better-auth", Role::Auth),
            ("drizzle", Role::Orm),
        ]);
        let report = registry.evaluate(&graph, &full).unwrap();
        assert!(report
            .packs_applied
            .contains(&"nextjs-better-auth-drizzle".to_string()));
    }

    #[test]
    fn express_and_fastify_both_trigger_the_express_pack() {
        let graph = quoll_graph::Graph::open_in_memory().unwrap();
        let registry = Registry::builtin().unwrap();
        for id in ["express", "fastify"] {
            let report = registry
                .evaluate(&graph, &detection(&[(id, Role::Framework)]))
                .unwrap();
            assert!(
                report.packs_applied.contains(&"express".to_string()),
                "`{id}` should match the express pack's `any` clause"
            );
        }
    }
}
