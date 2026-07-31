use std::collections::BTreeMap;
use std::sync::Arc;

use quoll_core::config::PluginsConfig;

use crate::context::ScanContext;
use crate::manifest::Capability;
use crate::plugin::Plugin;

/// Whether a plugin will run, and if not, why.
///
/// Scheduling decisions are recorded rather than silently applied so that `quoll scan`
/// can always answer "why didn't Semgrep run?" without a debug build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Selected,
    Skipped(SkipReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Turned off in `quoll.toml`.
    Disabled,
    /// Nothing in this repository is relevant to it.
    NotApplicable,
    /// Too slow for the active profile.
    TooExpensive { cost: String, profile: String },
    /// Needs the network and the scan is offline.
    RequiresNetwork,
    /// Needs a running target and none was supplied.
    RequiresTarget,
}

impl SkipReason {
    pub fn describe(&self) -> String {
        match self {
            SkipReason::Disabled => "disabled in configuration".to_string(),
            SkipReason::NotApplicable => "not applicable to this repository".to_string(),
            SkipReason::TooExpensive { cost, profile } => {
                format!("cost `{cost}` exceeds the `{profile}` profile budget")
            }
            SkipReason::RequiresNetwork => "requires network access, scan is offline".to_string(),
            SkipReason::RequiresTarget => "requires a running target (--target-url)".to_string(),
        }
    }
}

/// The set of plugins available to a scan.
///
/// Ordered by id so that scan output is stable between runs, which matters for
/// reproducible reports and for diffing CI logs.
#[derive(Default, Clone)]
pub struct Registry {
    plugins: BTreeMap<String, Arc<dyn Plugin>>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry::default()
    }

    /// Add a plugin. A later registration with the same id replaces the earlier one,
    /// which is how a user-supplied plugin overrides a built-in.
    pub fn register(&mut self, plugin: Arc<dyn Plugin>) -> &mut Self {
        self.plugins.insert(plugin.id().to_string(), plugin);
        self
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn Plugin>> {
        self.plugins.get(id)
    }

    pub fn all(&self) -> impl Iterator<Item = &Arc<dyn Plugin>> {
        self.plugins.values()
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub fn ids(&self) -> Vec<&str> {
        self.plugins.keys().map(String::as_str).collect()
    }

    pub fn with_capability(&self, capability: Capability) -> Vec<&Arc<dyn Plugin>> {
        self.plugins
            .values()
            .filter(|p| p.manifest().has_capability(capability))
            .collect()
    }

    /// Decide which plugins run for this scan, and record why the others do not.
    ///
    /// Availability is deliberately not checked here: it requires filesystem access and
    /// process spawning, so the orchestrator does it separately and concurrently.
    pub fn plan(
        &self,
        config: &PluginsConfig,
        ctx: &ScanContext,
    ) -> Vec<(Arc<dyn Plugin>, Selection)> {
        let profile = ctx.profile();
        self.plugins
            .values()
            .map(|plugin| {
                let manifest = plugin.manifest();
                let selection = if !config.is_permitted(&manifest.id) {
                    Selection::Skipped(SkipReason::Disabled)
                } else if manifest.cost.as_u8() > profile.max_plugin_cost() {
                    Selection::Skipped(SkipReason::TooExpensive {
                        cost: manifest.cost.as_str().to_string(),
                        profile: profile.as_str().to_string(),
                    })
                } else if !manifest.offline_capable && ctx.is_offline() {
                    Selection::Skipped(SkipReason::RequiresNetwork)
                } else if manifest
                    .capabilities
                    .iter()
                    .all(|c| c.requires_running_target())
                    && ctx.target_url().is_none()
                {
                    Selection::Skipped(SkipReason::RequiresTarget)
                } else if !plugin.applies_to(ctx) {
                    Selection::Skipped(SkipReason::NotApplicable)
                } else {
                    Selection::Selected
                };
                (Arc::clone(plugin), selection)
            })
            .collect()
    }

    /// Just the plugins that will run.
    pub fn selected(&self, config: &PluginsConfig, ctx: &ScanContext) -> Vec<Arc<dyn Plugin>> {
        self.plan(config, ctx)
            .into_iter()
            .filter(|(_, selection)| *selection == Selection::Selected)
            .map(|(plugin, _)| plugin)
            .collect()
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("plugins", &self.ids())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{CostTier, PluginManifest};
    use crate::output::PluginOutput;
    use async_trait::async_trait;
    use quoll_core::{Language, Profile, Result, TechStack};

    struct Fake {
        manifest: PluginManifest,
    }

    impl Fake {
        fn boxed(manifest: PluginManifest) -> Arc<dyn Plugin> {
            Arc::new(Fake { manifest })
        }
    }

    #[async_trait]
    impl Plugin for Fake {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }

        async fn run(&self, _ctx: &ScanContext) -> Result<PluginOutput> {
            Ok(PluginOutput::empty())
        }
    }

    fn registry() -> Registry {
        let mut registry = Registry::new();
        registry.register(Fake::boxed(
            PluginManifest::builder("gitleaks", "Gitleaks")
                .capability(Capability::SecretScanning)
                .cost(CostTier::Fast)
                .build(),
        ));
        registry.register(Fake::boxed(
            PluginManifest::builder("codeql", "CodeQL")
                .capability(Capability::StaticAnalysis)
                .cost(CostTier::Expensive)
                .build(),
        ));
        registry.register(Fake::boxed(
            PluginManifest::builder("cargo-audit", "cargo-audit")
                .capability(Capability::DependencyAudit)
                .languages([Language::Rust])
                .cost(CostTier::Fast)
                .build(),
        ));
        registry.register(Fake::boxed(
            PluginManifest::builder("zap", "OWASP ZAP")
                .capability(Capability::DynamicValidation)
                .cost(CostTier::Fast)
                .build(),
        ));
        registry
    }

    fn context(profile: Profile) -> ScanContext {
        ScanContext::new("/repo", profile).with_tech_stack(TechStack {
            languages: vec![(Language::TypeScript, 10)],
            ..Default::default()
        })
    }

    fn reason(plan: &[(Arc<dyn Plugin>, Selection)], id: &str) -> Selection {
        plan.iter()
            .find(|(p, _)| p.id() == id)
            .map(|(_, s)| s.clone())
            .expect("plugin present")
    }

    #[test]
    fn expensive_plugins_are_dropped_from_fast_profiles() {
        let plan = registry().plan(&PluginsConfig::default(), &context(Profile::Fast));
        assert!(matches!(
            reason(&plan, "codeql"),
            Selection::Skipped(SkipReason::TooExpensive { .. })
        ));
        assert_eq!(reason(&plan, "gitleaks"), Selection::Selected);
    }

    #[test]
    fn deep_profiles_admit_expensive_plugins() {
        let plan = registry().plan(&PluginsConfig::default(), &context(Profile::Deep));
        assert_eq!(reason(&plan, "codeql"), Selection::Selected);
    }

    #[test]
    fn language_mismatch_skips_the_plugin() {
        let plan = registry().plan(&PluginsConfig::default(), &context(Profile::Deep));
        assert!(matches!(
            reason(&plan, "cargo-audit"),
            Selection::Skipped(SkipReason::NotApplicable)
        ));
    }

    #[test]
    fn dynamic_validators_need_a_target() {
        let plan = registry().plan(&PluginsConfig::default(), &context(Profile::Release));
        assert!(matches!(
            reason(&plan, "zap"),
            Selection::Skipped(SkipReason::RequiresTarget)
        ));

        let with_target = context(Profile::Release).with_target_url(Some("http://x".into()));
        let plan = registry().plan(&PluginsConfig::default(), &with_target);
        assert_eq!(reason(&plan, "zap"), Selection::Selected);
    }

    #[test]
    fn configuration_denylist_wins() {
        let config = PluginsConfig {
            disabled: vec!["gitleaks".into()],
            ..Default::default()
        };
        let plan = registry().plan(&config, &context(Profile::Deep));
        assert_eq!(
            reason(&plan, "gitleaks"),
            Selection::Skipped(SkipReason::Disabled)
        );
    }

    #[test]
    fn later_registration_replaces_an_existing_id() {
        let mut registry = Registry::new();
        registry.register(Fake::boxed(
            PluginManifest::builder("semgrep", "Built-in").build(),
        ));
        registry.register(Fake::boxed(
            PluginManifest::builder("semgrep", "User override").build(),
        ));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get("semgrep").unwrap().manifest().name, "User override");
    }

    #[test]
    fn capability_lookup_finds_the_right_plugins() {
        let registry = registry();
        let secrets = registry.with_capability(Capability::SecretScanning);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].id(), "gitleaks");
    }
}
