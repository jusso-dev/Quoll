use async_trait::async_trait;
use quoll_core::Result;

use crate::context::ScanContext;
use crate::exec;
use crate::manifest::PluginManifest;
use crate::output::PluginOutput;

/// Why a plugin can or cannot run right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Ready {
        /// Version of the underlying tool, when it could be determined.
        tool_version: Option<String>,
    },
    /// A prerequisite is missing. `quoll doctor` renders `hint` verbatim.
    Missing {
        reason: String,
        hint: Option<String>,
    },
}

impl Availability {
    pub fn is_ready(&self) -> bool {
        matches!(self, Availability::Ready { .. })
    }

    pub fn missing(reason: impl Into<String>) -> Availability {
        Availability::Missing {
            reason: reason.into(),
            hint: None,
        }
    }

    pub fn missing_with_hint(reason: impl Into<String>, hint: impl Into<String>) -> Availability {
        Availability::Missing {
            reason: reason.into(),
            hint: Some(hint.into()),
        }
    }
}

/// The contract every security tool adapter implements.
///
/// Quoll's core depends on this trait and nothing below it. Adding a scanner means
/// writing an implementation and registering it; no core file changes.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Static self-description. Must be cheap and side-effect free.
    fn manifest(&self) -> &PluginManifest;

    /// Whether prerequisites are satisfied on this machine.
    ///
    /// The default implementation checks every declared binary is on `PATH`, which is
    /// correct for the majority of adapters that simply wrap a CLI.
    async fn availability(&self) -> Availability {
        for requirement in &self.manifest().required_binaries {
            let Some(path) = exec::which(&requirement.name) else {
                return Availability::Missing {
                    reason: format!("`{}` not found on PATH", requirement.name),
                    hint: requirement.install_hint.clone(),
                };
            };
            if let Some(flag) = &requirement.version_flag {
                if let Some(version) = exec::tool_version(&path, flag).await {
                    return Availability::Ready {
                        tool_version: Some(version),
                    };
                }
            }
        }
        Availability::Ready { tool_version: None }
    }

    /// Whether this plugin has anything to contribute to this repository.
    ///
    /// The default answer is derived from the manifest's declared languages, which is
    /// right for most adapters. Override when relevance depends on file contents —
    /// `cargo-audit` needs a `Cargo.lock`, not merely some Rust.
    fn applies_to(&self, ctx: &ScanContext) -> bool {
        let manifest = self.manifest();
        if manifest.languages.is_empty() {
            return true;
        }
        manifest
            .languages
            .iter()
            .any(|lang| ctx.tech_stack().uses_language(lang))
    }

    /// Do the work.
    ///
    /// Implementations should return `Ok(PluginOutput::skipped(..))` rather than an
    /// error when there is legitimately nothing to do; errors mean the tool broke.
    async fn run(&self, ctx: &ScanContext) -> Result<PluginOutput>;

    /// Convenience accessor used throughout the orchestrator.
    fn id(&self) -> &str {
        &self.manifest().id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{BinaryRequirement, Capability};
    use quoll_core::{Language, Profile, TechStack};

    struct RustOnly {
        manifest: PluginManifest,
    }

    impl RustOnly {
        fn new() -> Self {
            RustOnly {
                manifest: PluginManifest::builder("rust-only", "Rust Only")
                    .capability(Capability::StaticAnalysis)
                    .languages([Language::Rust])
                    .requires(BinaryRequirement::new(
                        "quoll-definitely-not-a-real-binary",
                    ))
                    .build(),
            }
        }
    }

    #[async_trait]
    impl Plugin for RustOnly {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }

        async fn run(&self, _ctx: &ScanContext) -> Result<PluginOutput> {
            Ok(PluginOutput::empty())
        }
    }

    fn context_with(languages: Vec<(Language, usize)>) -> ScanContext {
        ScanContext::new("/repo", Profile::Balanced).with_tech_stack(TechStack {
            languages,
            ..Default::default()
        })
    }

    #[test]
    fn language_gating_uses_the_manifest_by_default() {
        let plugin = RustOnly::new();
        assert!(plugin.applies_to(&context_with(vec![(Language::Rust, 5)])));
        assert!(!plugin.applies_to(&context_with(vec![(Language::Go, 5)])));
    }

    #[tokio::test]
    async fn missing_binaries_surface_as_unavailable() {
        let availability = RustOnly::new().availability().await;
        assert!(!availability.is_ready());
        match availability {
            Availability::Missing { reason, .. } => assert!(reason.contains("not found on PATH")),
            other => panic!("expected Missing, got {other:?}"),
        }
    }
}
