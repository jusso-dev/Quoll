//! First-party scanner adapters.
//!
//! Quoll runs other people's tools. This crate holds the adapters that make each one speak
//! the same finding schema, and it is kept separate from `quoll-plugin` so that the plugin
//! contract has no dependency on any tool that implements it.
//!
//! Every adapter splits into two halves. Running the tool is a thin wrapper over
//! [`quoll_plugin::Exec`] — direct spawn with an argument vector, never a shell, always
//! with a timeout. Parsing its output is a pure function over a string, which is why the
//! parsers have full test coverage against recorded tool output without any of these tools
//! being installed.
//!
//! Three conventions hold across all of them:
//!
//! * **A non-zero exit is not a failure.** Most scanners exit `1` when they find
//!   something. Adapters run leniently and judge the output, not the status.
//! * **Skipping is not failing.** A Rust auditor on a TypeScript repository returns
//!   `PluginOutput::skipped`, which the run report distinguishes from both a clean result
//!   and a crash.
//! * **Findings are evidence, not conclusions.** An adapter emits `RawFinding`; deciding
//!   what it means is the correlation engine's job.
//!
//! ```no_run
//! use quoll_plugins::registry;
//!
//! for plugin in registry().all() {
//!     println!("{} — {}", plugin.id(), plugin.manifest().description);
//! }
//! ```

pub mod cargo_audit;
pub mod common;
pub mod gitleaks;
pub mod osv;
pub mod semgrep;
pub mod strix;
pub mod trivy;

use std::sync::Arc;

use quoll_plugin::{Plugin, Registry};

pub use cargo_audit::CargoAudit;
pub use gitleaks::Gitleaks;
pub use osv::OsvScanner;
pub use semgrep::Semgrep;
pub use strix::{check_target, Refusal, Strix, TargetPolicy, ValidationRequest};
pub use trivy::Trivy;

/// Every first-party adapter, ready to schedule.
///
/// Built at call time rather than held in a static: a registry is cheap, and a mutable
/// global would make plugin availability depend on what ran earlier in the process.
pub fn registry() -> Registry {
    let mut registry = Registry::new();
    for plugin in all() {
        registry.register(plugin);
    }
    registry
}

/// The adapters, in a stable order.
pub fn all() -> Vec<Arc<dyn Plugin>> {
    vec![
        Arc::new(Semgrep::new()),
        Arc::new(Gitleaks::new()),
        Arc::new(OsvScanner::new()),
        Arc::new(CargoAudit::new()),
        Arc::new(Trivy::new()),
        Arc::new(Strix::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{Language, Profile, TechStack};
    use quoll_plugin::{Capability, ScanContext};

    #[test]
    fn the_registry_holds_every_adapter() {
        let registry = registry();
        assert_eq!(registry.len(), 6);
        for id in ["semgrep", "gitleaks", "osv-scanner", "cargo-audit", "trivy", "strix"] {
            assert!(registry.get(id).is_some(), "missing `{id}`");
        }
    }

    #[test]
    fn plugin_ids_are_unique() {
        let registry = registry();
        let ids = registry.ids();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }

    #[test]
    fn every_adapter_states_how_to_install_its_binary() {
        for plugin in all() {
            let manifest = plugin.manifest();
            assert!(
                !manifest.required_binaries.is_empty(),
                "`{}` declares no binary",
                manifest.id
            );
            for requirement in &manifest.required_binaries {
                assert!(
                    requirement.install_hint.is_some(),
                    "`{}` does not say how to install `{}`",
                    manifest.id,
                    requirement.name
                );
            }
        }
    }

    #[test]
    fn every_adapter_declares_a_licence() {
        for plugin in all() {
            assert!(
                !plugin.manifest().license.trim().is_empty(),
                "`{}` declares no licence",
                plugin.id()
            );
        }
    }

    #[test]
    fn only_strix_can_mutate_a_target() {
        for plugin in all() {
            let dynamic = plugin
                .manifest()
                .has_capability(Capability::DynamicValidation);
            assert_eq!(dynamic, plugin.id() == "strix", "{}", plugin.id());
        }
    }

    #[test]
    fn a_fast_profile_schedules_only_the_cheap_scanners() {
        let ctx = ScanContext::new("/repo", Profile::Fast)
            .with_tech_stack(TechStack {
                languages: vec![(Language::Rust, 20)],
                ..Default::default()
            })
            .with_files(vec!["Cargo.lock".into(), "src/main.rs".into()]);

        let registry = registry();
        let selected = registry.selected(&Default::default(), &ctx);
        let ids: Vec<String> = selected.iter().map(|p| p.id().to_string()).collect();

        assert!(ids.iter().any(|id| id == "gitleaks"), "{ids:?}");
        assert!(ids.iter().any(|id| id == "cargo-audit"), "{ids:?}");
        assert!(!ids.iter().any(|id| id == "strix"), "dynamic validation is never fast");
        assert!(!ids.iter().any(|id| id == "trivy"), "trivy is moderate, not fast");
    }

    #[test]
    fn an_offline_scan_drops_the_network_bound_scanners() {
        let ctx = ScanContext::new("/repo", Profile::Deep)
            .with_offline(true)
            .with_files(vec!["Cargo.lock".into()]);

        let registry = registry();
        let ids: Vec<String> = registry
            .selected(&Default::default(), &ctx)
            .iter()
            .map(|p| p.id().to_string())
            .collect();
        assert!(!ids.iter().any(|id| id == "strix"), "{ids:?}");
    }

    #[test]
    fn a_typescript_repository_does_not_schedule_cargo_audit() {
        let ctx = ScanContext::new("/repo", Profile::Deep)
            .with_tech_stack(TechStack {
                languages: vec![(Language::TypeScript, 40)],
                ..Default::default()
            })
            .with_files(vec!["package-lock.json".into(), "src/app.ts".into()]);

        let registry = registry();
        let ids: Vec<String> = registry
            .selected(&Default::default(), &ctx)
            .iter()
            .map(|p| p.id().to_string())
            .collect();
        assert!(!ids.iter().any(|id| id == "cargo-audit"), "{ids:?}");
        assert!(ids.iter().any(|id| id == "osv-scanner"), "{ids:?}");
    }

    #[test]
    fn configuration_can_switch_an_adapter_off() {
        let ctx = ScanContext::new("/repo", Profile::Deep).with_files(vec!["Cargo.lock".into()]);
        let config = quoll_core::config::PluginsConfig {
            disabled: vec!["gitleaks".into()],
            ..Default::default()
        };

        let registry = registry();
        let ids: Vec<String> = registry
            .selected(&config, &ctx)
            .iter()
            .map(|p| p.id().to_string())
            .collect();
        assert!(!ids.iter().any(|id| id == "gitleaks"), "{ids:?}");
    }
}
