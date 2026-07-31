//! The plugin contract.
//!
//! Quoll's core never depends on a specific security tool. It depends on this crate,
//! which defines what a plugin advertises ([`PluginManifest`]), what it is given
//! ([`ScanContext`]) and what it returns ([`PluginOutput`]). Adding Semgrep, CodeQL or
//! a tool that does not exist yet requires no change to the orchestrator.

pub mod context;
pub mod exec;
pub mod manifest;
pub mod output;
pub mod plugin;
pub mod registry;

pub use context::ScanContext;
pub use exec::{which, CommandOutput, Exec};
pub use manifest::{BinaryRequirement, Capability, CostTier, PluginManifest};
pub use output::{Diagnostic, PluginOutput, PluginRun, RunStatus};
pub use plugin::{Availability, Plugin};
pub use registry::{Registry, Selection, SkipReason};

pub use async_trait::async_trait;
