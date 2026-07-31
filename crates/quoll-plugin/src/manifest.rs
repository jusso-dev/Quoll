use std::fmt;

use quoll_core::{Confidence, Ecosystem, Language};
use serde::{Deserialize, Serialize};

/// What a plugin contributes to a scan.
///
/// The orchestrator schedules by capability, never by plugin name, so that swapping
/// Gitleaks for TruffleHog requires no change to the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Pattern or dataflow analysis over source code.
    StaticAnalysis,
    /// Credential material in files or history.
    SecretScanning,
    /// Known advisories against declared dependencies.
    DependencyAudit,
    /// Infrastructure-as-code misconfiguration.
    IacScanning,
    /// Container image and OS package analysis.
    ContainerScanning,
    /// Licence obligations and incompatibilities.
    LicenseCompliance,
    /// Exercises a running application to prove exploitability.
    DynamicValidation,
    /// Language-model reasoning.
    AiReasoning,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::StaticAnalysis => "static_analysis",
            Capability::SecretScanning => "secret_scanning",
            Capability::DependencyAudit => "dependency_audit",
            Capability::IacScanning => "iac_scanning",
            Capability::ContainerScanning => "container_scanning",
            Capability::LicenseCompliance => "license_compliance",
            Capability::DynamicValidation => "dynamic_validation",
            Capability::AiReasoning => "ai_reasoning",
        }
    }

    /// Whether this capability needs a deployed, running target.
    pub fn requires_running_target(self) -> bool {
        matches!(self, Capability::DynamicValidation)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rough runtime class, used to decide whether a profile can afford a plugin.
///
/// Wall-clock seconds would be a lie: the same scanner takes 3s on a toy repository and
/// 20 minutes on a monorepo. A tier is honest about being an ordering, not a promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostTier {
    /// Seconds. Safe in a pre-commit hook.
    Fast = 1,
    /// Tens of seconds to a few minutes. Fine in CI.
    Moderate = 2,
    /// Minutes to hours. Nightly or release only.
    Expensive = 3,
}

impl CostTier {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CostTier::Fast => "fast",
            CostTier::Moderate => "moderate",
            CostTier::Expensive => "expensive",
        }
    }
}

/// An external executable the plugin shells out to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryRequirement {
    /// Executable name as it appears on `PATH`.
    pub name: String,
    /// Argument that makes the binary print its version, e.g. `--version`.
    #[serde(default)]
    pub version_flag: Option<String>,
    /// Minimum supported version, informational only.
    #[serde(default)]
    pub minimum_version: Option<String>,
    /// Shown by `quoll doctor` when the binary is missing.
    #[serde(default)]
    pub install_hint: Option<String>,
}

impl BinaryRequirement {
    pub fn new(name: impl Into<String>) -> BinaryRequirement {
        BinaryRequirement {
            name: name.into(),
            version_flag: Some("--version".to_string()),
            minimum_version: None,
            install_hint: None,
        }
    }

    pub fn version_flag(mut self, flag: impl Into<String>) -> Self {
        self.version_flag = Some(flag.into());
        self
    }

    pub fn install_hint(mut self, hint: impl Into<String>) -> Self {
        self.install_hint = Some(hint.into());
        self
    }
}

/// Everything a plugin advertises about itself.
///
/// The registry uses this to schedule without ever loading or running the plugin, which
/// is what makes `quoll plugins` and `quoll doctor` instant and side-effect free.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Stable identifier used in config and suppressions, e.g. `semgrep`.
    pub id: String,
    pub name: String,
    pub description: String,
    /// Version of the Quoll adapter, not of the underlying tool.
    pub version: String,
    pub capabilities: Vec<Capability>,
    /// Languages the plugin analyses. Empty means language-agnostic.
    #[serde(default)]
    pub languages: Vec<Language>,
    /// Package ecosystems the plugin understands. Empty means not dependency-oriented.
    #[serde(default)]
    pub ecosystems: Vec<Ecosystem>,
    #[serde(default)]
    pub required_binaries: Vec<BinaryRequirement>,
    pub cost: CostTier,
    /// Default trust in this tool's output, before per-finding confidence.
    pub baseline_confidence: Confidence,
    /// Licence of the underlying tool, surfaced so users can vet their supply chain.
    pub license: String,
    #[serde(default)]
    pub homepage: Option<String>,
    /// Whether the plugin works with no network access.
    pub offline_capable: bool,
}

impl PluginManifest {
    pub fn builder(id: impl Into<String>, name: impl Into<String>) -> ManifestBuilder {
        ManifestBuilder {
            manifest: PluginManifest {
                id: id.into(),
                name: name.into(),
                description: String::new(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                capabilities: Vec::new(),
                languages: Vec::new(),
                ecosystems: Vec::new(),
                required_binaries: Vec::new(),
                cost: CostTier::Moderate,
                baseline_confidence: Confidence::new(0.7),
                license: "unknown".to_string(),
                homepage: None,
                offline_capable: true,
            },
        }
    }

    pub fn has_capability(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Whether the plugin is relevant to a repository using these languages.
    ///
    /// Language-agnostic plugins (secret scanners, IaC) always apply.
    pub fn supports_language(&self, language: &Language) -> bool {
        self.languages.is_empty() || self.languages.contains(language)
    }

    pub fn supports_ecosystem(&self, ecosystem: Ecosystem) -> bool {
        self.ecosystems.is_empty() || self.ecosystems.contains(&ecosystem)
    }
}

pub struct ManifestBuilder {
    manifest: PluginManifest,
}

impl ManifestBuilder {
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.manifest.description = description.into();
        self
    }

    pub fn capability(mut self, capability: Capability) -> Self {
        if !self.manifest.capabilities.contains(&capability) {
            self.manifest.capabilities.push(capability);
        }
        self
    }

    pub fn languages(mut self, languages: impl IntoIterator<Item = Language>) -> Self {
        self.manifest.languages.extend(languages);
        self
    }

    pub fn ecosystems(mut self, ecosystems: impl IntoIterator<Item = Ecosystem>) -> Self {
        self.manifest.ecosystems.extend(ecosystems);
        self
    }

    pub fn requires(mut self, requirement: BinaryRequirement) -> Self {
        self.manifest.required_binaries.push(requirement);
        self
    }

    pub fn cost(mut self, cost: CostTier) -> Self {
        self.manifest.cost = cost;
        self
    }

    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.manifest.baseline_confidence = confidence;
        self
    }

    pub fn license(mut self, license: impl Into<String>) -> Self {
        self.manifest.license = license.into();
        self
    }

    pub fn homepage(mut self, homepage: impl Into<String>) -> Self {
        self.manifest.homepage = Some(homepage.into());
        self
    }

    pub fn requires_network(mut self) -> Self {
        self.manifest.offline_capable = false;
        self
    }

    pub fn build(self) -> PluginManifest {
        self.manifest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_agnostic_plugins_apply_everywhere() {
        let manifest = PluginManifest::builder("gitleaks", "Gitleaks")
            .capability(Capability::SecretScanning)
            .build();
        assert!(manifest.supports_language(&Language::Rust));
        assert!(manifest.supports_language(&Language::Php));
    }

    #[test]
    fn language_specific_plugins_are_selective() {
        let manifest = PluginManifest::builder("cargo-audit", "cargo-audit")
            .languages([Language::Rust])
            .build();
        assert!(manifest.supports_language(&Language::Rust));
        assert!(!manifest.supports_language(&Language::Go));
    }

    #[test]
    fn cost_tiers_order_by_expense() {
        assert!(CostTier::Fast < CostTier::Expensive);
        assert_eq!(CostTier::Moderate.as_u8(), 2);
    }

    #[test]
    fn builder_defaults_to_offline_capable() {
        let manifest = PluginManifest::builder("x", "X").build();
        assert!(manifest.offline_capable);
        assert!(!PluginManifest::builder("y", "Y")
            .requires_network()
            .build()
            .offline_capable);
    }
}
