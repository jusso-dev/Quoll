use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Confidence, Error, Profile, Result, Severity};

/// Canonical config file name, discovered by walking up from the scan target.
pub const CONFIG_FILE: &str = "quoll.toml";

/// Directory Quoll owns inside a repository: graph, baselines, reports, cache.
pub const STATE_DIR: &str = ".quoll";

/// Root of `quoll.toml`.
///
/// Every field has a defensible default so that `quoll scan` works on a repository with
/// no configuration at all. The file exists to override, never to enable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub project: ProjectConfig,
    pub scan: ScanConfig,
    pub graph: GraphConfig,
    pub plugins: PluginsConfig,
    pub policy: PolicyConfig,
    pub ai: AiConfig,
    pub report: ReportConfig,
    pub suppress: SuppressConfig,

    /// Absolute path this config was loaded from. Not serialised.
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
    /// Repository root; every relative path in this config resolves against it.
    #[serde(skip)]
    pub root: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Free-text note carried into reports, e.g. "PCI scope: cardholder data".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub profile: Profile,
    /// Glob patterns to scan. Empty means the whole repository.
    pub include: Vec<String>,
    /// Glob patterns to skip, on top of `.gitignore`.
    pub exclude: Vec<String>,
    /// Severity at or above which `quoll ci` exits non-zero.
    pub fail_on: Option<Severity>,
    /// Skip files larger than this; minified bundles are noise, not source.
    pub max_file_size_kb: u64,
    /// Honour `.gitignore` and friends when walking the tree.
    pub respect_gitignore: bool,
    /// Git ref to diff against for incremental scans.
    pub base_ref: Option<String>,
    /// Parallel plugin executions. `None` means one per available core.
    pub concurrency: Option<usize>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            profile: Profile::default(),
            include: Vec::new(),
            exclude: default_excludes(),
            fail_on: None,
            max_file_size_kb: 2048,
            respect_gitignore: true,
            base_ref: None,
            concurrency: None,
        }
    }
}

/// Directories that are never worth scanning as first-party source.
///
/// Dependency contents are covered by the dependency scanners instead, which read
/// lockfiles and are both faster and more accurate than pattern-matching vendored code.
fn default_excludes() -> Vec<String> {
    [
        "**/node_modules/**",
        "**/vendor/**",
        "**/target/**",
        "**/dist/**",
        "**/build/**",
        "**/.next/**",
        "**/.venv/**",
        "**/venv/**",
        "**/__pycache__/**",
        "**/.git/**",
        "**/.quoll/**",
        "**/*.min.js",
        "**/*.min.css",
        "**/*.lock",
        "**/*.map",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GraphConfig {
    pub enabled: bool,
    /// SQLite path, relative to the repository root.
    pub path: PathBuf,
    /// Rebuild from scratch instead of updating incrementally.
    pub rebuild: bool,
}

impl Default for GraphConfig {
    fn default() -> Self {
        GraphConfig {
            enabled: true,
            path: PathBuf::from(STATE_DIR).join("graph.db"),
            rebuild: false,
        }
    }
}

/// Plugin selection plus per-plugin overrides.
///
/// Unknown keys are accepted here, unlike everywhere else in the config: any table that
/// is not `enabled`/`disabled`/`search_paths` is a plugin id, and Quoll cannot know the
/// full set of plugin ids at compile time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginsConfig {
    /// Allowlist. Empty means "every plugin whose requirements are satisfied".
    pub enabled: Vec<String>,
    /// Denylist, applied after the allowlist.
    pub disabled: Vec<String>,
    /// Extra directories to search for external plugin manifests.
    pub search_paths: Vec<PathBuf>,
    /// Per-plugin overrides, keyed by plugin id.
    #[serde(flatten)]
    pub settings: BTreeMap<String, PluginSettings>,
}

/// Per-plugin configuration.
///
/// `extra_args` is an escape hatch: no matter how well Quoll models a scanner, users
/// will need a flag Quoll does not know about, and forking the plugin to get it is worse
/// than passing it through.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PluginSettings {
    pub enabled: Option<bool>,
    /// Override the binary path when it is not on `PATH`.
    pub binary: Option<PathBuf>,
    /// Rulesets or config files, interpreted by the plugin.
    pub config: Vec<String>,
    pub timeout_secs: Option<u64>,
    pub extra_args: Vec<String>,
    /// Environment variables set for this plugin's process.
    pub env: BTreeMap<String, String>,
}

impl PluginsConfig {
    pub fn settings_for(&self, plugin_id: &str) -> Option<&PluginSettings> {
        self.settings.get(plugin_id)
    }

    /// Whether a plugin is permitted to run, given allowlist and denylist.
    pub fn is_permitted(&self, plugin_id: &str) -> bool {
        if self.disabled.iter().any(|d| d == plugin_id) {
            return false;
        }
        if let Some(explicit) = self.settings.get(plugin_id).and_then(|s| s.enabled) {
            return explicit;
        }
        self.enabled.is_empty() || self.enabled.iter().any(|e| e == plugin_id)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Packs to load. Empty means "whatever detection finds".
    pub packs: Vec<String>,
    pub disabled: Vec<String>,
    /// Directories holding user-authored packs.
    pub search_paths: Vec<PathBuf>,
    /// Individual control ids to switch off, e.g. `nextjs/csrf-on-mutations`.
    pub disabled_controls: Vec<String>,
}

/// AI configuration. Everything here is optional; Quoll is fully functional with it off.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    /// Off unless switched on. Quoll must work with no keys and no network.
    pub enabled: bool,
    /// Provider id to use, matching a key in `providers`.
    pub provider: Option<String>,
    /// Overrides the profile's investigation threshold when set.
    pub investigation_threshold: Option<Confidence>,
    /// Overrides the profile's investigation cap when set.
    pub max_investigations: Option<usize>,
    pub models: ModelPolicy,
    pub providers: BTreeMap<String, ProviderConfig>,
    /// Hard ceiling on total tokens for a run. Exceeding it stops investigation.
    pub token_budget: Option<u64>,
}

/// Which model does which job.
///
/// The split is the point: strong models reason about hypotheses, cheap models write
/// prose. A cheap model is never asked to decide whether a vulnerability is real.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelPolicy {
    /// Reasoning model for hypothesis investigation.
    pub investigate: Option<String>,
    /// Cheap model for report prose, remediation text and regression tests.
    pub report: Option<String>,
    /// Reasoning effort hint, passed through where the provider supports it.
    pub effort: Option<String>,
}

impl Default for ModelPolicy {
    fn default() -> Self {
        ModelPolicy {
            investigate: None,
            report: None,
            effort: Some("high".to_string()),
        }
    }
}

/// How to reach a model provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProviderConfig {
    /// Provider implementation: `openai`, `anthropic`, `ollama`, `command`.
    pub kind: String,
    pub base_url: Option<String>,
    /// Environment variable holding the API key. Keys are never stored in the file.
    pub api_key_env: Option<String>,
    /// For `command` providers: the executable to invoke, e.g. `codex` or `claude`.
    pub command: Option<String>,
    pub args: Vec<String>,
    pub timeout_secs: Option<u64>,
    pub extra: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportConfig {
    /// Any of `markdown`, `json`, `sarif`.
    pub formats: Vec<String>,
    pub output_dir: PathBuf,
    /// Include refuted and suppressed findings for auditability.
    pub include_suppressed: bool,
    /// Path to a baseline file; findings present in it are reported as pre-existing.
    pub baseline: Option<PathBuf>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        ReportConfig {
            formats: vec!["markdown".to_string()],
            output_dir: PathBuf::from(STATE_DIR).join("reports"),
            include_suppressed: false,
            baseline: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SuppressConfig {
    /// Rule ids to silence globally, e.g. `semgrep:generic.secrets.example`.
    pub rules: Vec<String>,
    /// Path globs to silence entirely, e.g. `tests/**`.
    pub paths: Vec<String>,
    /// Targeted suppressions with a mandatory reason.
    pub entries: Vec<Suppression>,
}

/// A deliberate, documented exception.
///
/// `reason` is required: an undocumented suppression is indistinguishable from an
/// oversight six months later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    /// Finding fingerprint, rule id, or `plugin:rule`.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub reason: String,
    /// Expiry date, RFC 3339. Past this date the suppression stops applying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

impl Config {
    /// Load configuration for a scan target.
    ///
    /// Walks up from `start` looking for `quoll.toml`; if none exists, returns defaults
    /// rooted at `start`. A repository with no config is a supported configuration.
    pub fn discover(start: &Path) -> Result<Config> {
        let start = start
            .canonicalize()
            .map_err(|e| Error::io(start.to_path_buf(), e))?;

        for dir in start.ancestors() {
            let candidate = dir.join(CONFIG_FILE);
            if candidate.is_file() {
                let mut config = Config::load(&candidate)?;
                config.root = dir.to_path_buf();
                return Ok(config);
            }
            // Stop climbing at the repository boundary; a parent directory's config
            // has nothing to do with this project.
            if dir.join(".git").exists() {
                break;
            }
        }

        Ok(Config {
            root: start,
            ..Config::default()
        })
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).map_err(|e| Error::io(path.to_path_buf(), e))?;
        let mut config: Config =
            toml::from_str(&text).map_err(|e| Error::parse(path.display().to_string(), e))?;
        config.source_path = Some(path.to_path_buf());
        config.root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        config.validate()?;
        Ok(config)
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::parse("quoll.toml", e))
    }

    /// Reject configurations that would silently misbehave.
    pub fn validate(&self) -> Result<()> {
        for format in &self.report.formats {
            if !matches!(format.as_str(), "markdown" | "json" | "sarif") {
                return Err(Error::config(format!(
                    "unknown report format `{format}` (expected markdown, json or sarif)"
                )));
            }
        }
        if self.ai.enabled && self.ai.provider.is_none() {
            return Err(Error::config(
                "ai.enabled is true but ai.provider is not set",
            ));
        }
        if let Some(name) = &self.ai.provider {
            if !self.ai.providers.contains_key(name) {
                return Err(Error::config(format!(
                    "ai.provider is `{name}` but [ai.providers.{name}] is not defined"
                )));
            }
        }
        for entry in &self.suppress.entries {
            if entry.reason.trim().is_empty() {
                return Err(Error::config(format!(
                    "suppression `{}` must state a reason",
                    entry.id
                )));
            }
        }
        Ok(())
    }

    /// Resolve a config-relative path against the repository root.
    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        }
    }

    pub fn graph_path(&self) -> PathBuf {
        self.resolve(&self.graph.path)
    }

    pub fn report_dir(&self) -> PathBuf {
        self.resolve(&self.report.output_dir)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join(STATE_DIR)
    }

    /// Effective severity gate, falling back to the profile default.
    pub fn fail_on(&self) -> Severity {
        self.scan.fail_on.unwrap_or_else(|| self.scan.profile.fail_on())
    }

    pub fn investigation_threshold(&self) -> Confidence {
        self.ai
            .investigation_threshold
            .unwrap_or_else(|| self.scan.profile.investigation_threshold())
    }

    pub fn max_investigations(&self) -> usize {
        self.ai
            .max_investigations
            .unwrap_or_else(|| self.scan.profile.max_investigations())
    }

    /// AI runs only when the config asks for it *and* the profile permits it.
    pub fn ai_enabled(&self) -> bool {
        self.ai.enabled && self.scan.profile.allows_ai()
    }
}

/// Starter `quoll.toml` written by `quoll init`.
///
/// Written commented-out rather than active so that `quoll init` never changes scan
/// behaviour by itself — the file documents the knobs, it does not turn them.
pub const TEMPLATE: &str = r#"# Quoll configuration
# Every value below is a default; delete this file and Quoll still works.

[project]
# name = "my-service"

[scan]
# fast | balanced | deep | release
profile = "balanced"
# include = ["src/**", "app/**"]
# exclude = ["**/generated/**"]
# fail_on = "high"

[graph]
enabled = true

[plugins]
# Empty `enabled` means: run every plugin whose required binary is installed.
enabled = []
disabled = []

# [plugins.semgrep]
# config = ["p/security-audit", "p/owasp-top-ten"]
# timeout_secs = 300

[policy]
# Empty means: load whatever framework detection finds.
packs = []
disabled_controls = []

[ai]
# Quoll is fully functional with AI disabled. Turn this on to investigate
# high-confidence hypotheses that deterministic tooling cannot settle.
enabled = false
# provider = "openai"

# [ai.models]
# investigate = "gpt-5.6-sol-high"
# report = "gpt-5.6-luna"

# [ai.providers.openai]
# kind = "openai"
# api_key_env = "OPENAI_API_KEY"

# [ai.providers.ollama]
# kind = "ollama"
# base_url = "http://localhost:11434"

[report]
formats = ["markdown"]

[suppress]
rules = []
paths = []

# [[suppress.entries]]
# id = "semgrep:javascript.express.security.audit.express-cookie-session-no-secure"
# path = "examples/**"
# reason = "example app, not deployed"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_usable_with_no_file() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert!(!config.ai_enabled(), "AI must be opt-in");
        assert!(config.graph.enabled);
    }

    #[test]
    fn template_parses_and_validates() {
        let config: Config = toml::from_str(TEMPLATE).expect("template must be valid TOML");
        assert!(config.validate().is_ok());
        assert_eq!(config.scan.profile, Profile::Balanced);
    }

    #[test]
    fn rejects_ai_enabled_without_provider() {
        let config: Config = toml::from_str("[ai]\nenabled = true\n").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_provider_reference_with_no_definition() {
        let config: Config =
            toml::from_str("[ai]\nenabled = true\nprovider = \"openai\"\n").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_fully_specified_ai_block() {
        let config: Config = toml::from_str(
            r#"
            [ai]
            enabled = true
            provider = "openai"
            [ai.providers.openai]
            kind = "openai"
            api_key_env = "OPENAI_API_KEY"
            "#,
        )
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_suppression_without_reason() {
        let config: Config = toml::from_str(
            r#"
            [[suppress.entries]]
            id = "rule"
            reason = "  "
            "#,
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unknown_report_format() {
        let config: Config = toml::from_str("[report]\nformats = [\"pdf\"]\n").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn plugin_allowlist_and_denylist_compose() {
        let plugins: PluginsConfig = toml::from_str(
            r#"
            enabled = ["semgrep", "gitleaks"]
            disabled = ["gitleaks"]
            "#,
        )
        .unwrap();
        assert!(plugins.is_permitted("semgrep"));
        assert!(!plugins.is_permitted("gitleaks"));
        assert!(!plugins.is_permitted("trivy"), "allowlist excludes the rest");
    }

    #[test]
    fn per_plugin_enable_overrides_allowlist() {
        let plugins: PluginsConfig = toml::from_str(
            r#"
            enabled = ["semgrep"]
            [trivy]
            enabled = true
            "#,
        )
        .unwrap();
        assert!(plugins.is_permitted("trivy"));
    }

    #[test]
    fn fast_profile_disables_ai_even_when_configured() {
        let mut config = Config::default();
        config.ai.enabled = true;
        config.scan.profile = Profile::Fast;
        assert!(!config.ai_enabled());
    }

    #[test]
    fn explicit_threshold_overrides_profile() {
        let mut config = Config::default();
        config.ai.investigation_threshold = Some(Confidence::new(0.1));
        assert_eq!(config.investigation_threshold(), Confidence::new(0.1));
    }
}
