use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use quoll_core::config::PluginSettings;
use quoll_core::{Language, Profile, TechStack};

/// Everything a plugin is allowed to know about the scan it is participating in.
///
/// Plugins receive a reference to this and nothing else. They cannot see other plugins'
/// results, cannot read global state and cannot influence scheduling — which is what
/// keeps them independently testable and safe to run concurrently.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Absolute repository root. All relative paths resolve against this.
    root: PathBuf,
    /// Repository-relative paths in scope for this scan, after include/exclude filtering.
    files: Vec<PathBuf>,
    /// Subset of `files` changed against the base ref, when scanning incrementally.
    changed_files: Option<Vec<PathBuf>>,
    tech_stack: TechStack,
    profile: Profile,
    /// Per-plugin configuration for the plugin being invoked.
    settings: PluginSettings,
    timeout: Duration,
    /// When true, plugins must not make network calls.
    offline: bool,
    /// Scratch directory, cleaned up by the orchestrator after the run.
    work_dir: PathBuf,
    /// Base URL of a running instance, for dynamic validators.
    target_url: Option<String>,
}

impl ScanContext {
    pub fn new(root: impl Into<PathBuf>, profile: Profile) -> ScanContext {
        let root = root.into();
        let work_dir = root.join(quoll_core::config::STATE_DIR).join("work");
        ScanContext {
            root,
            files: Vec::new(),
            changed_files: None,
            tech_stack: TechStack::default(),
            profile,
            settings: PluginSettings::default(),
            timeout: profile.plugin_timeout(),
            offline: false,
            work_dir,
            target_url: None,
        }
    }

    pub fn with_files(mut self, files: Vec<PathBuf>) -> Self {
        self.files = files;
        self
    }

    pub fn with_changed_files(mut self, changed: Option<Vec<PathBuf>>) -> Self {
        self.changed_files = changed;
        self
    }

    pub fn with_tech_stack(mut self, stack: TechStack) -> Self {
        self.tech_stack = stack;
        self
    }

    pub fn with_settings(mut self, settings: PluginSettings) -> Self {
        if let Some(secs) = settings.timeout_secs {
            self.timeout = Duration::from_secs(secs);
        }
        self.settings = settings;
        self
    }

    pub fn with_work_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.work_dir = dir.into();
        self
    }

    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    pub fn with_target_url(mut self, url: Option<String>) -> Self {
        self.target_url = url;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    pub fn changed_files(&self) -> Option<&[PathBuf]> {
        self.changed_files.as_deref()
    }

    /// Files a plugin should actually analyse.
    ///
    /// Collapses the incremental/full distinction so plugins never have to think about
    /// it: in `fast` profiles this is the changed set, otherwise the whole scope.
    pub fn target_files(&self) -> &[PathBuf] {
        match (&self.changed_files, self.profile.incremental()) {
            (Some(changed), true) => changed,
            _ => &self.files,
        }
    }

    pub fn tech_stack(&self) -> &TechStack {
        &self.tech_stack
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    pub fn settings(&self) -> &PluginSettings {
        &self.settings
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn is_offline(&self) -> bool {
        self.offline
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    pub fn target_url(&self) -> Option<&str> {
        self.target_url.as_deref()
    }

    /// Absolute path for a repository-relative path.
    pub fn absolute(&self, relative: &Path) -> PathBuf {
        self.root.join(relative)
    }

    /// Whether the repository contains any file in the given language.
    pub fn has_language(&self, language: &Language) -> bool {
        self.tech_stack.uses_language(language)
    }

    /// Whether a file exists at the repository root, e.g. `Cargo.lock`.
    pub fn has_root_file(&self, name: &str) -> bool {
        self.root.join(name).exists()
    }

    /// Repository-relative paths whose file name matches, e.g. every `package.json`.
    pub fn files_named(&self, name: &str) -> Vec<PathBuf> {
        self.files
            .iter()
            .filter(|p| p.file_name().and_then(|n| n.to_str()) == Some(name))
            .cloned()
            .collect()
    }

    /// Repository-relative paths with the given extension, e.g. `tf`.
    pub fn files_with_extension(&self, extension: &str) -> Vec<PathBuf> {
        self.files
            .iter()
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(extension))
            .cloned()
            .collect()
    }

    /// Environment variables to apply to this plugin's subprocess.
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.settings.env
    }

    /// Create the scratch directory on demand.
    pub fn ensure_work_dir(&self) -> quoll_core::Result<&Path> {
        std::fs::create_dir_all(&self.work_dir)
            .map_err(|e| quoll_core::Error::io(self.work_dir.clone(), e))?;
        Ok(&self.work_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(profile: Profile) -> ScanContext {
        ScanContext::new("/repo", profile)
            .with_files(vec![
                PathBuf::from("src/main.rs"),
                PathBuf::from("package.json"),
                PathBuf::from("infra/main.tf"),
            ])
            .with_changed_files(Some(vec![PathBuf::from("src/main.rs")]))
    }

    #[test]
    fn fast_profile_narrows_to_changed_files() {
        assert_eq!(context(Profile::Fast).target_files().len(), 1);
    }

    #[test]
    fn full_profiles_analyse_everything_in_scope() {
        assert_eq!(context(Profile::Deep).target_files().len(), 3);
    }

    #[test]
    fn falls_back_to_full_scope_when_no_diff_is_available() {
        let ctx = context(Profile::Fast).with_changed_files(None);
        assert_eq!(ctx.target_files().len(), 3);
    }

    #[test]
    fn finds_files_by_name_and_extension() {
        let ctx = context(Profile::Balanced);
        assert_eq!(ctx.files_named("package.json").len(), 1);
        assert_eq!(ctx.files_with_extension("tf").len(), 1);
        assert!(ctx.files_named("Cargo.toml").is_empty());
    }

    #[test]
    fn plugin_timeout_override_wins_over_profile() {
        let settings = PluginSettings {
            timeout_secs: Some(7),
            ..Default::default()
        };
        let ctx = ScanContext::new("/repo", Profile::Deep).with_settings(settings);
        assert_eq!(ctx.timeout(), Duration::from_secs(7));
    }
}
