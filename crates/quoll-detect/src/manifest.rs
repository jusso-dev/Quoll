use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use quoll_core::{Ecosystem, Result};

/// A package manifest, reduced to the parts detection cares about.
///
/// Parsed leniently. Manifests in the wild carry comments, unknown keys and inherited
/// workspace tables, and a strict deserialiser would refuse to read a file that the
/// package manager itself accepts — turning a detection miss into a scan failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub path: PathBuf,
    pub ecosystem: Option<Ecosystem>,
    pub name: Option<String>,
    pub version: Option<String>,
    /// Declared runtime dependencies: name to version specification.
    pub dependencies: BTreeMap<String, String>,
    /// Development and build dependencies, kept separate because a scanner in
    /// `devDependencies` says nothing about what ships.
    pub dev_dependencies: BTreeMap<String, String>,
    /// npm `scripts`, which reveal build tooling no dependency list mentions.
    pub scripts: BTreeMap<String, String>,
}

impl Manifest {
    /// Version specification for a dependency, runtime first.
    pub fn dependency(&self, name: &str) -> Option<&str> {
        self.dependencies
            .get(name)
            .or_else(|| self.dev_dependencies.get(name))
            .map(String::as_str)
    }

    pub fn has_dependency(&self, name: &str) -> bool {
        self.dependency(name).is_some()
    }

    /// Whether the dependency is a runtime one, as opposed to development-only.
    pub fn is_runtime_dependency(&self, name: &str) -> bool {
        self.dependencies.contains_key(name)
    }

    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty() && self.dev_dependencies.is_empty()
    }
}

/// Whether a file name is a manifest Quoll knows how to read.
pub fn is_manifest(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some(
            "package.json"
                | "Cargo.toml"
                | "go.mod"
                | "requirements.txt"
                | "pyproject.toml"
                | "Gemfile"
                | "composer.json"
                | "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
        )
    )
}

/// Parse a manifest. Returns `None` for files this module does not handle.
///
/// A manifest that fails to parse is reported as `None` with a debug log rather than as an
/// error: a malformed `package.json` in some vendored corner must not abort a scan.
pub fn parse(path: &Path, text: &str) -> Result<Option<Manifest>> {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => return Ok(None),
    };

    let manifest = match name {
        "package.json" => parse_package_json(path, text),
        "Cargo.toml" => parse_cargo_toml(path, text),
        "go.mod" => parse_go_mod(path, text),
        "requirements.txt" => Some(bare(path, Ecosystem::Pypi)),
        "pyproject.toml" => Some(bare(path, Ecosystem::Pypi)),
        "Gemfile" => Some(bare(path, Ecosystem::RubyGems)),
        "composer.json" => Some(bare(path, Ecosystem::Composer)),
        "pom.xml" => Some(bare(path, Ecosystem::Maven)),
        "build.gradle" | "build.gradle.kts" => Some(bare(path, Ecosystem::Gradle)),
        _ => return Ok(None),
    };

    if manifest.is_none() {
        tracing::debug!(path = %path.display(), "manifest could not be parsed, skipping");
    }
    Ok(manifest)
}

/// A manifest whose ecosystem is known but whose dependencies are not parsed yet.
///
/// Recording the ecosystem still matters: it decides which dependency scanners are worth
/// running, and that decision does not need the dependency list.
fn bare(path: &Path, ecosystem: Ecosystem) -> Manifest {
    Manifest {
        path: path.to_path_buf(),
        ecosystem: Some(ecosystem),
        ..Default::default()
    }
}

fn parse_package_json(path: &Path, text: &str) -> Option<Manifest> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;

    let string_map = |key: &str| -> BTreeMap<String, String> {
        object
            .get(key)
            .and_then(|v| v.as_object())
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };

    let mut dependencies = string_map("dependencies");
    // Peer dependencies are runtime requirements for a library; treating them as absent
    // would miss the framework in every published package.
    dependencies.extend(string_map("peerDependencies"));

    Some(Manifest {
        path: path.to_path_buf(),
        ecosystem: Some(Ecosystem::Npm),
        name: object.get("name").and_then(|v| v.as_str()).map(String::from),
        version: object
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from),
        dependencies,
        dev_dependencies: string_map("devDependencies"),
        scripts: string_map("scripts"),
    })
}

fn parse_cargo_toml(path: &Path, text: &str) -> Option<Manifest> {
    let value: toml::Value = toml::from_str(text).ok()?;
    let table = value.as_table()?;

    // A dependency is either `name = "1.0"` or `name = { version = "1.0", ... }`, and
    // workspace-inherited ones carry no version at all.
    let dependency_map = |key: &str| -> BTreeMap<String, String> {
        table
            .get(key)
            .and_then(|v| v.as_table())
            .map(|deps| {
                deps.iter()
                    .map(|(name, spec)| {
                        let version = match spec {
                            toml::Value::String(version) => version.clone(),
                            toml::Value::Table(detail) => detail
                                .get("version")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                                .unwrap_or_else(|| {
                                    if detail.get("workspace").is_some() {
                                        "workspace".to_string()
                                    } else {
                                        "*".to_string()
                                    }
                                }),
                            _ => "*".to_string(),
                        };
                        (name.clone(), version)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let package = table.get("package").and_then(|v| v.as_table());
    let mut dependencies = dependency_map("dependencies");

    // A virtual workspace root declares its dependencies under `[workspace.dependencies]`
    // and has no `[dependencies]` of its own.
    if let Some(workspace) = table.get("workspace").and_then(|v| v.as_table()) {
        if let Some(shared) = workspace.get("dependencies").and_then(|v| v.as_table()) {
            for (name, spec) in shared {
                let version = match spec {
                    toml::Value::String(version) => version.clone(),
                    toml::Value::Table(detail) => detail
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| "*".to_string()),
                    _ => "*".to_string(),
                };
                dependencies.entry(name.clone()).or_insert(version);
            }
        }
    }

    let mut dev_dependencies = dependency_map("dev-dependencies");
    dev_dependencies.extend(dependency_map("build-dependencies"));

    Some(Manifest {
        path: path.to_path_buf(),
        ecosystem: Some(Ecosystem::Cargo),
        name: package
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .map(String::from),
        version: package
            .and_then(|p| p.get("version"))
            .and_then(|v| v.as_str())
            .map(String::from),
        dependencies,
        dev_dependencies,
        scripts: BTreeMap::new(),
    })
}

/// `go.mod` is a line-oriented format with no TOML or JSON parser to lean on.
fn parse_go_mod(path: &Path, text: &str) -> Option<Manifest> {
    let mut manifest = bare(path, Ecosystem::Go);
    let mut in_require_block = false;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("module ") {
            manifest.name = line.strip_prefix("module ").map(|s| s.trim().to_string());
        } else if line.starts_with("require (") {
            in_require_block = true;
        } else if in_require_block && line == ")" {
            in_require_block = false;
        } else {
            let requirement = if in_require_block {
                Some(line)
            } else {
                line.strip_prefix("require ")
            };
            if let Some(requirement) = requirement {
                let mut parts = requirement.split_whitespace();
                if let (Some(name), Some(version)) = (parts.next(), parts.next()) {
                    if !name.is_empty() && !name.starts_with("//") {
                        manifest
                            .dependencies
                            .insert(name.to_string(), version.to_string());
                    }
                }
            }
        }
    }
    Some(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(name: &str) -> PathBuf {
        PathBuf::from(name)
    }

    #[test]
    fn recognises_the_manifests_it_handles() {
        assert!(is_manifest(&at("package.json")));
        assert!(is_manifest(&at("Cargo.toml")));
        assert!(!is_manifest(&at("Cargo.lock")));
        assert!(!is_manifest(&at("src/main.rs")));
    }

    #[test]
    fn reads_package_json_dependencies() {
        let text = r#"{
            "name": "web",
            "version": "0.1.0",
            "dependencies": { "next": "^15.2.0", "better-auth": "1.2.3" },
            "devDependencies": { "typescript": "^5.4.0" },
            "scripts": { "build": "next build" }
        }"#;
        let manifest = parse(&at("package.json"), text).unwrap().unwrap();

        assert_eq!(manifest.ecosystem, Some(Ecosystem::Npm));
        assert_eq!(manifest.name.as_deref(), Some("web"));
        assert_eq!(manifest.dependency("next"), Some("^15.2.0"));
        assert_eq!(manifest.dependency("typescript"), Some("^5.4.0"));
        assert!(manifest.is_runtime_dependency("next"));
        assert!(!manifest.is_runtime_dependency("typescript"));
        assert_eq!(manifest.scripts.get("build").unwrap(), "next build");
    }

    #[test]
    fn peer_dependencies_count_as_runtime() {
        let text = r#"{ "peerDependencies": { "react": "^19.0.0" } }"#;
        let manifest = parse(&at("package.json"), text).unwrap().unwrap();
        assert!(manifest.is_runtime_dependency("react"));
    }

    #[test]
    fn reads_cargo_dependencies_in_both_spellings() {
        let text = r#"
            [package]
            name = "api"
            version = "0.3.1"

            [dependencies]
            axum = "0.8"
            tokio = { version = "1", features = ["full"] }
            shared = { path = "../shared" }
            inherited = { workspace = true }

            [dev-dependencies]
            insta = "1"
        "#;
        let manifest = parse(&at("Cargo.toml"), text).unwrap().unwrap();

        assert_eq!(manifest.ecosystem, Some(Ecosystem::Cargo));
        assert_eq!(manifest.name.as_deref(), Some("api"));
        assert_eq!(manifest.dependency("axum"), Some("0.8"));
        assert_eq!(manifest.dependency("tokio"), Some("1"));
        assert_eq!(manifest.dependency("shared"), Some("*"));
        assert_eq!(manifest.dependency("inherited"), Some("workspace"));
        assert!(!manifest.is_runtime_dependency("insta"));
    }

    #[test]
    fn a_virtual_workspace_root_still_yields_dependencies() {
        let text = r#"
            [workspace]
            members = ["crates/*"]

            [workspace.dependencies]
            axum = "0.8"
        "#;
        let manifest = parse(&at("Cargo.toml"), text).unwrap().unwrap();
        assert_eq!(manifest.dependency("axum"), Some("0.8"));
    }

    #[test]
    fn reads_go_mod_requirements() {
        let text = "module github.com/me/api\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/lib/pq v1.10.9\n)\n";
        let manifest = parse(&at("go.mod"), text).unwrap().unwrap();

        assert_eq!(manifest.ecosystem, Some(Ecosystem::Go));
        assert_eq!(manifest.name.as_deref(), Some("github.com/me/api"));
        assert_eq!(manifest.dependency("github.com/gin-gonic/gin"), Some("v1.9.1"));
        assert_eq!(manifest.dependencies.len(), 2);
    }

    #[test]
    fn unparseable_manifests_are_skipped_not_fatal() {
        let manifest = parse(&at("package.json"), "{ this is not json").unwrap();
        assert!(manifest.is_none());
    }

    #[test]
    fn unknown_files_are_not_manifests() {
        assert!(parse(&at("README.md"), "# hi").unwrap().is_none());
    }

    #[test]
    fn ecosystem_only_manifests_record_the_ecosystem() {
        let manifest = parse(&at("Gemfile"), "gem 'rails'\n").unwrap().unwrap();
        assert_eq!(manifest.ecosystem, Some(Ecosystem::RubyGems));
        assert!(manifest.is_empty());
    }
}
