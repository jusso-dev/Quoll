use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A continuous integration provider, identified from files in the repository.
///
/// This is the static half of CI awareness. The runtime half — am I executing inside a
/// pipeline right now, and against which base ref — is environment-variable inspection and
/// belongs with the scan orchestrator, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CiProvider {
    GitHubActions,
    GitLabCi,
    AzureDevOps,
    CircleCi,
    Jenkins,
    Buildkite,
    TravisCi,
    Bitbucket,
    Drone,
}

impl CiProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            CiProvider::GitHubActions => "github-actions",
            CiProvider::GitLabCi => "gitlab-ci",
            CiProvider::AzureDevOps => "azure-devops",
            CiProvider::CircleCi => "circleci",
            CiProvider::Jenkins => "jenkins",
            CiProvider::Buildkite => "buildkite",
            CiProvider::TravisCi => "travis-ci",
            CiProvider::Bitbucket => "bitbucket-pipelines",
            CiProvider::Drone => "drone",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            CiProvider::GitHubActions => "GitHub Actions",
            CiProvider::GitLabCi => "GitLab CI",
            CiProvider::AzureDevOps => "Azure DevOps",
            CiProvider::CircleCi => "CircleCI",
            CiProvider::Jenkins => "Jenkins",
            CiProvider::Buildkite => "Buildkite",
            CiProvider::TravisCi => "Travis CI",
            CiProvider::Bitbucket => "Bitbucket Pipelines",
            CiProvider::Drone => "Drone",
        }
    }

    /// Whether Quoll can emit native annotations for this provider.
    ///
    /// Everything else still gets SARIF and an exit code, which is enough to gate a build.
    pub fn supports_annotations(self) -> bool {
        matches!(
            self,
            CiProvider::GitHubActions | CiProvider::GitLabCi | CiProvider::AzureDevOps
        )
    }
}

impl fmt::Display for CiProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A CI provider found in the repository, with the file that proved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiDetection {
    pub provider: CiProvider,
    pub config: PathBuf,
}

/// Identify CI providers from repository-relative paths.
///
/// Path-based only: reading and parsing every workflow file would cost more than the answer
/// is worth, and the file's existence is the signal.
pub fn detect(files: &[PathBuf]) -> Vec<CiDetection> {
    let mut found: Vec<CiDetection> = Vec::new();

    for path in files {
        let key = path.to_string_lossy().replace('\\', "/");
        let provider = match provider_for(&key, path) {
            Some(provider) => provider,
            None => continue,
        };
        // One detection per provider; the first config file found is the one cited.
        if !found.iter().any(|d| d.provider == provider) {
            found.push(CiDetection {
                provider,
                config: path.clone(),
            });
        }
    }

    found.sort_by_key(|d| d.provider);
    found
}

fn provider_for(key: &str, path: &Path) -> Option<CiProvider> {
    let name = path.file_name()?.to_str()?;

    // GitHub Actions is a directory convention rather than a fixed file name.
    if key.starts_with(".github/workflows/")
        && (name.ends_with(".yml") || name.ends_with(".yaml"))
    {
        return Some(CiProvider::GitHubActions);
    }
    if key.starts_with(".circleci/") && name.starts_with("config.") {
        return Some(CiProvider::CircleCi);
    }
    if key.starts_with(".buildkite/") && (name.ends_with(".yml") || name.ends_with(".yaml")) {
        return Some(CiProvider::Buildkite);
    }

    Some(match key {
        ".gitlab-ci.yml" | ".gitlab-ci.yaml" => CiProvider::GitLabCi,
        "azure-pipelines.yml" | "azure-pipelines.yaml" => CiProvider::AzureDevOps,
        "Jenkinsfile" => CiProvider::Jenkins,
        ".travis.yml" => CiProvider::TravisCi,
        "bitbucket-pipelines.yml" => CiProvider::Bitbucket,
        ".drone.yml" => CiProvider::Drone,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(items: &[&str]) -> Vec<PathBuf> {
        items.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn finds_github_actions_workflows() {
        let found = detect(&paths(&[".github/workflows/ci.yml", "src/main.rs"]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].provider, CiProvider::GitHubActions);
        assert_eq!(found[0].config, PathBuf::from(".github/workflows/ci.yml"));
    }

    #[test]
    fn a_provider_is_reported_once_however_many_configs_it_has() {
        let found = detect(&paths(&[
            ".github/workflows/ci.yml",
            ".github/workflows/release.yaml",
            ".github/workflows/nightly.yml",
        ]));
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn finds_every_fixed_name_provider() {
        let found = detect(&paths(&[
            ".gitlab-ci.yml",
            "azure-pipelines.yml",
            "Jenkinsfile",
            ".travis.yml",
            "bitbucket-pipelines.yml",
            ".drone.yml",
            ".circleci/config.yml",
            ".buildkite/pipeline.yml",
        ]));
        let providers: Vec<CiProvider> = found.iter().map(|d| d.provider).collect();
        for expected in [
            CiProvider::GitLabCi,
            CiProvider::AzureDevOps,
            CiProvider::Jenkins,
            CiProvider::TravisCi,
            CiProvider::Bitbucket,
            CiProvider::Drone,
            CiProvider::CircleCi,
            CiProvider::Buildkite,
        ] {
            assert!(providers.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn non_yaml_files_in_the_workflow_directory_are_ignored() {
        let found = detect(&paths(&[".github/workflows/README.md", ".github/dependabot.yml"]));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_repository_with_no_ci_yields_nothing() {
        assert!(detect(&paths(&["src/main.rs", "Cargo.toml"])).is_empty());
    }

    #[test]
    fn results_are_ordered_deterministically() {
        let a = detect(&paths(&["Jenkinsfile", ".gitlab-ci.yml"]));
        let b = detect(&paths(&[".gitlab-ci.yml", "Jenkinsfile"]));
        assert_eq!(a, b);
    }

    #[test]
    fn only_some_providers_get_native_annotations() {
        assert!(CiProvider::GitHubActions.supports_annotations());
        assert!(!CiProvider::Jenkins.supports_annotations());
    }
}
