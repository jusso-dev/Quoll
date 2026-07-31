use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::Confidence;

/// Source languages Quoll can reason about structurally.
///
/// `Other` keeps unknown languages representable so that detection never drops a file
/// silently — it just means no tree-sitter grammar is wired up for it yet.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    JavaScript,
    TypeScript,
    Tsx,
    Python,
    Go,
    Java,
    Ruby,
    Php,
    CSharp,
    Kotlin,
    Swift,
    Scala,
    Elixir,
    Shell,
    Sql,
    Hcl,
    Yaml,
    Json,
    Toml,
    Dockerfile,
    Other(String),
}

impl Language {
    pub fn as_str(&self) -> &str {
        match self {
            Language::Rust => "rust",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
            Language::Tsx => "tsx",
            Language::Python => "python",
            Language::Go => "go",
            Language::Java => "java",
            Language::Ruby => "ruby",
            Language::Php => "php",
            Language::CSharp => "csharp",
            Language::Kotlin => "kotlin",
            Language::Swift => "swift",
            Language::Scala => "scala",
            Language::Elixir => "elixir",
            Language::Shell => "shell",
            Language::Sql => "sql",
            Language::Hcl => "hcl",
            Language::Yaml => "yaml",
            Language::Json => "json",
            Language::Toml => "toml",
            Language::Dockerfile => "dockerfile",
            Language::Other(name) => name,
        }
    }

    /// Best-effort language identification from a path.
    ///
    /// Extension-based, because opening every file to sniff content costs more than the
    /// accuracy is worth at repository scale.
    pub fn from_path(path: &Path) -> Option<Language> {
        let name = path.file_name()?.to_str()?;
        if name == "Dockerfile" || name.starts_with("Dockerfile.") {
            return Some(Language::Dockerfile);
        }
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "rs" => Language::Rust,
            "js" | "mjs" | "cjs" | "jsx" => Language::JavaScript,
            "ts" | "mts" | "cts" => Language::TypeScript,
            "tsx" => Language::Tsx,
            "py" | "pyi" => Language::Python,
            "go" => Language::Go,
            "java" => Language::Java,
            "rb" | "rake" => Language::Ruby,
            "php" => Language::Php,
            "cs" => Language::CSharp,
            "kt" | "kts" => Language::Kotlin,
            "swift" => Language::Swift,
            "scala" | "sc" => Language::Scala,
            "ex" | "exs" => Language::Elixir,
            "sh" | "bash" | "zsh" => Language::Shell,
            "sql" => Language::Sql,
            "tf" | "tfvars" | "hcl" => Language::Hcl,
            "yaml" | "yml" => Language::Yaml,
            "json" => Language::Json,
            "toml" => Language::Toml,
            _ => return None,
        })
    }

    /// Whether Quoll has a tree-sitter grammar for structural analysis.
    pub fn has_grammar(&self) -> bool {
        matches!(
            self,
            Language::Rust
                | Language::JavaScript
                | Language::TypeScript
                | Language::Tsx
                | Language::Python
                | Language::Go
                | Language::Java
                | Language::Ruby
                | Language::Php
                | Language::CSharp
        )
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Language {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_ascii_lowercase();
        Ok(match lower.as_str() {
            "rust" => Language::Rust,
            "javascript" | "js" => Language::JavaScript,
            "typescript" | "ts" => Language::TypeScript,
            "tsx" => Language::Tsx,
            "python" | "py" => Language::Python,
            "go" | "golang" => Language::Go,
            "java" => Language::Java,
            "ruby" | "rb" => Language::Ruby,
            "php" => Language::Php,
            "csharp" | "c#" | "cs" => Language::CSharp,
            "kotlin" => Language::Kotlin,
            "swift" => Language::Swift,
            "scala" => Language::Scala,
            "elixir" => Language::Elixir,
            "shell" | "bash" | "sh" => Language::Shell,
            "sql" => Language::Sql,
            "hcl" | "terraform" => Language::Hcl,
            "yaml" | "yml" => Language::Yaml,
            "json" => Language::Json,
            "toml" => Language::Toml,
            "dockerfile" | "docker" => Language::Dockerfile,
            _ => Language::Other(lower),
        })
    }
}

/// Package ecosystem, which decides which dependency scanners are worth running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo,
    Npm,
    Pypi,
    Go,
    Maven,
    Gradle,
    RubyGems,
    Composer,
    NuGet,
    Hex,
    Terraform,
    Docker,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Go => "go",
            Ecosystem::Maven => "maven",
            Ecosystem::Gradle => "gradle",
            Ecosystem::RubyGems => "rubygems",
            Ecosystem::Composer => "composer",
            Ecosystem::NuGet => "nuget",
            Ecosystem::Hex => "hex",
            Ecosystem::Terraform => "terraform",
            Ecosystem::Docker => "docker",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A detected library, runtime or service, with the evidence that proved it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Technology {
    /// Canonical identifier, e.g. `nextjs`, `better-auth`, `postgresql`.
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub confidence: Confidence,
    /// Human-readable reasons, e.g. `package.json declares "next": "^16.0.0"`.
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl Technology {
    pub fn new(id: impl Into<String>, name: impl Into<String>, confidence: Confidence) -> Self {
        Technology {
            id: id.into(),
            name: name.into(),
            version: None,
            confidence,
            evidence: Vec::new(),
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn because(mut self, reason: impl Into<String>) -> Self {
        self.evidence.push(reason.into());
        self
    }

    /// Major version as an integer, for policy packs that gate on it (`nextjs>=15`).
    pub fn major_version(&self) -> Option<u32> {
        let v = self.version.as_ref()?;
        let digits: String = v
            .trim_start_matches(['^', '~', '>', '=', '<', 'v', ' '])
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }
}

/// A detected application framework — the unit that policy packs bind to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Framework {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub language: Language,
    pub confidence: Confidence,
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl Framework {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        language: Language,
        confidence: Confidence,
    ) -> Self {
        Framework {
            id: id.into(),
            name: name.into(),
            version: None,
            language,
            confidence,
            evidence: Vec::new(),
        }
    }

    pub fn with_version(mut self, version: Option<String>) -> Self {
        self.version = version;
        self
    }

    pub fn because(mut self, reason: impl Into<String>) -> Self {
        self.evidence.push(reason.into());
        self
    }
}

/// Everything detection learned about a repository.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TechStack {
    #[serde(default)]
    pub languages: Vec<(Language, usize)>,
    #[serde(default)]
    pub ecosystems: BTreeSet<Ecosystem>,
    #[serde(default)]
    pub frameworks: Vec<Framework>,
    #[serde(default)]
    pub technologies: Vec<Technology>,
}

impl TechStack {
    pub fn primary_language(&self) -> Option<&Language> {
        self.languages
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang)
    }

    pub fn has_framework(&self, id: &str) -> bool {
        self.frameworks.iter().any(|f| f.id == id)
    }

    pub fn framework(&self, id: &str) -> Option<&Framework> {
        self.frameworks.iter().find(|f| f.id == id)
    }

    pub fn has_technology(&self, id: &str) -> bool {
        self.technologies.iter().any(|t| t.id == id)
    }

    pub fn technology(&self, id: &str) -> Option<&Technology> {
        self.technologies.iter().find(|t| t.id == id)
    }

    pub fn uses_language(&self, lang: &Language) -> bool {
        self.languages.iter().any(|(l, _)| l == lang)
    }

    /// Sort detections by confidence so reports lead with the strongest signals.
    pub fn sort(&mut self) {
        self.languages.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        self.frameworks
            .sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.id.cmp(&b.id)));
        self.technologies
            .sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.id.cmp(&b.id)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_languages_by_extension() {
        assert_eq!(
            Language::from_path(Path::new("src/main.rs")),
            Some(Language::Rust)
        );
        assert_eq!(
            Language::from_path(Path::new("app/page.tsx")),
            Some(Language::Tsx)
        );
        assert_eq!(Language::from_path(Path::new("README")), None);
    }

    #[test]
    fn recognises_dockerfile_variants() {
        assert_eq!(
            Language::from_path(Path::new("Dockerfile")),
            Some(Language::Dockerfile)
        );
        assert_eq!(
            Language::from_path(Path::new("Dockerfile.prod")),
            Some(Language::Dockerfile)
        );
    }

    #[test]
    fn parses_major_from_semver_ranges() {
        let t = Technology::new("next", "Next.js", Confidence::CERTAIN).with_version("^16.1.2");
        assert_eq!(t.major_version(), Some(16));
        let t = Technology::new("next", "Next.js", Confidence::CERTAIN).with_version("v3.0.0");
        assert_eq!(t.major_version(), Some(3));
    }

    #[test]
    fn primary_language_is_the_most_common() {
        let stack = TechStack {
            languages: vec![(Language::Rust, 3), (Language::TypeScript, 40)],
            ..Default::default()
        };
        assert_eq!(stack.primary_language(), Some(&Language::TypeScript));
    }
}
