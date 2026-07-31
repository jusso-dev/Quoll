use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::str::FromStr;

use quoll_core::config::Config;
use quoll_core::{Confidence, Ecosystem, Language, Result, TechStack};
use quoll_graph::{Parsers, Walker};

use crate::ci::{self, CiDetection, CiProvider};
use crate::component::{Component, Role};
use crate::manifest::{self, Manifest};
use crate::rules;

/// Confidence assigned to each kind of signal.
///
/// A runtime dependency is close to proof: the package manager will install it and the
/// application will not start without it. A development dependency is weaker — a test
/// helper says little about what ships. An import is corroboration on its own, because in
/// a monorepo the declaring manifest may be two directories up.
const RUNTIME_DEPENDENCY: f64 = 0.9;
const DEV_DEPENDENCY: f64 = 0.6;
const IMPORT: f64 = 0.55;
const CONVENTION: f64 = 0.8;

/// Default cap on files parsed for imports.
///
/// Detection runs before indexing and must stay fast. Five hundred files is enough to see
/// every framework a repository uses; parsing the whole tree would duplicate the indexer's
/// work for no additional answer.
const DEFAULT_MAX_IMPORT_FILES: usize = 500;

/// Everything detection learned about a repository.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Detection {
    /// Detected components, strongest first.
    pub components: Vec<Component>,
    /// File counts per language, most common first.
    pub languages: Vec<(Language, usize)>,
    pub ecosystems: BTreeSet<Ecosystem>,
    pub ci: Vec<CiDetection>,
    pub manifests: Vec<Manifest>,
    /// True when the import scan hit its file cap, so absence of a component is not
    /// evidence of absence.
    pub imports_truncated: bool,
}

impl Detection {
    pub fn get(&self, id: &str) -> Option<&Component> {
        self.components.iter().find(|c| c.id == id)
    }

    pub fn has(&self, id: &str) -> bool {
        self.get(id).is_some()
    }

    /// Components filling a given role, strongest first.
    pub fn with_role(&self, role: Role) -> Vec<&Component> {
        self.components.iter().filter(|c| c.role == role).collect()
    }

    /// The most likely web framework, when there is one.
    pub fn primary_framework(&self) -> Option<&Component> {
        self.with_role(Role::Framework).into_iter().next()
    }

    pub fn auth(&self) -> Option<&Component> {
        self.with_role(Role::Auth).into_iter().next()
    }

    pub fn orm(&self) -> Option<&Component> {
        self.with_role(Role::Orm).into_iter().next()
    }

    pub fn primary_language(&self) -> Option<&Language> {
        self.languages.first().map(|(language, _)| language)
    }

    pub fn ci_providers(&self) -> Vec<CiProvider> {
        self.ci.iter().map(|d| d.provider).collect()
    }

    /// Convert to the shared `TechStack` that plugins and scan contexts speak.
    pub fn to_tech_stack(&self) -> TechStack {
        let mut stack = TechStack {
            languages: self.languages.clone(),
            ecosystems: self.ecosystems.clone(),
            frameworks: Vec::new(),
            technologies: Vec::new(),
        };
        for component in &self.components {
            match component.role {
                Role::Framework => stack.frameworks.push(component.to_framework()),
                _ => stack.technologies.push(component.to_technology()),
            }
        }
        stack.sort();
        stack
    }

    /// One line for the terminal: `typescript · nextjs-app-router · better-auth · drizzle`.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(language) = self.primary_language() {
            parts.push(language.to_string());
        }
        for role in [Role::Framework, Role::Auth, Role::Orm] {
            if let Some(component) = self.with_role(role).into_iter().next() {
                parts.push(component.id.clone());
            }
        }
        if parts.is_empty() {
            "nothing recognised".to_string()
        } else {
            parts.join(" · ")
        }
    }
}

/// Identifies the stack a repository is built on.
///
/// Three signals, in decreasing order of authority: package manifests, framework file
/// conventions, and imports in source code. Each records why it fired, so every detection
/// can be argued with.
#[derive(Debug, Clone)]
pub struct Detector {
    root: PathBuf,
    max_import_files: usize,
    scan_imports: bool,
}

impl Detector {
    pub fn new(root: impl Into<PathBuf>) -> Detector {
        Detector {
            root: root.into(),
            max_import_files: DEFAULT_MAX_IMPORT_FILES,
            scan_imports: true,
        }
    }

    pub fn from_config(config: &Config) -> Detector {
        Detector::new(config.root.clone())
    }

    pub fn max_import_files(mut self, max: usize) -> Detector {
        self.max_import_files = max;
        self
    }

    /// Turn off the import scan. Manifests and conventions alone are enough when speed
    /// matters more than catching a hoisted dependency.
    pub fn scan_imports(mut self, scan: bool) -> Detector {
        self.scan_imports = scan;
        self
    }

    /// Run detection over a set of repository-relative paths.
    pub fn detect(&self, files: &[PathBuf]) -> Result<Detection> {
        let walker = Walker::new(&self.root);
        let mut found: BTreeMap<String, Component> = BTreeMap::new();
        let mut detection = Detection {
            languages: count_languages(files),
            ci: ci::detect(files),
            ..Default::default()
        };

        // 1. Manifests. The strongest signal, and the only one that carries a version.
        for path in files.iter().filter(|p| manifest::is_manifest(p)) {
            let source = match walker.read(path)? {
                Some(source) => source,
                None => continue,
            };
            let parsed = match manifest::parse(path, &source.text)? {
                Some(parsed) => parsed,
                None => continue,
            };
            if let Some(ecosystem) = parsed.ecosystem {
                detection.ecosystems.insert(ecosystem);
            }
            for component in components_from_manifest(&parsed) {
                merge(&mut found, component);
            }
            detection.manifests.push(parsed);
        }

        // 2. Conventions. Directory layouts and configuration files that a manifest cannot
        //    express — most importantly which Next.js router is in use.
        for component in components_from_conventions(files, &found) {
            merge(&mut found, component);
        }

        // 3. Imports. Corroboration, and a safety net for monorepos where the manifest
        //    that declares a package lives somewhere this scan did not look.
        if self.scan_imports {
            let (components, truncated) = self.components_from_imports(&walker, files)?;
            detection.imports_truncated = truncated;
            for component in components {
                merge(&mut found, component);
            }
        }

        detection.components = found.into_values().collect();
        // Strongest first, then by id so that equal-confidence output is stable.
        detection
            .components
            .sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.id.cmp(&b.id)));

        for (language, _) in &detection.languages {
            if let Some(ecosystem) = ecosystem_for_language(language) {
                detection.ecosystems.insert(ecosystem);
            }
        }
        Ok(detection)
    }

    fn components_from_imports(
        &self,
        walker: &Walker,
        files: &[PathBuf],
    ) -> Result<(Vec<Component>, bool)> {
        let mut parsers = Parsers::new();
        let mut components = Vec::new();

        let candidates: Vec<&PathBuf> = files
            .iter()
            .filter(|path| {
                Language::from_path(path)
                    .as_ref()
                    .is_some_and(quoll_graph::parse::is_supported)
            })
            .collect();
        let truncated = candidates.len() > self.max_import_files;

        for path in candidates.into_iter().take(self.max_import_files) {
            let source = match walker.read(path)? {
                Some(source) => source,
                None => continue,
            };
            let parsed = match parsers.parse(&source)? {
                Some(parsed) => parsed,
                None => continue,
            };
            for import in parsed.imports {
                if let Some(rule) = rules::rule_for_import(&import.module) {
                    components.push(
                        Component::new(rule.id, rule.name, rule.role)
                            .with_language(Language::from_str(rule.language).unwrap_or(Language::Other(rule.language.into())))
                            .with_confidence(Confidence::new(IMPORT))
                            .because(format!("{} imports `{}`", path.display(), import.module)),
                    );
                }
            }
        }
        Ok((components, truncated))
    }
}

fn merge(found: &mut BTreeMap<String, Component>, component: Component) {
    match found.get_mut(&component.id) {
        Some(existing) => existing.merge(component),
        None => {
            found.insert(component.id.clone(), component);
        }
    }
}

fn count_languages(files: &[PathBuf]) -> Vec<(Language, usize)> {
    let mut counts: BTreeMap<Language, usize> = BTreeMap::new();
    for path in files {
        if let Some(language) = Language::from_path(path) {
            *counts.entry(language).or_insert(0) += 1;
        }
    }
    let mut languages: Vec<(Language, usize)> = counts.into_iter().collect();
    languages.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    languages
}

fn ecosystem_for_language(language: &Language) -> Option<Ecosystem> {
    Some(match language {
        Language::Rust => Ecosystem::Cargo,
        Language::JavaScript | Language::TypeScript | Language::Tsx => Ecosystem::Npm,
        Language::Python => Ecosystem::Pypi,
        Language::Go => Ecosystem::Go,
        Language::Ruby => Ecosystem::RubyGems,
        Language::Php => Ecosystem::Composer,
        Language::CSharp => Ecosystem::NuGet,
        Language::Hcl => Ecosystem::Terraform,
        Language::Dockerfile => Ecosystem::Docker,
        _ => return None,
    })
}

fn components_from_manifest(manifest: &Manifest) -> Vec<Component> {
    let mut components = Vec::new();
    let describe = manifest.path.display().to_string();

    for (package, version) in manifest.dependencies.iter().chain(&manifest.dev_dependencies) {
        let rule = match rules::rule_for_package(package) {
            Some(rule) => rule,
            None => continue,
        };
        let runtime = manifest.is_runtime_dependency(package);
        let confidence = if runtime {
            RUNTIME_DEPENDENCY
        } else {
            DEV_DEPENDENCY
        };
        let kind = if runtime { "dependency" } else { "dev dependency" };

        components.push(
            Component::new(rule.id, rule.name, rule.role)
                .with_language(
                    Language::from_str(rule.language)
                        .unwrap_or(Language::Other(rule.language.into())),
                )
                .with_version(Some(version.clone()))
                .with_confidence(Confidence::new(confidence))
                .because(format!("{describe} declares `{package}` as a {kind}")),
        );
    }
    components
}

/// Detections that come from file layout rather than from a dependency list.
fn components_from_conventions(
    files: &[PathBuf],
    found: &BTreeMap<String, Component>,
) -> Vec<Component> {
    let keys: BTreeSet<String> = files
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();
    let mut components = Vec::new();

    // Which Next.js router is in use decides which policy pack applies, and nothing in
    // package.json says. The answer is in the directory layout.
    if found.contains_key("nextjs") {
        if let Some(evidence) = first_matching(&keys, |key| {
            is_under(key, "app") && is_router_file(key)
        }) {
            components.push(
                Component::new("nextjs-app-router", "Next.js App Router", Role::Framework)
                    .with_language(Language::TypeScript)
                    .with_version(found.get("nextjs").and_then(|c| c.version.clone()))
                    .with_confidence(Confidence::new(CONVENTION))
                    .because(format!("`{evidence}` is an App Router entry point")),
            );
        }
        if let Some(evidence) = first_matching(&keys, |key| is_under(key, "pages")) {
            components.push(
                Component::new("nextjs-pages-router", "Next.js Pages Router", Role::Framework)
                    .with_language(Language::TypeScript)
                    .with_version(found.get("nextjs").and_then(|c| c.version.clone()))
                    .with_confidence(Confidence::new(CONVENTION))
                    .because(format!("`{evidence}` is under a Pages Router directory")),
            );
        }
    }

    // Configuration files prove an ORM even when the manifest was not in scope.
    if let Some(evidence) = first_matching(&keys, |key| key.ends_with("schema.prisma")) {
        components.push(
            Component::new("prisma", "Prisma", Role::Orm)
                .with_language(Language::TypeScript)
                .with_confidence(Confidence::new(CONVENTION))
                .because(format!("`{evidence}` is a Prisma schema")),
        );
    }
    if let Some(evidence) = first_matching(&keys, |key| {
        key.ends_with("drizzle.config.ts") || key.ends_with("drizzle.config.js")
    }) {
        components.push(
            Component::new("drizzle", "Drizzle ORM", Role::Orm)
                .with_language(Language::TypeScript)
                .with_confidence(Confidence::new(CONVENTION))
                .because(format!("`{evidence}` configures Drizzle")),
        );
    }

    components
}

fn first_matching(keys: &BTreeSet<String>, predicate: impl Fn(&str) -> bool) -> Option<String> {
    keys.iter().find(|key| predicate(key)).cloned()
}

/// Whether a path sits under `directory`, at the repository root or under `src/`.
///
/// Next.js accepts both layouts, and a project that uses `src/app` is no less an App Router
/// project than one that uses `app`.
fn is_under(key: &str, directory: &str) -> bool {
    key.starts_with(&format!("{directory}/")) || key.starts_with(&format!("src/{directory}/"))
}

fn is_router_file(key: &str) -> bool {
    let name = key.rsplit('/').next().unwrap_or(key);
    matches!(
        name,
        "page.tsx"
            | "page.ts"
            | "page.jsx"
            | "page.js"
            | "layout.tsx"
            | "layout.ts"
            | "layout.jsx"
            | "layout.js"
            | "route.ts"
            | "route.js"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Fixture {
            Fixture {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn write(&self, path: &str, contents: &str) -> &Fixture {
            let full = self.dir.path().join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, contents).unwrap();
            self
        }

        fn files(&self) -> Vec<PathBuf> {
            Walker::new(self.dir.path()).discover().unwrap().files
        }

        fn detect(&self) -> Detection {
            Detector::new(self.dir.path()).detect(&self.files()).unwrap()
        }
    }

    fn next_app() -> Fixture {
        let fixture = Fixture::new();
        fixture
            .write(
                "package.json",
                r#"{
                    "name": "web",
                    "dependencies": {
                        "next": "^15.2.0",
                        "better-auth": "^1.2.0",
                        "drizzle-orm": "^0.38.0",
                        "react": "^19.0.0"
                    },
                    "devDependencies": { "typescript": "^5.4.0" }
                }"#,
            )
            .write("app/page.tsx", "export default function Page() {}\n")
            .write(
                "app/api/users/route.ts",
                "import { auth } from 'better-auth/next-js';\nexport async function POST() {}\n",
            )
            .write(".github/workflows/ci.yml", "on: push\n");
        fixture
    }

    #[test]
    fn detects_the_mvp_next_stack() {
        let detection = next_app().detect();

        assert!(detection.has("nextjs"));
        assert!(detection.has("nextjs-app-router"));
        assert_eq!(detection.auth().unwrap().id, "better-auth");
        assert_eq!(detection.orm().unwrap().id, "drizzle");
    }

    #[test]
    fn records_versions_from_the_manifest() {
        let detection = next_app().detect();
        let next = detection.get("nextjs").unwrap();
        assert_eq!(next.version.as_deref(), Some("^15.2.0"));
        assert_eq!(next.major_version(), Some(15));
    }

    #[test]
    fn every_detection_states_its_evidence() {
        let detection = next_app().detect();
        for component in &detection.components {
            assert!(
                !component.evidence.is_empty(),
                "`{}` was detected with no stated reason",
                component.id
            );
        }
    }

    #[test]
    fn a_manifest_entry_plus_an_import_beats_either_alone() {
        let detection = next_app().detect();
        let auth = detection.get("better-auth").unwrap();
        assert!(
            auth.confidence.value() > RUNTIME_DEPENDENCY,
            "two signals should outrank one: {:?}",
            auth
        );
        assert_eq!(auth.evidence.len(), 2, "{:?}", auth.evidence);
    }

    #[test]
    fn the_app_router_is_distinguished_from_the_pages_router() {
        let pages = Fixture::new();
        pages
            .write("package.json", r#"{"dependencies":{"next":"^13.0.0"}}"#)
            .write("pages/index.tsx", "export default function Home() {}\n");

        let detection = pages.detect();
        assert!(detection.has("nextjs-pages-router"));
        assert!(!detection.has("nextjs-app-router"));
    }

    #[test]
    fn src_app_counts_as_the_app_router() {
        let fixture = Fixture::new();
        fixture
            .write("package.json", r#"{"dependencies":{"next":"^15.0.0"}}"#)
            .write("src/app/layout.tsx", "export default function L() {}\n");

        assert!(fixture.detect().has("nextjs-app-router"));
    }

    #[test]
    fn a_router_directory_without_next_proves_nothing() {
        let fixture = Fixture::new();
        fixture.write("app/page.tsx", "export default function Page() {}\n");
        assert!(!fixture.detect().has("nextjs-app-router"));
    }

    #[test]
    fn detects_a_rust_service() {
        let fixture = Fixture::new();
        fixture
            .write(
                "Cargo.toml",
                "[package]\nname = \"api\"\n\n[dependencies]\naxum = \"0.8\"\nsqlx = { version = \"0.8\" }\n",
            )
            .write(
                "src/main.rs",
                "use axum::Router;\nfn main() {}\n",
            );

        let detection = fixture.detect();
        assert_eq!(detection.primary_framework().unwrap().id, "axum");
        assert_eq!(detection.orm().unwrap().id, "sqlx");
        assert!(detection.ecosystems.contains(&Ecosystem::Cargo));
        assert_eq!(detection.primary_language(), Some(&Language::Rust));
    }

    #[test]
    fn development_dependencies_rank_below_runtime_ones() {
        let fixture = Fixture::new();
        fixture.write(
            "package.json",
            r#"{"dependencies":{"express":"^4.0.0"},"devDependencies":{"drizzle-orm":"^0.38.0"}}"#,
        );

        let detection = fixture.detect();
        let express = detection.get("express").unwrap();
        let drizzle = detection.get("drizzle").unwrap();
        assert!(express.confidence > drizzle.confidence);
    }

    #[test]
    fn a_prisma_schema_is_enough_on_its_own() {
        let fixture = Fixture::new();
        fixture.write("prisma/schema.prisma", "datasource db {}\n");
        assert!(fixture.detect().has("prisma"));
    }

    #[test]
    fn imports_catch_a_dependency_the_manifest_never_declared() {
        let fixture = Fixture::new();
        fixture.write("src/db.ts", "import { drizzle } from 'drizzle-orm';\n");

        let detection = fixture.detect();
        let drizzle = detection.get("drizzle").unwrap();
        assert_eq!(drizzle.role, Role::Orm);
        assert!(drizzle.confidence.value() <= RUNTIME_DEPENDENCY);
    }

    #[test]
    fn the_import_scan_can_be_switched_off() {
        let fixture = Fixture::new();
        fixture.write("src/db.ts", "import { drizzle } from 'drizzle-orm';\n");

        let detection = Detector::new(fixture.dir.path())
            .scan_imports(false)
            .detect(&fixture.files())
            .unwrap();
        assert!(!detection.has("drizzle"));
    }

    #[test]
    fn hitting_the_import_cap_is_reported() {
        let fixture = Fixture::new();
        for index in 0..5 {
            fixture.write(&format!("src/m{index}.ts"), "export const a = 1;\n");
        }

        let detection = Detector::new(fixture.dir.path())
            .max_import_files(2)
            .detect(&fixture.files())
            .unwrap();
        assert!(detection.imports_truncated);
    }

    #[test]
    fn finds_the_ci_provider() {
        let detection = next_app().detect();
        assert_eq!(detection.ci_providers(), vec![CiProvider::GitHubActions]);
    }

    #[test]
    fn converts_to_a_tech_stack() {
        let stack = next_app().detect().to_tech_stack();
        assert!(stack.has_framework("nextjs"));
        assert!(stack.has_technology("better-auth"));
        assert!(stack.uses_language(&Language::Tsx));
    }

    #[test]
    fn an_empty_repository_detects_nothing_and_says_so() {
        let fixture = Fixture::new();
        let detection = fixture.detect();
        assert!(detection.components.is_empty());
        assert_eq!(detection.summary(), "nothing recognised");
    }

    #[test]
    fn the_summary_names_the_stack() {
        let summary = next_app().detect().summary();
        assert!(summary.contains("better-auth"), "{summary}");
        assert!(summary.contains("drizzle"), "{summary}");
    }

    #[test]
    fn detection_is_deterministic() {
        let fixture = next_app();
        let first = fixture.detect();
        let second = fixture.detect();
        assert_eq!(first.components, second.components);
    }
}
