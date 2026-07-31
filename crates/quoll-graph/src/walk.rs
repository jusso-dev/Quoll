use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use quoll_core::config::{Config, STATE_DIR};
use quoll_core::{ids, Error, Language, Result};

/// Bytes inspected when deciding whether a file is binary.
const SNIFF_BYTES: usize = 8192;

/// Directories never descended into, regardless of configuration.
///
/// `.git` holds packfiles that would be read as source, and `.quoll` holds the graph
/// itself — indexing either wastes time and produces nonsense nodes.
const ALWAYS_SKIP_DIRS: &[&str] = &[".git", STATE_DIR];

/// The result of discovering files to index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    /// Repository-relative paths, sorted, ready to index.
    pub files: Vec<PathBuf>,
    /// Files skipped for exceeding the size limit.
    pub skipped_large: usize,
    /// Files skipped because their contents are not text.
    pub skipped_binary: usize,
    /// Entries skipped because they are symlinks.
    pub skipped_symlinks: usize,
}

/// A file read from disk, with the hash that decides whether to reparse it.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub text: String,
    pub hash: String,
    pub size: u64,
    pub language: Option<Language>,
}

/// Discovers the files that make up a repository.
///
/// The walker treats the repository as untrusted input: it never follows symlinks, never
/// executes anything, and refuses to emit paths that escape the root.
#[derive(Debug, Clone)]
pub struct Walker {
    root: PathBuf,
    include: Vec<String>,
    exclude: Vec<String>,
    max_file_size: u64,
    respect_gitignore: bool,
}

impl Walker {
    pub fn new(root: impl Into<PathBuf>) -> Walker {
        Walker {
            root: root.into(),
            include: Vec::new(),
            exclude: Vec::new(),
            max_file_size: 2 * 1024 * 1024,
            respect_gitignore: true,
        }
    }

    /// Build a walker from a loaded configuration.
    pub fn from_config(config: &Config) -> Walker {
        Walker {
            root: config.root.clone(),
            include: config.scan.include.clone(),
            exclude: config.scan.exclude.clone(),
            max_file_size: config.scan.max_file_size_kb.saturating_mul(1024),
            respect_gitignore: config.scan.respect_gitignore,
        }
    }

    pub fn include(mut self, patterns: Vec<String>) -> Walker {
        self.include = patterns;
        self
    }

    pub fn exclude(mut self, patterns: Vec<String>) -> Walker {
        self.exclude = patterns;
        self
    }

    pub fn max_file_size(mut self, bytes: u64) -> Walker {
        self.max_file_size = bytes;
        self
    }

    pub fn respect_gitignore(mut self, respect: bool) -> Walker {
        self.respect_gitignore = respect;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Walk the repository and return the files worth indexing.
    pub fn discover(&self) -> Result<Discovery> {
        let include = build_globs(&self.include)?;
        let exclude = build_globs(&self.exclude)?;
        let mut discovery = Discovery::default();

        let mut builder = WalkBuilder::new(&self.root);
        builder
            // Symlinks are never followed. A repository can contain a link to /etc or to
            // a parent directory, and following it would take Quoll outside the tree it
            // was asked to scan.
            .follow_links(false)
            // Dotfiles are in scope: `.github/workflows`, `.env.example` and `.npmrc` are
            // exactly the files a security scan cares about.
            .hidden(false)
            .parents(self.respect_gitignore)
            .git_ignore(self.respect_gitignore)
            .git_global(self.respect_gitignore)
            .git_exclude(self.respect_gitignore)
            .ignore(self.respect_gitignore)
            .require_git(false);
        builder.filter_entry(|entry| {
            !entry
                .file_name()
                .to_str()
                .is_some_and(|name| ALWAYS_SKIP_DIRS.contains(&name))
        });

        for entry in builder.build() {
            let entry = match entry {
                Ok(entry) => entry,
                // An unreadable directory is a fact about the checkout, not a reason to
                // abandon the scan.
                Err(err) => {
                    tracing::debug!(%err, "skipping unreadable entry");
                    continue;
                }
            };

            let file_type = match entry.file_type() {
                Some(file_type) => file_type,
                None => continue,
            };
            if file_type.is_symlink() {
                discovery.skipped_symlinks += 1;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let relative = match entry.path().strip_prefix(&self.root) {
                Ok(relative) => relative,
                Err(_) => continue,
            };
            let key = relative.to_string_lossy().replace('\\', "/");

            if exclude.iter().any(|glob| glob.is_match(&key)) {
                continue;
            }
            if !include.is_empty() && !include.iter().any(|glob| glob.is_match(&key)) {
                continue;
            }

            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if self.max_file_size > 0 && size > self.max_file_size {
                discovery.skipped_large += 1;
                continue;
            }
            if is_binary(entry.path()) {
                discovery.skipped_binary += 1;
                continue;
            }

            discovery.files.push(relative.to_path_buf());
        }

        discovery.files.sort();
        Ok(discovery)
    }

    /// Read a discovered file, rejecting anything that resolves outside the repository.
    pub fn read(&self, relative: &Path) -> Result<Option<SourceFile>> {
        let absolute = self.root.join(relative);
        if !is_contained(&self.root, &absolute) {
            return Err(Error::Graph(format!(
                "refusing to read `{}`: resolves outside the repository root",
                relative.display()
            )));
        }
        let bytes = match std::fs::read(&absolute) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Error::io(absolute, err)),
        };
        // Hash the bytes, not the decoded string: the hash must change when the file does,
        // including when only its encoding changes.
        let hash = ids::content_hash(&bytes);
        let size = bytes.len() as u64;
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            // Not UTF-8, so no grammar can parse it. Treated as skipped rather than fatal.
            Err(_) => return Ok(None),
        };
        Ok(Some(SourceFile {
            path: relative.to_path_buf(),
            language: Language::from_path(relative),
            text,
            hash,
            size,
        }))
    }
}

/// Whether `candidate` stays inside `root` once `..` components are resolved.
///
/// Uses lexical resolution rather than `canonicalize` so the check works for paths that do
/// not exist yet, and so a symlinked repository root does not fail its own containment
/// check.
fn is_contained(root: &Path, candidate: &Path) -> bool {
    use std::path::Component;

    let mut depth = 0i32;
    let relative = match candidate.strip_prefix(root) {
        Ok(relative) => relative,
        Err(_) => return false,
    };
    for component in relative.components() {
        match component {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

fn build_globs(patterns: &[String]) -> Result<Vec<globset::GlobMatcher>> {
    patterns
        .iter()
        .map(|pattern| {
            globset::Glob::new(pattern)
                .map(|glob| glob.compile_matcher())
                .map_err(|err| Error::config(format!("invalid glob `{pattern}`: {err}")))
        })
        .collect()
}

/// Whether a file looks binary, decided by the presence of a NUL byte in its first
/// [`SNIFF_BYTES`].
///
/// The same heuristic git uses. It is cheap and wrong only for text files that embed NUL,
/// which are not source code.
fn is_binary(path: &Path) -> bool {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return true,
    };
    let mut buffer = [0u8; SNIFF_BYTES];
    match file.read(&mut buffer) {
        Ok(read) => buffer[..read].contains(&0),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("src/lib.ts"), "export const a = 1;\n").unwrap();
        fs::write(root.join("node_modules/pkg/index.js"), "module.exports={}\n").unwrap();
        fs::write(root.join(".git/config"), "[core]\n").unwrap();
        fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
        fs::write(root.join("logo.png"), [0x89, b'P', b'N', b'G', 0x00, 0x1a]).unwrap();
        dir
    }

    fn walker(root: &Path) -> Walker {
        Walker::new(root).exclude(vec!["**/node_modules/**".into()])
    }

    #[test]
    fn finds_source_and_skips_excluded_directories() {
        let dir = repo();
        let found = walker(dir.path()).discover().unwrap();
        let names: Vec<String> = found
            .files
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();

        assert!(names.contains(&"src/main.rs".to_string()));
        assert!(names.contains(&"src/lib.ts".to_string()));
        assert!(!names.iter().any(|n| n.contains("node_modules")));
    }

    #[test]
    fn never_descends_into_git_or_quoll() {
        let dir = repo();
        fs::create_dir_all(dir.path().join(".quoll")).unwrap();
        fs::write(dir.path().join(".quoll/graph.db"), "x").unwrap();

        let found = walker(dir.path()).discover().unwrap();
        let names: Vec<String> = found.files.iter().map(|p| p.to_string_lossy().into()).collect();
        assert!(!names.iter().any(|n| n.contains(".git/")));
        assert!(!names.iter().any(|n| n.contains(".quoll")));
    }

    #[test]
    fn dotfiles_stay_in_scope() {
        let dir = repo();
        let found = walker(dir.path()).discover().unwrap();
        let names: Vec<String> = found
            .files
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(
            names.contains(&".github/workflows/ci.yml".to_string()),
            "{names:?}"
        );
    }

    #[test]
    fn binary_files_are_skipped_and_counted() {
        let dir = repo();
        let found = walker(dir.path()).discover().unwrap();
        assert!(!found.files.iter().any(|p| p.ends_with("logo.png")));
        assert_eq!(found.skipped_binary, 1);
    }

    #[test]
    fn oversized_files_are_skipped_and_counted() {
        let dir = repo();
        fs::write(dir.path().join("src/huge.rs"), "x".repeat(4096)).unwrap();
        let found = walker(dir.path()).max_file_size(1024).discover().unwrap();
        assert!(!found.files.iter().any(|p| p.ends_with("huge.rs")));
        assert_eq!(found.skipped_large, 1);
    }

    #[test]
    fn include_patterns_narrow_the_scope() {
        let dir = repo();
        let found = walker(dir.path())
            .include(vec!["src/**/*.rs".into()])
            .discover()
            .unwrap();
        assert_eq!(found.files.len(), 1);
        assert!(found.files[0].ends_with("main.rs"));
    }

    #[test]
    fn gitignored_files_are_skipped_when_configured() {
        let dir = repo();
        fs::write(dir.path().join(".gitignore"), "generated.rs\n").unwrap();
        fs::write(dir.path().join("src/generated.rs"), "// gen\n").unwrap();

        let respected = walker(dir.path()).discover().unwrap();
        assert!(!respected.files.iter().any(|p| p.ends_with("generated.rs")));

        let ignored = walker(dir.path()).respect_gitignore(false).discover().unwrap();
        assert!(ignored.files.iter().any(|p| p.ends_with("generated.rs")));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed() {
        let dir = repo();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secrets.env"), "TOKEN=x\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();

        let found = walker(dir.path()).discover().unwrap();
        assert!(!found.files.iter().any(|p| p.to_string_lossy().contains("escape")));
        assert_eq!(found.skipped_symlinks, 1);
    }

    #[test]
    fn reading_rejects_paths_that_escape_the_root() {
        let dir = repo();
        let err = walker(dir.path())
            .read(Path::new("../../etc/passwd"))
            .unwrap_err();
        assert!(err.to_string().contains("outside the repository"), "{err}");
    }

    #[test]
    fn reading_returns_content_hash_and_language() {
        let dir = repo();
        let file = walker(dir.path())
            .read(Path::new("src/main.rs"))
            .unwrap()
            .unwrap();
        assert_eq!(file.language, Some(Language::Rust));
        assert_eq!(file.hash.len(), 64);
        assert!(file.text.contains("fn main"));

        let again = walker(dir.path()).read(Path::new("src/main.rs")).unwrap().unwrap();
        assert_eq!(file.hash, again.hash);
    }

    #[test]
    fn reading_a_missing_file_is_not_an_error() {
        let dir = repo();
        assert!(walker(dir.path()).read(Path::new("src/gone.rs")).unwrap().is_none());
    }

    #[test]
    fn containment_check_rejects_traversal() {
        let root = Path::new("/repo");
        assert!(is_contained(root, Path::new("/repo/src/main.rs")));
        assert!(is_contained(root, Path::new("/repo/src/../src/main.rs")));
        assert!(!is_contained(root, Path::new("/repo/../etc/passwd")));
        assert!(!is_contained(root, Path::new("/etc/passwd")));
    }

    #[test]
    fn invalid_globs_are_configuration_errors() {
        let dir = repo();
        let err = walker(dir.path())
            .include(vec!["src/[".into()])
            .discover()
            .unwrap_err();
        assert!(err.to_string().contains("invalid glob"), "{err}");
    }
}
