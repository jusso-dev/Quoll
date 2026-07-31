use quoll_core::{Language, Result};
use quoll_graph::{Graph, GraphOps};

use crate::commands::Context;
use crate::exit::Exit;

/// How a single check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Working.
    Ok,
    /// Not present, but Quoll degrades rather than fails.
    Optional,
    /// Present and broken. The only status that changes the exit code.
    Broken,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

impl Check {
    fn ok(name: &str, detail: impl Into<String>) -> Check {
        Check {
            name: name.to_string(),
            status: Status::Ok,
            detail: detail.into(),
        }
    }

    fn optional(name: &str, detail: impl Into<String>) -> Check {
        Check {
            name: name.to_string(),
            status: Status::Optional,
            detail: detail.into(),
        }
    }

    fn broken(name: &str, detail: impl Into<String>) -> Check {
        Check {
            name: name.to_string(),
            status: Status::Broken,
            detail: detail.into(),
        }
    }
}

/// External tools Quoll will drive once the adapter crate lands.
///
/// Reported here rather than nowhere: knowing a scanner is missing before the adapter
/// exists is more useful than discovering it on the first real scan.
const EXPECTED_TOOLS: &[(&str, &str)] = &[
    ("semgrep", "static analysis"),
    ("gitleaks", "secret scanning"),
    ("osv-scanner", "dependency vulnerabilities"),
    ("trivy", "container and dependency scanning"),
    ("cargo-audit", "Rust advisory database"),
];

pub fn run(context: &Context) -> Result<Exit> {
    let printer = &context.printer;
    let checks = collect(context);

    printer.heading("Quoll");
    printer.field("version", env!("CARGO_PKG_VERSION"));
    printer.field("graph schema", format!("v{}", quoll_graph::SCHEMA_VERSION));

    printer.heading("Checks");
    for check in &checks {
        let marker = match check.status {
            Status::Ok => printer.green("✓"),
            Status::Optional => printer.dim("–"),
            Status::Broken => printer.red("✗"),
        };
        printer.line(format!(
            "  {marker} {:<24} {}",
            check.name,
            printer.dim(&check.detail)
        ));
    }

    let broken = checks.iter().filter(|c| c.status == Status::Broken).count();
    printer.line("");
    if broken == 0 {
        printer.success("no problems found");
        Ok(Exit::Ok)
    } else {
        printer.warn(format!("{broken} check(s) failed"));
        Ok(Exit::InvalidConfig)
    }
}

/// Run every check. Separated from rendering so that tests can assert on outcomes.
pub fn collect(context: &Context) -> Vec<Check> {
    let mut checks = Vec::new();

    // Configuration.
    match context.config() {
        Ok(config) => {
            let source = config
                .source_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "defaults (no quoll.toml)".to_string());
            checks.push(Check::ok("configuration", source));
            checks.push(Check::ok("profile", config.scan.profile.as_str()));

            // Graph.
            let path = config.graph_path();
            if path.exists() {
                match Graph::open(&path) {
                    Ok(graph) => match graph.stats() {
                        Ok(stats) => checks.push(Check::ok(
                            "code graph",
                            format!("{} files, {} nodes", stats.files, stats.nodes),
                        )),
                        Err(err) => checks.push(Check::broken("code graph", err.to_string())),
                    },
                    Err(err) => checks.push(Check::broken("code graph", err.to_string())),
                }
            } else {
                checks.push(Check::optional(
                    "code graph",
                    "not built yet — run `quoll graph build`",
                ));
            }

            // State directory. Checked by writing, because a read-only checkout in CI is a
            // real and otherwise confusing failure.
            let state = config.state_dir();
            match std::fs::create_dir_all(&state)
                .and_then(|_| std::fs::write(state.join(".write-test"), b""))
            {
                Ok(()) => {
                    let _ = std::fs::remove_file(state.join(".write-test"));
                    checks.push(Check::ok("state directory", state.display().to_string()));
                }
                Err(err) => checks.push(Check::broken(
                    "state directory",
                    format!("{}: {err}", state.display()),
                )),
            }

            // AI.
            if config.ai.enabled {
                match &config.ai.provider {
                    Some(provider) => checks.push(Check::ok("ai provider", provider.clone())),
                    None => checks.push(Check::broken("ai provider", "enabled but not configured")),
                }
            } else {
                checks.push(Check::optional("ai", "disabled — scans run deterministically"));
            }
        }
        Err(err) => checks.push(Check::broken("configuration", err.to_string())),
    }

    // Language support.
    let supported: Vec<&str> = [
        Language::Rust,
        Language::TypeScript,
        Language::Tsx,
        Language::JavaScript,
    ]
    .iter()
    .filter(|language| quoll_graph::parse::is_supported(language))
    .map(|language| language.as_str())
    .collect();
    checks.push(Check::ok("indexing", supported.join(", ")));

    // External scanners.
    for (binary, purpose) in EXPECTED_TOOLS {
        match quoll_plugin::which(binary) {
            Some(path) => checks.push(Check::ok(binary, path.display().to_string())),
            None => checks.push(Check::optional(binary, format!("not installed — {purpose}"))),
        }
    }

    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Printer;
    use std::path::Path;

    fn context(root: &Path) -> Context {
        Context {
            printer: Printer::plain(),
            root: root.to_path_buf(),
            config_override: None,
        }
    }

    fn find<'a>(checks: &'a [Check], name: &str) -> &'a Check {
        checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no `{name}` check in {:?}", checks.iter().map(|c| &c.name).collect::<Vec<_>>()))
    }

    #[test]
    fn a_bare_repository_passes() {
        let dir = tempfile::tempdir().unwrap();
        let checks = collect(&context(dir.path()));
        assert!(checks.iter().all(|c| c.status != Status::Broken), "{checks:#?}");
        assert_eq!(run(&context(dir.path())).unwrap(), Exit::Ok);
    }

    #[test]
    fn a_missing_graph_is_optional_not_broken() {
        let dir = tempfile::tempdir().unwrap();
        let checks = collect(&context(dir.path()));
        assert_eq!(find(&checks, "code graph").status, Status::Optional);
    }

    #[test]
    fn a_corrupt_graph_is_broken() {
        let dir = tempfile::tempdir().unwrap();
        let graph_path = dir.path().join(".quoll/graph.db");
        std::fs::create_dir_all(graph_path.parent().unwrap()).unwrap();
        std::fs::write(&graph_path, b"this is not a database").unwrap();

        let checks = collect(&context(dir.path()));
        assert_eq!(find(&checks, "code graph").status, Status::Broken);
        assert_eq!(run(&context(dir.path())).unwrap(), Exit::InvalidConfig);
    }

    #[test]
    fn an_invalid_config_is_reported_as_broken() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("quoll.toml"),
            "[ai]\nenabled = true\n",
        )
        .unwrap();

        let checks = collect(&context(dir.path()));
        assert_eq!(find(&checks, "configuration").status, Status::Broken);
    }

    #[test]
    fn missing_scanners_never_fail_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let checks = collect(&context(dir.path()));
        for (binary, _) in EXPECTED_TOOLS {
            assert_ne!(find(&checks, binary).status, Status::Broken);
        }
    }

    #[test]
    fn indexing_reports_the_languages_with_grammars() {
        let dir = tempfile::tempdir().unwrap();
        let checks = collect(&context(dir.path()));
        let detail = &find(&checks, "indexing").detail;
        assert!(detail.contains("rust"), "{detail}");
        assert!(detail.contains("typescript"), "{detail}");
    }
}
