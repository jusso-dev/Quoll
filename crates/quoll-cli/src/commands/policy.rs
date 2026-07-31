use quoll_core::{Error, Result};
use quoll_detect::{Detection, Detector};
use quoll_graph::Walker;
use quoll_policy::{Invariant, Registry};

use crate::cli::PolicyCommand;
use crate::commands::Context;
use crate::exit::Exit;
use crate::output::pad;

pub fn run(context: &Context, command: &PolicyCommand) -> Result<Exit> {
    match command {
        PolicyCommand::List => list(context),
        PolicyCommand::Explain { id } => explain(context, id),
    }
}

/// Which packs Quoll has, and which of them apply here.
///
/// Both halves matter. A user whose pack is not firing needs to know it was loaded and
/// skipped, and why — otherwise the only signal is silence, which is indistinguishable
/// from a pack that found nothing wrong.
fn list(context: &Context) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;
    let registry = Registry::from_config(&config)?;

    if registry.is_empty() {
        printer.warn("no policy packs are enabled");
        return Ok(Exit::Ok);
    }

    let detection = detect(context)?;
    let applicable = applicable_ids(&registry, &detection);
    let width = registry.ids().iter().map(|id| id.len()).max().unwrap_or(0);

    printer.heading("Policy packs");
    for pack in registry.packs() {
        let applies = applicable.contains(&pack.id);
        let marker = if applies {
            printer.green("✓")
        } else {
            printer.dim("–")
        };
        let count = pack.invariants.len();
        let note = if applies {
            format!("{count} invariant(s)")
        } else {
            "does not apply to this repository".to_string()
        };
        printer.line(format!(
            "  {marker} {} {}  {}",
            pad(&pack.id, width + 2),
            printer.dim(&pack.version),
            printer.dim(&note)
        ));
    }

    printer.line("");
    printer.line(format!(
        "  {}",
        printer.dim(&format!(
            "{} of {} pack(s) apply · {}",
            applicable.len(),
            registry.len(),
            detection.summary()
        ))
    ));
    printer.line(format!(
        "  {}",
        printer.dim("`quoll policy explain <pack/invariant>` for the detail")
    ));
    Ok(Exit::Ok)
}

/// One invariant in full: what it checks, why, and what to do about a violation.
fn explain(context: &Context, id: &str) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;
    let registry = Registry::from_config(&config)?;

    let matches = find(&registry, id);
    if matches.is_empty() {
        return Err(Error::Policy(format!(
            "no invariant matches `{id}`; run `quoll policy list` to see the enabled packs"
        )));
    }

    for (pack_id, invariant) in matches {
        printer.heading(&invariant.qualified_id(pack_id));
        printer.field("title", &invariant.title);
        printer.field("severity", invariant.severity.as_str());
        printer.field("applies to", describe_selector(invariant));

        if let Some(description) = &invariant.description {
            printer.line("");
            for line in wrap(description, 76) {
                printer.line(format!("  {line}"));
            }
        }

        printer.heading("Requires");
        for requirement in invariant.requires.iter().chain(&invariant.requires_all) {
            printer.line(format!("  · {}", requirement.describe()));
        }
        if !invariant.requires_any.is_empty() {
            let alternatives: Vec<String> = invariant
                .requires_any
                .iter()
                .map(|r| r.describe())
                .collect();
            printer.line(format!("  · {}", alternatives.join(", or ")));
        }
        if let Some(forbidden) = &invariant.forbids {
            printer.line(format!("  · the absence of {}", forbidden.describe()));
        }

        if let Some(remediation) = &invariant.remediation {
            printer.heading("Remediation");
            for line in wrap(remediation, 76) {
                printer.line(format!("  {line}"));
            }
        }
    }
    Ok(Exit::Ok)
}

/// Find invariants by `pack/invariant`, by bare invariant id, or by pack id.
fn find<'a>(registry: &'a Registry, id: &str) -> Vec<(&'a str, &'a Invariant)> {
    let mut found = Vec::new();
    for pack in registry.packs() {
        if pack.id == id {
            found.extend(pack.invariants.iter().map(|i| (pack.id.as_str(), i)));
            continue;
        }
        for invariant in &pack.invariants {
            if invariant.id == id || invariant.qualified_id(&pack.id) == id {
                found.push((pack.id.as_str(), invariant));
            }
        }
    }
    found
}

fn applicable_ids(registry: &Registry, detection: &Detection) -> Vec<String> {
    // Applicability is decided by the evaluator, so `policy list` and a real scan can never
    // disagree about which packs are in play.
    let graph = match quoll_graph::Graph::open_in_memory() {
        Ok(graph) => graph,
        Err(_) => return Vec::new(),
    };
    registry
        .evaluate(&graph, detection)
        .map(|report| report.packs_applied)
        .unwrap_or_default()
}

fn detect(context: &Context) -> Result<Detection> {
    let config = context.config()?;
    let files = Walker::from_config(&config).discover()?.files;
    Detector::from_config(&config).detect(&files)
}

fn describe_selector(invariant: &Invariant) -> String {
    let selector = &invariant.applies_to;
    let mut parts = vec![format!("{} nodes", selector.node_kind)];
    if !selector.methods.is_empty() {
        parts.push(format!("methods {}", selector.methods.join(", ")));
    }
    if !selector.operations.is_empty() {
        parts.push(format!("operations {}", selector.operations.join(", ")));
    }
    if let Some(fragment) = &selector.path_contains {
        parts.push(format!("path containing `{fragment}`"));
    }
    if let Some(fragment) = &selector.name_contains {
        parts.push(format!("name containing `{fragment}`"));
    }
    parts.join(", ")
}

/// Greedy word wrap. Pack descriptions are prose and unwrapped prose in a terminal is
/// unreadable at any width above about ninety columns.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
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

    fn next_app() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("app/api")).unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"next":"^15.0.0","better-auth":"^1.0.0","drizzle-orm":"^0.38.0"}}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("app/api/route.ts"), "export async function POST() {}\n")
            .unwrap();
        dir
    }

    #[test]
    fn listing_shows_which_packs_apply() {
        let dir = next_app();
        assert_eq!(list(&context(dir.path())).unwrap(), Exit::Ok);
    }

    #[test]
    fn a_next_repository_activates_the_next_packs() {
        let dir = next_app();
        let config = quoll_core::config::Config {
            root: dir.path().to_path_buf(),
            ..Default::default()
        };
        let registry = Registry::from_config(&config).unwrap();
        let detection = detect(&context(dir.path())).unwrap();

        let applicable = applicable_ids(&registry, &detection);
        assert!(applicable.contains(&"nextjs-app-router".to_string()), "{applicable:?}");
        assert!(applicable.contains(&"nextjs-better-auth-drizzle".to_string()));
        assert!(!applicable.contains(&"axum".to_string()));
    }

    #[test]
    fn explain_accepts_a_qualified_id() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            explain(&context(dir.path()), "axum/authenticated-mutation").unwrap(),
            Exit::Ok
        );
    }

    #[test]
    fn explain_accepts_a_whole_pack() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(explain(&context(dir.path()), "axum").unwrap(), Exit::Ok);
    }

    #[test]
    fn explaining_something_unknown_is_an_error_with_guidance() {
        let dir = tempfile::tempdir().unwrap();
        let err = explain(&context(dir.path()), "no-such-thing").unwrap_err();
        assert!(err.to_string().contains("quoll policy list"), "{err}");
        assert_eq!(Exit::from_error(&err), Exit::InvalidConfig);
    }

    #[test]
    fn a_bare_invariant_id_finds_it_in_every_pack() {
        let registry = Registry::builtin().unwrap();
        let found = find(&registry, "authenticated-mutation");
        assert!(found.len() >= 3, "the same id appears in several packs: {found:?}");
    }

    #[test]
    fn wrapping_respects_the_width() {
        let wrapped = wrap("one two three four five six seven eight", 12);
        assert!(wrapped.iter().all(|line| line.len() <= 12), "{wrapped:?}");
        assert_eq!(wrapped.join(" "), "one two three four five six seven eight");
    }

    #[test]
    fn selectors_describe_themselves() {
        let registry = Registry::builtin().unwrap();
        let invariant = registry
            .get("nextjs-better-auth-drizzle")
            .unwrap()
            .invariant("tenant-scoped-write")
            .unwrap();
        let described = describe_selector(invariant);
        assert!(described.contains("database_operation"), "{described}");
        assert!(described.contains("update"), "{described}");
    }
}
