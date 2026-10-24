use std::path::{Path, PathBuf};
use std::str::FromStr;

use quoll_core::{Error, Result, Severity};
use quoll_plugin::{CommandOutput, Exec, ScanContext};

/// Build the invocation for a tool, applying everything the user configured.
///
/// Every adapter goes through here so that the working directory, timeout, environment
/// allowlist and binary override are applied identically. A tool is spawned directly with
/// an argument vector — never through a shell — so a repository path containing `;` is
/// data, not syntax.
pub fn command(ctx: &ScanContext, default_binary: &str) -> Exec {
    let binary = ctx
        .settings()
        .binary
        .clone()
        .unwrap_or_else(|| PathBuf::from(default_binary));

    Exec::new(binary)
        .cwd(ctx.root())
        .timeout(ctx.timeout())
        .envs(ctx.env())
}

/// Append the user's escape-hatch arguments.
///
/// However well Quoll models a scanner, someone will need a flag it does not know about,
/// and forking the adapter to get it is worse than passing it through.
pub fn with_extra_args(exec: Exec, ctx: &ScanContext) -> Exec {
    exec.args(ctx.settings().extra_args.clone())
}

/// The exit code a tool was told to use for "findings present", honouring a user override.
///
/// Trivy and Gitleaks are run with `--exit-code 0` so findings are not failures. A user who
/// passes their own `--exit-code` in `extra_args` moves that code, and it must still count
/// as success. The last occurrence wins, as it does for the tools themselves.
pub fn findings_exit_code(ctx: &ScanContext, default: i32) -> i32 {
    let args = &ctx.settings().extra_args;
    let mut code = default;
    for (i, arg) in args.iter().enumerate() {
        let value = match arg.strip_prefix("--exit-code") {
            Some("") => args.get(i + 1).map(String::as_str),
            Some(rest) => rest.strip_prefix('='),
            None => None,
        };
        if let Some(parsed) = value.and_then(|v| v.parse().ok()) {
            code = parsed;
        }
    }
    code
}

/// The JSON report a tool printed, or an error if it printed nothing.
///
/// Every adapter that reads stdout asks for a JSON format, and every one of those tools
/// prints a document even when it finds nothing. Empty stdout therefore means the tool did
/// not scan, and must not be reported as a clean result.
pub fn report<'a>(tool: &str, output: &'a CommandOutput) -> Result<&'a str> {
    if output.stdout.trim().is_empty() {
        return Err(Error::plugin(
            tool,
            format!("produced no report: {}", output.error_summary()),
        ));
    }
    Ok(&output.stdout)
}

/// Parse a tool's JSON, naming the tool when it fails.
///
/// A scanner that prints a usage message where JSON was expected produces a parse error
/// that must say which scanner, or the user is left guessing which of six tools broke.
pub fn parse_json<T: serde::de::DeserializeOwned>(tool: &str, text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(|err| {
        Error::plugin(
            tool,
            format!(
                "could not parse output as JSON: {err}{}",
                excerpt(text)
            ),
        )
    })
}

/// A short excerpt of unparseable output, for the error message.
///
/// Bounded deliberately: a scanner that dumps a megabyte of HTML must not put a megabyte
/// of HTML in a report.
fn excerpt(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return " (output was empty)".to_string();
    }
    let head: String = trimmed.chars().take(160).collect();
    format!(" — output began: {head}")
}

/// Normalise a tool-reported path to a repository-relative one.
///
/// Scanners are inconsistent: some report absolute paths, some relative, some prefixed
/// with `./`. Reports must be comparable between a laptop and a CI runner with a different
/// checkout directory, so every path is reduced to the same form.
pub fn relative(root: &Path, reported: &str) -> PathBuf {
    let path = Path::new(reported.trim());
    let stripped = path.strip_prefix(root).unwrap_or(path);
    let text = stripped.to_string_lossy();
    PathBuf::from(text.trim_start_matches("./").replace('\\', "/"))
}

/// Map a tool's severity word onto Quoll's scale, with a stated default.
///
/// Unknown words become the fallback rather than an error: a scanner adding a new severity
/// name in a point release must not break a scan.
pub fn severity(raw: &str, fallback: Severity) -> Severity {
    Severity::from_str(raw).unwrap_or(fallback)
}

/// Map a CVSS base score onto Quoll's scale, using the standard CVSS v3 bands.
pub fn severity_from_cvss(score: f64) -> Severity {
    match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        s if s > 0.0 => Severity::Low,
        _ => Severity::Info,
    }
}

/// Line numbers are 1-indexed everywhere in Quoll; a tool reporting 0 means "no line".
pub fn line(raw: i64) -> Option<u32> {
    (raw > 0).then_some(raw as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_reduced_to_a_single_repository_relative_form() {
        let root = Path::new("/repo");
        assert_eq!(relative(root, "/repo/src/main.rs"), PathBuf::from("src/main.rs"));
        assert_eq!(relative(root, "./src/main.rs"), PathBuf::from("src/main.rs"));
        assert_eq!(relative(root, "src/main.rs"), PathBuf::from("src/main.rs"));
        assert_eq!(relative(root, "  src/main.rs  "), PathBuf::from("src/main.rs"));
    }

    #[test]
    fn paths_outside_the_root_are_left_alone() {
        assert_eq!(
            relative(Path::new("/repo"), "/usr/lib/node_modules/x.js"),
            PathBuf::from("/usr/lib/node_modules/x.js")
        );
    }

    #[test]
    fn severity_words_map_onto_the_scale() {
        assert_eq!(severity("ERROR", Severity::Info), Severity::High);
        assert_eq!(severity("WARNING", Severity::Info), Severity::Medium);
        assert_eq!(severity("CRITICAL", Severity::Info), Severity::Critical);
    }

    #[test]
    fn an_unrecognised_severity_falls_back_rather_than_failing() {
        assert_eq!(severity("spicy", Severity::Medium), Severity::Medium);
    }

    #[test]
    fn cvss_scores_use_the_standard_bands() {
        assert_eq!(severity_from_cvss(9.8), Severity::Critical);
        assert_eq!(severity_from_cvss(7.5), Severity::High);
        assert_eq!(severity_from_cvss(5.3), Severity::Medium);
        assert_eq!(severity_from_cvss(2.1), Severity::Low);
        assert_eq!(severity_from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn a_user_exit_code_override_is_honoured() {
        let ctx = |args: &[&str]| {
            ScanContext::new("/repo", quoll_core::Profile::Fast).with_settings(
                quoll_core::config::PluginSettings {
                    extra_args: args.iter().map(|a| a.to_string()).collect(),
                    ..Default::default()
                },
            )
        };
        assert_eq!(findings_exit_code(&ctx(&[]), 0), 0);
        assert_eq!(findings_exit_code(&ctx(&["--exit-code", "7"]), 0), 7);
        assert_eq!(findings_exit_code(&ctx(&["--exit-code=3", "--exit-code=5"]), 0), 5);
        assert_eq!(findings_exit_code(&ctx(&["--exit-codes", "9"]), 0), 0);
    }

    #[test]
    fn empty_stdout_is_not_a_clean_report() {
        let output = CommandOutput {
            status: Some(0),
            stdout: " \n".into(),
            stderr: "fatal: no database\n".into(),
            duration: std::time::Duration::ZERO,
        };
        let err = report("trivy", &output).unwrap_err();
        assert!(err.to_string().contains("no database"), "{err}");
    }

    #[test]
    fn zero_lines_become_no_line() {
        assert_eq!(line(0), None);
        assert_eq!(line(-1), None);
        assert_eq!(line(42), Some(42));
    }

    #[test]
    fn a_json_parse_failure_names_the_tool_and_shows_a_bounded_excerpt() {
        let long = "x".repeat(5000);
        let err = parse_json::<serde_json::Value>("semgrep", &long).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("semgrep"), "{message}");
        assert!(message.len() < 400, "excerpt must be bounded: {} chars", message.len());
    }

    #[test]
    fn empty_output_is_reported_as_empty() {
        let err = parse_json::<serde_json::Value>("gitleaks", "   ").unwrap_err();
        assert!(err.to_string().contains("output was empty"), "{err}");
    }
}
