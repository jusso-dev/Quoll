use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Command line surface.
///
/// This module defines shape only. Nothing here decides what a scan does — the CLI parses
/// arguments, calls a command, and maps the result to an exit code.
#[derive(Debug, Parser)]
#[command(
    name = "quoll",
    version,
    about = "A code security scanner that builds a graph before it decides what to report",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Repository root. Defaults to the current directory.
    #[arg(long, short = 'C', global = true, value_name = "DIR")]
    pub path: Option<PathBuf>,

    /// Configuration file. Defaults to the nearest `quoll.toml`.
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Suppress progress output. Results are still printed.
    #[arg(long, short, global = true)]
    pub quiet: bool,

    /// Increase log verbosity. Repeat for more.
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable coloured output.
    #[arg(long, global = true)]
    pub no_color: bool,
}

impl GlobalArgs {
    pub fn root(&self) -> PathBuf {
        self.path.clone().unwrap_or_else(|| PathBuf::from("."))
    }

    /// Log filter for `tracing`, unless `RUST_LOG` overrides it.
    pub fn log_filter(&self) -> &'static str {
        match (self.quiet, self.verbose) {
            (true, 0) => "error",
            (_, 0) => "warn",
            (_, 1) => "info",
            (_, 2) => "debug",
            _ => "trace",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a starter `quoll.toml`.
    Init(InitArgs),

    /// Scan a repository.
    Scan(ScanArgs),

    /// Scan in CI: non-interactive, changed files, SARIF output, stable exit codes.
    Ci(CiArgs),

    /// Explain a finding, a hypothesis or a policy decision.
    Explain(ExplainArgs),

    /// Investigate a hypothesis with a model.
    Investigate(InvestigateArgs),

    /// Validate a hypothesis against a running non-production target.
    Validate(ValidateArgs),

    /// Build, update and inspect the code graph.
    #[command(subcommand)]
    Graph(GraphCommand),

    /// List and inspect findings from the last scan.
    #[command(subcommand)]
    Findings(FindingsCommand),

    /// Export the last scan in another format.
    Export(ExportArgs),

    /// Inspect scanner plugins.
    #[command(subcommand)]
    Plugins(PluginsCommand),

    /// Inspect policy packs.
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Check that this installation is usable.
    Doctor,

    /// Serve Quoll's tools over MCP.
    Mcp(McpArgs),
}

impl Command {
    /// Name used in messages and telemetry.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Init(_) => "init",
            Command::Scan(_) => "scan",
            Command::Ci(_) => "ci",
            Command::Explain(_) => "explain",
            Command::Investigate(_) => "investigate",
            Command::Validate(_) => "validate",
            Command::Graph(_) => "graph",
            Command::Findings(_) => "findings",
            Command::Export(_) => "export",
            Command::Plugins(_) => "plugins",
            Command::Policy(_) => "policy",
            Command::Doctor => "doctor",
            Command::Mcp(_) => "mcp",
        }
    }
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Overwrite an existing `quoll.toml`.
    #[arg(long)]
    pub force: bool,

    /// Profile to write into the new file.
    #[arg(long, value_enum, default_value_t = ProfileArg::Balanced)]
    pub profile: ProfileArg,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Path to scan. Defaults to the repository root.
    pub target: Option<PathBuf>,

    #[arg(long, value_enum)]
    pub profile: Option<ProfileArg>,

    /// Fail at or above this severity.
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<String>,

    /// Never call a model, whatever the profile allows.
    #[arg(long)]
    pub no_ai: bool,

    /// Forbid every network call, including scanner downloads.
    #[arg(long)]
    pub offline: bool,

    /// Report formats to write.
    #[arg(long, value_name = "FORMAT")]
    pub format: Vec<String>,
}

#[derive(Debug, Args)]
pub struct CiArgs {
    /// Git ref to diff against when selecting changed files.
    #[arg(long, value_name = "REF")]
    pub base_ref: Option<String>,

    #[arg(long, value_enum)]
    pub profile: Option<ProfileArg>,

    /// Where to write the SARIF file.
    #[arg(long, value_name = "FILE")]
    pub sarif: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// Finding, hypothesis or control id.
    pub id: String,
}

#[derive(Debug, Args)]
pub struct InvestigateArgs {
    /// Hypothesis id. Omit to investigate every qualifying hypothesis.
    pub id: Option<String>,

    /// Report what would be sent to the model, and send nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Base URL of a running non-production target.
    #[arg(long, value_name = "URL")]
    pub target_url: String,

    /// Hypothesis to validate.
    pub id: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum GraphCommand {
    /// Index the repository from scratch.
    Build(GraphBuildArgs),
    /// Index only what changed since the last run.
    Update,
    /// Print node, edge and file counts.
    Stats,
}

#[derive(Debug, Args)]
pub struct GraphBuildArgs {
    /// Keep existing nodes instead of discarding them first.
    ///
    /// Only safe when the parser has not changed; `build` discards by default for exactly
    /// that reason.
    #[arg(long)]
    pub incremental: bool,
}

#[derive(Debug, Subcommand)]
pub enum FindingsCommand {
    /// List findings from the last scan.
    List(FindingsListArgs),
    /// Show one finding in full.
    Show { id: String },
}

#[derive(Debug, Args)]
pub struct FindingsListArgs {
    /// Only findings at or above this severity.
    #[arg(long, value_name = "SEVERITY")]
    pub severity: Option<String>,

    /// Include suppressed findings.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    #[arg(long, value_enum)]
    pub format: FormatArg,

    /// Write to a file instead of stdout.
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum PluginsCommand {
    /// List registered plugins.
    List,
    /// Check which plugin binaries are installed and runnable.
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// List policy packs that apply to this repository.
    List,
    /// Explain one policy invariant.
    Explain { id: String },
}

#[derive(Debug, Args)]
pub struct McpArgs {
    /// Serve over stdio. The only transport in this build.
    #[arg(long, default_value_t = true)]
    pub stdio: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    Fast,
    Balanced,
    Deep,
    Release,
}

impl From<ProfileArg> for quoll_core::Profile {
    fn from(arg: ProfileArg) -> Self {
        match arg {
            ProfileArg::Fast => quoll_core::Profile::Fast,
            ProfileArg::Balanced => quoll_core::Profile::Balanced,
            ProfileArg::Deep => quoll_core::Profile::Deep,
            ProfileArg::Release => quoll_core::Profile::Release,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
    Json,
    Sarif,
    Markdown,
}

impl FormatArg {
    pub fn as_str(self) -> &'static str {
        match self {
            FormatArg::Json => "json",
            FormatArg::Sarif => "sarif",
            FormatArg::Markdown => "markdown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn global_flags_work_after_the_subcommand() {
        let cli = Cli::try_parse_from(["quoll", "graph", "stats", "--quiet"]).unwrap();
        assert!(cli.global.quiet);
        assert_eq!(cli.command.name(), "graph");
    }

    #[test]
    fn the_repository_root_defaults_to_the_current_directory() {
        let cli = Cli::try_parse_from(["quoll", "doctor"]).unwrap();
        assert_eq!(cli.global.root(), PathBuf::from("."));

        let cli = Cli::try_parse_from(["quoll", "-C", "/repo", "doctor"]).unwrap();
        assert_eq!(cli.global.root(), PathBuf::from("/repo"));
    }

    #[test]
    fn verbosity_maps_to_a_log_filter() {
        let quiet = Cli::try_parse_from(["quoll", "--quiet", "doctor"]).unwrap();
        assert_eq!(quiet.global.log_filter(), "error");

        let loud = Cli::try_parse_from(["quoll", "-vv", "doctor"]).unwrap();
        assert_eq!(loud.global.log_filter(), "debug");
    }

    #[test]
    fn scan_accepts_an_optional_target() {
        let cli = Cli::try_parse_from(["quoll", "scan"]).unwrap();
        match cli.command {
            Command::Scan(args) => assert!(args.target.is_none()),
            other => panic!("expected scan, got {}", other.name()),
        }

        let cli = Cli::try_parse_from(["quoll", "scan", "packages/api"]).unwrap();
        match cli.command {
            Command::Scan(args) => assert_eq!(args.target.unwrap(), PathBuf::from("packages/api")),
            other => panic!("expected scan, got {}", other.name()),
        }
    }

    #[test]
    fn export_requires_a_format() {
        assert!(Cli::try_parse_from(["quoll", "export"]).is_err());
        let cli = Cli::try_parse_from(["quoll", "export", "--format", "sarif"]).unwrap();
        match cli.command {
            Command::Export(args) => assert_eq!(args.format.as_str(), "sarif"),
            other => panic!("expected export, got {}", other.name()),
        }
    }

    #[test]
    fn unknown_profiles_are_rejected_at_parse_time() {
        assert!(Cli::try_parse_from(["quoll", "scan", "--profile", "banana"]).is_err());
        assert!(Cli::try_parse_from(["quoll", "scan", "--profile", "deep"]).is_ok());
    }

    #[test]
    fn every_command_in_the_specification_is_reachable() {
        for args in [
            vec!["quoll", "init"],
            vec!["quoll", "scan"],
            vec!["quoll", "ci"],
            vec!["quoll", "explain", "F-1"],
            vec!["quoll", "investigate"],
            vec!["quoll", "validate", "--target-url", "http://localhost:3000"],
            vec!["quoll", "graph", "build"],
            vec!["quoll", "graph", "update"],
            vec!["quoll", "graph", "stats"],
            vec!["quoll", "findings", "list"],
            vec!["quoll", "findings", "show", "F-1"],
            vec!["quoll", "export", "--format", "json"],
            vec!["quoll", "plugins", "list"],
            vec!["quoll", "plugins", "doctor"],
            vec!["quoll", "policy", "list"],
            vec!["quoll", "policy", "explain", "authenticated-mutation"],
            vec!["quoll", "doctor"],
            vec!["quoll", "mcp"],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "{args:?} failed to parse");
        }
    }
}
