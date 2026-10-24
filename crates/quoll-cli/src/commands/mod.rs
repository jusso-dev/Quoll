pub mod ci;
pub mod doctor;
pub mod explain;
pub mod export;
pub mod findings;
pub mod graph;
pub mod init;
pub mod investigate;
pub mod mcp;
pub mod plugins;
pub mod policy;
pub mod scan;
pub mod validate;

use std::path::PathBuf;

use quoll_core::config::{trust_granted_by_env, Config};
use quoll_core::{Error, Result};
use quoll_engine::store::ensure_state_dir_safe;

use crate::cli::{Cli, Command, GlobalArgs};
use crate::exit::Exit;
use crate::output::Printer;

/// Everything a command needs that is not its own arguments.
pub struct Context {
    pub printer: Printer,
    pub root: PathBuf,
    pub config_override: Option<PathBuf>,
    /// Honour execution settings in a discovered `quoll.toml`.
    pub trust_repo_config: bool,
}

impl Context {
    pub fn new(global: &GlobalArgs, printer: Printer) -> Context {
        Context {
            printer,
            root: global.root(),
            config_override: global.config.clone(),
            trust_repo_config: global.trust_repo_config || trust_granted_by_env(),
        }
    }

    /// The repository root, canonicalised. A missing root is a usage error, not a crash.
    pub fn canonical_root(&self) -> Result<PathBuf> {
        match self.root.canonicalize() {
            Ok(root) if root.is_dir() => Ok(root),
            _ => Err(Error::config(format!(
                "repository root `{}` is not a directory",
                self.root.display()
            ))),
        }
    }

    /// Load configuration for this invocation.
    ///
    /// An explicit `--config` is trusted and loaded verbatim, but rooted at `-C` (default:
    /// the current directory), not at the file's directory. Otherwise Quoll walks up from
    /// the target looking for `quoll.toml` and falls back to defaults, because a repository
    /// with no configuration is a supported configuration. A discovered file comes from the
    /// repository being scanned, so it is neutralised unless trust was granted.
    pub fn config(&self) -> Result<Config> {
        let root = self.canonical_root()?;
        match &self.config_override {
            Some(path) => {
                if !path.is_file() {
                    return Err(Error::config(format!(
                        "no configuration file at `{}`",
                        path.display()
                    )));
                }
                let mut config = Config::load(path)?;
                config.root = root;
                Ok(config)
            }
            None => Config::discover_with_trust(&root, self.trust_repo_config),
        }
    }

    /// Load configuration for a command that writes state; see [`ensure_writable`].
    pub fn config_for_writing(&self) -> Result<Config> {
        let config = self.config()?;
        ensure_writable(&config)?;
        Ok(config)
    }
}

/// Refuse when anything Quoll is about to write to is a symlink.
///
/// The repository being scanned controls `.quoll/`, so a planted link there would turn a
/// scan into a write anywhere the user can write.
pub fn ensure_writable(config: &Config) -> Result<()> {
    ensure_state_dir_safe(&config.state_dir())?;
    ensure_state_dir_safe(&config.report_dir())?;
    ensure_state_dir_safe(&config.graph_path())
}

/// Run the parsed command.
///
/// Returns the process exit code. Commands signal failure by returning an `Err`, which is
/// classified centrally in [`Exit::from_error`], so no command has to know its own code.
pub async fn dispatch(cli: Cli, context: &Context) -> Result<Exit> {
    match cli.command {
        Command::Init(args) => init::run(context, &args),
        Command::Graph(command) => graph::run(context, &command),
        Command::Doctor => doctor::run(context),
        Command::Plugins(command) => plugins::run(context, &command).await,
        Command::Policy(command) => policy::run(context, &command),
        Command::Scan(args) => scan::run(context, &args).await,
        Command::Ci(args) => ci::run(context, &args).await,
        Command::Explain(args) => explain::run(context, &args),
        Command::Investigate(args) => investigate::run(context, &args).await,
        Command::Validate(args) => validate::run(context, &args).await,
        Command::Findings(command) => findings::run(context, &command),
        Command::Export(args) => export::run(context, &args),
        Command::Mcp(args) => mcp::run(context, &args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(root: &std::path::Path, config: Option<PathBuf>, trust: bool) -> Context {
        Context {
            printer: Printer::plain(),
            root: root.to_path_buf(),
            config_override: config,
            trust_repo_config: trust,
        }
    }

    const HOSTILE: &str = "[plugins.gitleaks]\nbinary = \"/bin/sh\"\n";

    fn gitleaks_binary(config: &Config) -> Option<PathBuf> {
        config.plugins.settings_for("gitleaks").and_then(|s| s.binary.clone())
    }

    #[test]
    fn discovered_config_is_untrusted_unless_trust_is_granted() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join(".git")).unwrap();
        std::fs::write(repo.path().join("quoll.toml"), HOSTILE).unwrap();

        let config = context(repo.path(), None, false).config().unwrap();
        assert_eq!(gitleaks_binary(&config), None);

        let config = context(repo.path(), None, true).config().unwrap();
        assert_eq!(gitleaks_binary(&config), Some(PathBuf::from("/bin/sh")));
    }

    #[test]
    fn explicit_config_is_trusted_and_rooted_at_the_repository() {
        let repo = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let file = elsewhere.path().join("q.toml");
        std::fs::write(&file, HOSTILE).unwrap();

        let config = context(repo.path(), Some(file), false).config().unwrap();
        assert_eq!(gitleaks_binary(&config), Some(PathBuf::from("/bin/sh")));
        // `--config /etc/q.toml -C repo` scans the repo, not /etc.
        assert_eq!(config.root, repo.path().canonicalize().unwrap());
    }

    #[test]
    fn a_missing_root_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = context(&dir.path().join("gone"), None, false)
            .config()
            .unwrap_err();
        assert_eq!(Exit::from_error(&error), Exit::InvalidConfig);
    }
}
