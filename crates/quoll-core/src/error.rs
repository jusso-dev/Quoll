use std::path::PathBuf;

/// The workspace-wide result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors that cross crate boundaries.
///
/// Plugin and provider failures are deliberately non-fatal at the type level: the
/// orchestrator degrades to whatever evidence it did manage to collect, and records
/// the failure in the run report rather than aborting the scan.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("io error: {0}")]
    BareIo(#[from] std::io::Error),

    #[error("failed to parse {what}: {message}")]
    Parse { what: String, message: String },

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("plugin `{plugin}` failed: {message}")]
    Plugin { plugin: String, message: String },

    #[error("plugin `{plugin}` is unavailable: {reason}")]
    PluginUnavailable { plugin: String, reason: String },

    #[error("required binary `{binary}` was not found on PATH")]
    MissingBinary { binary: String },

    #[error("graph error: {0}")]
    Graph(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("ai provider `{provider}` failed: {message}")]
    Ai { provider: String, message: String },

    #[error("no ai provider is configured; run `quoll doctor` for setup guidance")]
    NoAiProvider,

    #[error("budget exhausted: {0}")]
    Budget(String),

    #[error("dynamic validation refused: {0}")]
    DynamicValidation(String),

    #[error("operation timed out after {seconds}s: {what}")]
    Timeout { what: String, seconds: u64 },

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    pub fn parse(what: impl Into<String>, message: impl std::fmt::Display) -> Self {
        Error::Parse {
            what: what.into(),
            message: message.to_string(),
        }
    }

    pub fn plugin(plugin: impl Into<String>, message: impl std::fmt::Display) -> Self {
        Error::Plugin {
            plugin: plugin.into(),
            message: message.to_string(),
        }
    }

    pub fn config(message: impl std::fmt::Display) -> Self {
        Error::Config(message.to_string())
    }

    pub fn other(message: impl std::fmt::Display) -> Self {
        Error::Other(message.to_string())
    }

    /// Whether the scan can usefully continue after this error.
    ///
    /// Missing scanners and provider hiccups are recoverable; a corrupt graph is not.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::Plugin { .. }
                | Error::PluginUnavailable { .. }
                | Error::MissingBinary { .. }
                | Error::Ai { .. }
                | Error::NoAiProvider
                | Error::Budget(_)
                | Error::DynamicValidation(_)
                | Error::Timeout { .. }
        )
    }
}
