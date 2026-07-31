use quoll_core::Error;

/// Process exit codes.
///
/// These are a public interface. CI pipelines branch on them, so the numeric values are
/// fixed and may never be reassigned — a new failure mode gets a new code, it does not
/// reuse an old one.
///
/// Codes 0–7 are the documented scan outcomes. Codes above 64 follow the `sysexits`
/// convention and mean Quoll itself failed, not the code being scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    /// Policy passed.
    Ok = 0,
    /// Findings at or above the configured severity gate.
    FindingsThreshold = 1,
    /// The configuration is invalid.
    InvalidConfig = 2,
    /// An external scanner failed or timed out.
    ScannerFailed = 3,
    /// Graph indexing failed.
    GraphFailed = 4,
    /// A required model invocation failed.
    ModelFailed = 5,
    /// A token, call or byte budget was exhausted.
    BudgetExceeded = 6,
    /// Dynamic validation was requested against a target the policy forbids.
    DynamicValidationViolation = 7,
    /// The command exists but is not implemented in this build.
    NotImplemented = 70,
    /// An unexpected internal failure.
    Internal = 71,
}

impl Exit {
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Map a domain error to the code a CI pipeline should see.
    ///
    /// Errors carry enough structure to classify themselves, so no call site has to
    /// remember which code goes with which failure.
    pub fn from_error(error: &Error) -> Exit {
        match error {
            Error::Config(_) => Exit::InvalidConfig,
            Error::Parse { .. } => Exit::InvalidConfig,
            Error::Graph(_) => Exit::GraphFailed,
            Error::Plugin { .. }
            | Error::PluginUnavailable { .. }
            | Error::MissingBinary { .. }
            | Error::Timeout { .. } => Exit::ScannerFailed,
            Error::Ai { .. } | Error::NoAiProvider => Exit::ModelFailed,
            Error::Budget(_) => Exit::BudgetExceeded,
            Error::DynamicValidation(_) => Exit::DynamicValidationViolation,
            Error::Policy(_) => Exit::InvalidConfig,
            Error::Io { .. } | Error::BareIo(_) | Error::Serde(_) | Error::Other(_) => {
                Exit::Internal
            }
        }
    }
}

impl From<Exit> for std::process::ExitCode {
    fn from(exit: Exit) -> Self {
        std::process::ExitCode::from(exit.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_codes_are_fixed() {
        assert_eq!(Exit::Ok.code(), 0);
        assert_eq!(Exit::FindingsThreshold.code(), 1);
        assert_eq!(Exit::InvalidConfig.code(), 2);
        assert_eq!(Exit::ScannerFailed.code(), 3);
        assert_eq!(Exit::GraphFailed.code(), 4);
        assert_eq!(Exit::ModelFailed.code(), 5);
        assert_eq!(Exit::BudgetExceeded.code(), 6);
        assert_eq!(Exit::DynamicValidationViolation.code(), 7);
    }

    #[test]
    fn a_bad_config_is_distinguishable_from_a_bad_graph() {
        assert_eq!(
            Exit::from_error(&Error::config("bad")),
            Exit::InvalidConfig
        );
        assert_eq!(
            Exit::from_error(&Error::Graph("corrupt".into())),
            Exit::GraphFailed
        );
    }

    #[test]
    fn missing_scanners_are_scanner_failures_not_internal_errors() {
        let error = Error::MissingBinary {
            binary: "semgrep".into(),
        };
        assert_eq!(Exit::from_error(&error), Exit::ScannerFailed);
    }

    #[test]
    fn model_failures_are_their_own_code() {
        assert_eq!(Exit::from_error(&Error::NoAiProvider), Exit::ModelFailed);
    }

    #[test]
    fn internal_failures_never_collide_with_scan_outcomes() {
        let internal = Exit::from_error(&Error::other("boom"));
        assert_eq!(internal, Exit::Internal);
        assert!(internal.code() > Exit::DynamicValidationViolation.code());
    }
}
