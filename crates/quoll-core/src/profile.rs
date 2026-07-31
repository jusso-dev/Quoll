use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{Confidence, Severity};

/// Scan depth preset.
///
/// Profiles exist so that the same repository configuration works on a pre-commit hook
/// and on a nightly release gate without editing `quoll.toml`. Everything a profile sets
/// can still be overridden explicitly on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Changed files only, fast scanners, no AI. Targets a pre-commit or PR check.
    Fast,
    /// Full scan, standard scanners, AI on high-confidence hypotheses.
    #[default]
    Balanced,
    /// Everything, including slow scanners and a lower investigation threshold.
    Deep,
    /// Deep plus dynamic validation. For release gates.
    Release,
}

impl Profile {
    pub const ALL: [Profile; 4] = [
        Profile::Fast,
        Profile::Balanced,
        Profile::Deep,
        Profile::Release,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Fast => "fast",
            Profile::Balanced => "balanced",
            Profile::Deep => "deep",
            Profile::Release => "release",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Profile::Fast => "changed files, fast scanners, no AI",
            Profile::Balanced => "full scan, AI on high-confidence hypotheses",
            Profile::Deep => "all scanners, lower investigation threshold",
            Profile::Release => "deep scan plus dynamic validation",
        }
    }

    /// Whether to restrict analysis to files changed against the base ref.
    pub fn incremental(self) -> bool {
        matches!(self, Profile::Fast)
    }

    pub fn allows_ai(self) -> bool {
        !matches!(self, Profile::Fast)
    }

    pub fn allows_dynamic_validation(self) -> bool {
        matches!(self, Profile::Release)
    }

    /// Correlated confidence a hypothesis must reach before costing model tokens.
    ///
    /// Deeper profiles lower the bar because the user has opted into spending more.
    pub fn investigation_threshold(self) -> Confidence {
        match self {
            Profile::Fast => Confidence::CERTAIN,
            Profile::Balanced => Confidence::new(0.75),
            Profile::Deep => Confidence::new(0.55),
            Profile::Release => Confidence::new(0.45),
        }
    }

    /// Confidence below which a hypothesis is not reported at all.
    pub fn reporting_threshold(self) -> Confidence {
        match self {
            Profile::Fast => Confidence::new(0.6),
            Profile::Balanced => Confidence::new(0.4),
            Profile::Deep => Confidence::new(0.25),
            Profile::Release => Confidence::new(0.25),
        }
    }

    /// Cap on hypotheses handed to the model in one run, so cost stays bounded.
    pub fn max_investigations(self) -> usize {
        match self {
            Profile::Fast => 0,
            Profile::Balanced => 12,
            Profile::Deep => 40,
            Profile::Release => 80,
        }
    }

    /// Wall-clock budget for a single scanner plugin.
    pub fn plugin_timeout(self) -> Duration {
        match self {
            Profile::Fast => Duration::from_secs(60),
            Profile::Balanced => Duration::from_secs(300),
            Profile::Deep => Duration::from_secs(900),
            Profile::Release => Duration::from_secs(1800),
        }
    }

    /// Highest estimated runtime tier a plugin may declare and still be scheduled.
    pub fn max_plugin_cost(self) -> u8 {
        match self {
            Profile::Fast => 1,
            Profile::Balanced => 2,
            Profile::Deep => 3,
            Profile::Release => 3,
        }
    }

    /// Default severity at which CI should fail.
    pub fn fail_on(self) -> Severity {
        match self {
            Profile::Fast => Severity::High,
            Profile::Balanced => Severity::High,
            Profile::Deep => Severity::Medium,
            Profile::Release => Severity::Medium,
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Profile {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "fast" | "quick" => Profile::Fast,
            "balanced" | "default" => Profile::Balanced,
            "deep" | "full" => Profile::Deep,
            "release" | "gate" => Profile::Release,
            other => {
                return Err(crate::Error::config(format!(
                    "unknown profile `{other}` (expected fast, balanced, deep or release)"
                )))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_never_spends_tokens() {
        assert!(!Profile::Fast.allows_ai());
        assert_eq!(Profile::Fast.max_investigations(), 0);
        assert_eq!(
            Profile::Fast.investigation_threshold(),
            Confidence::CERTAIN,
            "unreachable threshold is the belt to max_investigations' braces"
        );
    }

    #[test]
    fn deeper_profiles_investigate_more_readily() {
        assert!(
            Profile::Deep.investigation_threshold() < Profile::Balanced.investigation_threshold()
        );
        assert!(Profile::Deep.max_investigations() > Profile::Balanced.max_investigations());
    }

    #[test]
    fn only_release_validates_dynamically() {
        for p in Profile::ALL {
            assert_eq!(p.allows_dynamic_validation(), p == Profile::Release);
        }
    }

    #[test]
    fn reporting_bar_is_never_above_investigation_bar() {
        for p in Profile::ALL {
            assert!(p.reporting_threshold() <= p.investigation_threshold());
        }
    }

    #[test]
    fn parses_aliases() {
        assert_eq!("QUICK".parse::<Profile>().unwrap(), Profile::Fast);
        assert!("banana".parse::<Profile>().is_err());
    }
}
