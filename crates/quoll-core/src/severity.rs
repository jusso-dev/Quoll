use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Impact rating, ordered so that `Critical > High > ... > Info`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The default. An unrated finding must never be assumed serious.
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// SARIF 2.1.0 only defines `none`/`note`/`warning`/`error`.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Info => "note",
            Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High => "error",
            Severity::Critical => "error",
        }
    }

    /// CVSS v3 qualitative band midpoint, used when a tool reports no numeric score.
    pub fn nominal_cvss(self) -> f32 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 3.0,
            Severity::Medium => 5.5,
            Severity::High => 7.5,
            Severity::Critical => 9.5,
        }
    }

    pub fn from_cvss(score: f32) -> Severity {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Deliberately generous: scanners disagree wildly on spelling.
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" | "blocker" => Severity::Critical,
            "high" | "error" | "severe" => Severity::High,
            "medium" | "moderate" | "warning" | "warn" => Severity::Medium,
            "low" | "minor" | "note" => Severity::Low,
            "info" | "informational" | "none" | "unknown" | "" => Severity::Info,
            other => {
                return Err(crate::Error::parse(
                    "severity",
                    format!("unrecognised severity `{other}`"),
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_by_impact() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
    }

    #[test]
    fn parses_scanner_dialects() {
        assert_eq!("BLOCKER".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("WARNING".parse::<Severity>().unwrap(), Severity::Medium);
        assert_eq!("moderate".parse::<Severity>().unwrap(), Severity::Medium);
        assert!("banana".parse::<Severity>().is_err());
    }

    #[test]
    fn cvss_round_trip_stays_in_band() {
        for sev in Severity::ALL {
            if sev != Severity::Info {
                assert_eq!(Severity::from_cvss(sev.nominal_cvss()), sev);
            }
        }
    }
}
