use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// A probability in `[0.0, 1.0]` that a claim is true.
///
/// Quoll combines confidence from many independent sources, so the arithmetic here is
/// the one place where the correlation maths lives. Values are clamped on construction:
/// a scanner reporting `1.4` should not be able to poison downstream thresholds.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Confidence(f64);

impl Confidence {
    pub const ZERO: Confidence = Confidence(0.0);
    pub const CERTAIN: Confidence = Confidence(1.0);

    pub fn new(value: f64) -> Confidence {
        if value.is_nan() {
            return Confidence::ZERO;
        }
        Confidence(value.clamp(0.0, 1.0))
    }

    pub fn value(self) -> f64 {
        self.0
    }

    pub fn percent(self) -> u8 {
        (self.0 * 100.0).round() as u8
    }

    /// Noisy-OR combination of independent supporting evidence.
    ///
    /// Two sources at 0.6 give 0.84 — more than either alone, never reaching certainty.
    /// This is the correct operator for "several tools independently point at this",
    /// which is exactly what the hypothesis engine does.
    pub fn combine(self, other: Confidence) -> Confidence {
        Confidence(1.0 - (1.0 - self.0) * (1.0 - other.0))
    }

    pub fn combine_all(items: impl IntoIterator<Item = Confidence>) -> Confidence {
        items
            .into_iter()
            .fold(Confidence::ZERO, |acc, c| acc.combine(c))
    }

    /// Scale a confidence down by a factor in `[0, 1]`, e.g. to discount a weak source.
    pub fn scale(self, factor: f64) -> Confidence {
        Confidence::new(self.0 * factor.clamp(0.0, 1.0))
    }

    /// Reduce confidence in the presence of a contradicting signal.
    pub fn penalise(self, penalty: f64) -> Confidence {
        Confidence::new(self.0 - penalty.clamp(0.0, 1.0))
    }

    pub fn label(self) -> &'static str {
        match self.0 {
            v if v >= 0.9 => "very high",
            v if v >= 0.75 => "high",
            v if v >= 0.5 => "moderate",
            v if v >= 0.25 => "low",
            _ => "speculative",
        }
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::ZERO
    }
}

impl Eq for Confidence {}

#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Safe: NaN is impossible by construction.
        self.0.partial_cmp(&other.0).unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

impl From<f64> for Confidence {
    fn from(value: f64) -> Self {
        Confidence::new(value)
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Confidence::new(f64::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_out_of_range_input() {
        assert_eq!(Confidence::new(1.9), Confidence::CERTAIN);
        assert_eq!(Confidence::new(-3.0), Confidence::ZERO);
        assert_eq!(Confidence::new(f64::NAN), Confidence::ZERO);
    }

    #[test]
    fn noisy_or_is_monotonic_and_bounded() {
        let a = Confidence::new(0.6);
        let combined = a.combine(Confidence::new(0.6));
        assert!(combined > a);
        assert!(combined.value() < 1.0);
        assert!((combined.value() - 0.84).abs() < 1e-9);
    }

    #[test]
    fn certainty_is_absorbing() {
        assert_eq!(
            Confidence::CERTAIN.combine(Confidence::new(0.1)),
            Confidence::CERTAIN
        );
    }

    #[test]
    fn combine_all_of_nothing_is_zero() {
        assert_eq!(Confidence::combine_all([]), Confidence::ZERO);
    }
}
