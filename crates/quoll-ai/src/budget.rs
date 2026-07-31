//! Hard ceilings on model spend.
//!
//! A budget is not advisory. Crossing it stops investigation for the rest of the run and
//! surfaces as exit code 6 so a CI pipeline can tell "we ran out of tokens" from "the
//! model failed".

use quoll_core::config::AiConfig;
use quoll_core::{Error, Result};

/// Running totals for one scan.
#[derive(Debug, Clone)]
pub struct Budget {
    pub max_tokens: Option<u64>,
    pub max_calls: Option<u64>,
    pub tokens_used: u64,
    pub calls_used: u64,
}

impl Budget {
    pub fn unlimited() -> Budget {
        Budget {
            max_tokens: None,
            max_calls: None,
            tokens_used: 0,
            calls_used: 0,
        }
    }

    pub fn from_config(config: &AiConfig) -> Budget {
        Budget {
            max_tokens: config.token_budget,
            // A call cap keeps a misbehaving loop from spinning even when tokens are open.
            max_calls: Some(config.max_investigations.unwrap_or(64) as u64 * 2),
            tokens_used: 0,
            calls_used: 0,
        }
    }

    pub fn with_token_budget(mut self, tokens: u64) -> Budget {
        self.max_tokens = Some(tokens);
        self
    }

    pub fn with_call_budget(mut self, calls: u64) -> Budget {
        self.max_calls = Some(calls);
        self
    }

    /// Reserve capacity for one call of approximately `estimated_tokens`.
    pub fn authorize(&self, estimated_tokens: u64) -> Result<()> {
        if let Some(max) = self.max_calls {
            if self.calls_used >= max {
                return Err(Error::Budget(format!(
                    "call budget exhausted ({max} calls)"
                )));
            }
        }
        if let Some(max) = self.max_tokens {
            if self.tokens_used + estimated_tokens > max {
                return Err(Error::Budget(format!(
                    "token budget exhausted ({}/{} used, need ~{estimated_tokens} more)",
                    self.tokens_used, max
                )));
            }
        }
        Ok(())
    }

    pub fn record(&mut self, tokens: u64) {
        self.calls_used += 1;
        self.tokens_used = self.tokens_used.saturating_add(tokens);
    }

    pub fn remaining_tokens(&self) -> Option<u64> {
        self.max_tokens.map(|max| max.saturating_sub(self.tokens_used))
    }

    pub fn is_exhausted(&self) -> bool {
        self.authorize(1).is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_budget_blocks_overspend() {
        let mut budget = Budget::unlimited().with_token_budget(100);
        budget.record(90);
        assert!(budget.authorize(5).is_ok());
        assert!(budget.authorize(20).is_err());
    }

    #[test]
    fn call_budget_blocks_extra_calls() {
        let mut budget = Budget::unlimited().with_call_budget(1);
        assert!(budget.authorize(1).is_ok());
        budget.record(10);
        assert!(budget.authorize(1).is_err());
    }
}
