//! Model providers, role routing, hard budgets and investigation for Quoll.
//!
//! AI is optional and never authoritative. A model may only strengthen or weaken a
//! hypothesis that already carries deterministic evidence, and a run with AI disabled is
//! a complete product, not a degraded mode.
//!
//! ```no_run
//! use quoll_ai::{Budget, Investigator, MockProvider, Role};
//! use quoll_core::config::AiConfig;
//!
//! # async fn demo(hyp: quoll_core::AttackHypothesis) -> quoll_core::Result<()> {
//! let provider = MockProvider::confirming();
//! let mut budget = Budget::from_config(&AiConfig::default());
//! let mut investigator = Investigator::new(provider, budget);
//! let verdict = investigator.investigate(&hyp).await?;
//! # Ok(())
//! # }
//! ```

pub mod budget;
pub mod cache;
pub mod investigate;
pub mod provider;
pub mod providers;

pub use budget::Budget;
pub use cache::InvestigationCache;
pub use investigate::{InvestigationVerdict, Investigator, VerdictKind};
pub use provider::{CompletionRequest, CompletionResponse, Provider, Role};
pub use providers::{from_config, CommandProvider, HttpProvider, MockProvider, NullProvider};
