//! Shared domain vocabulary for Quoll.
//!
//! Every other crate in the workspace speaks these types. `quoll-core` deliberately
//! depends on no scanner, no AI provider and no storage engine so that the contract
//! between the orchestrator and its plugins stays stable.

pub mod config;
pub mod confidence;
pub mod error;
pub mod evidence;
pub mod finding;
pub mod hypothesis;
pub mod ids;
pub mod location;
pub mod profile;
pub mod severity;
pub mod tech;
pub mod time_util;

pub use confidence::Confidence;
pub use error::{Error, Result};
pub use evidence::{Evidence, EvidenceKind, EvidenceSource};
pub use finding::{Finding, FindingStatus, Fix, RawFinding, Remediation};
pub use hypothesis::{AttackHypothesis, HypothesisClass, HypothesisStatus};
pub use location::{Location, Span};
pub use profile::Profile;
pub use severity::Severity;
pub use tech::{Ecosystem, Framework, Language, TechStack, Technology};
