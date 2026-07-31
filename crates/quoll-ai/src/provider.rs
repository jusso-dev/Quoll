//! The contract every model backend implements.

use async_trait::async_trait;
use quoll_core::Result;
use serde::{Deserialize, Serialize};

/// Which job a model is being asked to do.
///
/// The split is the point: a strong model reasons about hypotheses, a cheap model writes
/// prose. Routing never asks a cheap model whether a vulnerability is real.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Investigate,
    Report,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Investigate => "investigate",
            Role::Report => "report",
        }
    }
}

/// One completion request.
#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub role: Role,
    pub model: Option<String>,
    pub system: String,
    pub user: String,
    /// Soft estimate used for budget authorisation before the call.
    pub estimated_tokens: u64,
}

impl CompletionRequest {
    pub fn investigate(system: impl Into<String>, user: impl Into<String>) -> CompletionRequest {
        CompletionRequest {
            role: Role::Investigate,
            model: None,
            system: system.into(),
            user: user.into(),
            estimated_tokens: 2_000,
        }
    }
}

/// What came back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    pub text: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl CompletionResponse {
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

/// A model backend.
#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &str;

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
}
