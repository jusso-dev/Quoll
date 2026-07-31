use async_trait::async_trait;
use quoll_core::{Error, Result};

use crate::provider::{CompletionRequest, CompletionResponse, Provider};

/// Provider that refuses every call. Used when AI is disabled.
pub struct NullProvider;

#[async_trait]
impl Provider for NullProvider {
    fn id(&self) -> &str {
        "null"
    }

    async fn complete(&self, _request: CompletionRequest) -> Result<CompletionResponse> {
        Err(Error::NoAiProvider)
    }
}
