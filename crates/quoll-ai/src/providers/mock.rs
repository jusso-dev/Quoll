use async_trait::async_trait;
use quoll_core::Result;

use crate::provider::{CompletionRequest, CompletionResponse, Provider};
use crate::VerdictKind;

/// Deterministic provider for tests and offline demos.
pub struct MockProvider {
    kind: VerdictKind,
    rationale: String,
}

impl MockProvider {
    pub fn confirming() -> MockProvider {
        MockProvider {
            kind: VerdictKind::Confirmed,
            rationale: "Mock provider confirms the hypothesis from the supplied evidence.".into(),
        }
    }

    pub fn rejecting() -> MockProvider {
        MockProvider {
            kind: VerdictKind::Rejected,
            rationale: "Mock provider rejects the hypothesis.".into(),
        }
    }

    pub fn abstaining() -> MockProvider {
        MockProvider {
            kind: VerdictKind::Abstain,
            rationale: "Mock provider abstains.".into(),
        }
    }
}

#[async_trait]
impl Provider for MockProvider {
    fn id(&self) -> &str {
        "mock"
    }

    async fn complete(&self, _request: CompletionRequest) -> Result<CompletionResponse> {
        let verdict = match self.kind {
            VerdictKind::Confirmed => "confirmed",
            VerdictKind::Rejected => "rejected",
            VerdictKind::Abstain => "abstain",
        };
        let text = format!(
            "{{\"verdict\":\"{verdict}\",\"rationale\":{}}}",
            serde_json::to_string(&self.rationale).unwrap()
        );
        Ok(CompletionResponse {
            text,
            model: "mock".into(),
            input_tokens: 100,
            output_tokens: 50,
        })
    }
}
