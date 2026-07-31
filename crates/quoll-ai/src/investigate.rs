//! Hypothesis investigation.
//!
//! The model is handed only the evidence Quoll already holds and a closed set of
//! questions. It may confirm, reject or abstain — never invent a location, never mint a
//! finding of its own.

use quoll_core::{
    AttackHypothesis, Confidence, Evidence, EvidenceSource, HypothesisStatus, Result,
};
use serde::{Deserialize, Serialize};

use crate::budget::Budget;
use crate::cache::InvestigationCache;
use crate::provider::{CompletionRequest, Provider};

/// What the model decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictKind {
    Confirmed,
    Rejected,
    /// Model could not decide from the evidence; hypothesis stays proposed.
    Abstain,
}

/// Structured result of one investigation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigationVerdict {
    pub kind: VerdictKind,
    pub rationale: String,
    pub model: String,
    pub tokens: u64,
}

impl InvestigationVerdict {
    pub fn as_evidence(&self, provider_id: &str) -> Evidence {
        let source = EvidenceSource::Ai {
            provider: provider_id.to_string(),
            model: self.model.clone(),
        };
        let confidence = match self.kind {
            VerdictKind::Confirmed | VerdictKind::Rejected => Confidence::new(0.75),
            VerdictKind::Abstain => Confidence::new(0.3),
        };
        match self.kind {
            VerdictKind::Confirmed => {
                Evidence::supporting(source, self.rationale.clone(), confidence)
            }
            VerdictKind::Rejected => Evidence::refuting(source, self.rationale.clone(), confidence),
            VerdictKind::Abstain => Evidence::contextual(source, self.rationale.clone()),
        }
    }

    pub fn apply(self, hypothesis: &mut AttackHypothesis, provider_id: &str) {
        let evidence = self.as_evidence(provider_id);
        hypothesis.add_evidence(evidence);
        hypothesis.status = match self.kind {
            VerdictKind::Confirmed => HypothesisStatus::Confirmed,
            VerdictKind::Rejected => HypothesisStatus::Rejected,
            VerdictKind::Abstain => HypothesisStatus::Proposed,
        };
        if hypothesis.narrative.is_empty() && !self.rationale.is_empty() {
            hypothesis.narrative = self.rationale;
        }
    }
}

/// Runs investigations against a provider under a hard budget.
pub struct Investigator<P: Provider> {
    provider: P,
    budget: Budget,
    cache: InvestigationCache,
}

impl<P: Provider> Investigator<P> {
    pub fn new(provider: P, budget: Budget) -> Investigator<P> {
        Investigator {
            provider,
            budget,
            cache: InvestigationCache::memory(),
        }
    }

    pub fn with_cache(mut self, cache: InvestigationCache) -> Investigator<P> {
        self.cache = cache;
        self
    }

    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    pub fn budget_mut(&mut self) -> &mut Budget {
        &mut self.budget
    }

    pub fn cache(&self) -> &InvestigationCache {
        &self.cache
    }

    pub fn provider_id(&self) -> &str {
        self.provider.id()
    }

    /// Investigate one hypothesis, using the cache when possible.
    pub async fn investigate(
        &mut self,
        hypothesis: &AttackHypothesis,
    ) -> Result<InvestigationVerdict> {
        if let Some(cached) = self.cache.get(hypothesis) {
            tracing::debug!(id = %hypothesis.id, "investigation cache hit");
            return Ok(cached.clone());
        }

        let request = CompletionRequest::investigate(system_prompt(), user_prompt(hypothesis));
        self.budget.authorize(request.estimated_tokens)?;
        let response = self.provider.complete(request).await?;
        self.budget.record(response.total_tokens());

        let verdict = parse_verdict(&response.text, &response.model, response.total_tokens());
        self.cache.insert(hypothesis, verdict.clone());
        let _ = self.cache.save();
        Ok(verdict)
    }

    /// Dry-run: build the prompt, spend nothing.
    pub fn dry_run_prompt(&self, hypothesis: &AttackHypothesis) -> (String, String) {
        (system_prompt(), user_prompt(hypothesis))
    }
}

fn system_prompt() -> String {
    "You are a security investigator for Quoll. You may only reason over the evidence \
     provided. Never invent file paths or line numbers. Reply with exactly one JSON object: \
     {\"verdict\":\"confirmed\"|\"rejected\"|\"abstain\",\"rationale\":\"one short paragraph\"}."
        .into()
}

fn user_prompt(hypothesis: &AttackHypothesis) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Class: {}", hypothesis.class.as_str()));
    lines.push(format!("Title: {}", hypothesis.title));
    lines.push(format!("Location: {}", hypothesis.location.display()));
    lines.push(format!(
        "Confidence so far: {:.2}",
        hypothesis.confidence.value()
    ));
    if !hypothesis.narrative.is_empty() {
        lines.push(format!("Narrative: {}", hypothesis.narrative));
    }
    if let Some(entry) = &hypothesis.entry_point {
        lines.push(format!("Entry point: {entry}"));
    }
    lines.push("Evidence:".into());
    for item in &hypothesis.evidence {
        lines.push(format!(
            "- [{}] {} ({:.0}%): {}",
            if item.is_deterministic() {
                "det"
            } else {
                "ai"
            },
            item.source.label(),
            item.confidence.percent(),
            item.description
        ));
    }
    if !hypothesis.open_questions.is_empty() {
        lines.push("Open questions:".into());
        for q in &hypothesis.open_questions {
            lines.push(format!("- {q}"));
        }
    }
    lines.join("\n")
}

fn parse_verdict(text: &str, model: &str, tokens: u64) -> InvestigationVerdict {
    // Prefer a JSON object embedded in the reply; fall back to keyword scan.
    if let Some(json) = extract_json(text) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) {
            let kind = match value
                .get("verdict")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str()
            {
                "confirmed" | "confirm" | "true" | "yes" => VerdictKind::Confirmed,
                "rejected" | "reject" | "false" | "no" => VerdictKind::Rejected,
                _ => VerdictKind::Abstain,
            };
            let rationale = value
                .get("rationale")
                .and_then(|v| v.as_str())
                .unwrap_or(text)
                .trim()
                .to_string();
            return InvestigationVerdict {
                kind,
                rationale,
                model: model.to_string(),
                tokens,
            };
        }
    }

    let lower = text.to_ascii_lowercase();
    let kind = if lower.contains("\"confirmed\"") || lower.contains("verdict: confirmed") {
        VerdictKind::Confirmed
    } else if lower.contains("\"rejected\"") || lower.contains("verdict: rejected") {
        VerdictKind::Rejected
    } else {
        VerdictKind::Abstain
    };
    InvestigationVerdict {
        kind,
        rationale: text.trim().to_string(),
        model: model.to_string(),
        tokens,
    }
}

fn extract_json(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end > start {
        Some(text[start..=end].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::MockProvider;
    use quoll_core::{Evidence, EvidenceSource, HypothesisClass, Location};

    fn hyp() -> AttackHypothesis {
        AttackHypothesis::new(
            HypothesisClass::SqlInjection,
            Location::at("src/db.rs", 10),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: "sqli".into(),
                },
                "string concat into query",
                Confidence::new(0.8),
            )],
        )
    }

    #[tokio::test]
    async fn confirming_provider_marks_hypothesis_confirmed() {
        let mut inv = Investigator::new(MockProvider::confirming(), Budget::unlimited());
        let mut h = hyp();
        let verdict = inv.investigate(&h).await.unwrap();
        assert_eq!(verdict.kind, VerdictKind::Confirmed);
        verdict.apply(&mut h, "mock");
        assert_eq!(h.status, HypothesisStatus::Confirmed);
        assert!(h.evidence.iter().any(|e| !e.is_deterministic()));
    }

    #[tokio::test]
    async fn budget_exhaustion_surfaces_as_budget_error() {
        let mut inv = Investigator::new(
            MockProvider::confirming(),
            Budget::unlimited().with_call_budget(0),
        );
        let err = inv.investigate(&hyp()).await.unwrap_err();
        assert!(matches!(err, quoll_core::Error::Budget(_)));
    }
}
