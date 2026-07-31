use serde::{Deserialize, Serialize};

use crate::{ids, Confidence, Location};

/// Where a piece of evidence came from.
///
/// The distinction matters: `Scanner` and `Graph` evidence is reproducible and can be
/// re-derived on any machine, while `Ai` evidence is not. Reports separate the two so a
/// reader can always tell which conclusions rest on deterministic ground.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceSource {
    /// An external security tool, e.g. Semgrep rule `javascript.express.security.x`.
    Scanner { plugin: String, rule: String },
    /// A structural fact proven from the code graph.
    Graph { relation: String },
    /// A framework policy expectation that was met or violated.
    Policy { pack: String, control: String },
    /// A detected technology or framework.
    Detection { technology: String },
    /// A reasoning step from a language model. Never sufficient on its own.
    Ai { provider: String, model: String },
    /// A runtime observation from a dynamic validator.
    Dynamic { plugin: String },
    /// Repository history, e.g. a secret present in a previous commit.
    History { commit: String },
}

impl EvidenceSource {
    pub fn label(&self) -> String {
        match self {
            EvidenceSource::Scanner { plugin, rule } => format!("{plugin}:{rule}"),
            EvidenceSource::Graph { relation } => format!("graph:{relation}"),
            EvidenceSource::Policy { pack, control } => format!("policy:{pack}/{control}"),
            EvidenceSource::Detection { technology } => format!("detect:{technology}"),
            EvidenceSource::Ai { provider, model } => format!("ai:{provider}/{model}"),
            EvidenceSource::Dynamic { plugin } => format!("dynamic:{plugin}"),
            EvidenceSource::History { commit } => format!("history:{}", &commit[..commit.len().min(8)]),
        }
    }

    /// Whether re-running Quoll on the same commit reproduces this evidence exactly.
    pub fn is_deterministic(&self) -> bool {
        !matches!(self, EvidenceSource::Ai { .. } | EvidenceSource::Dynamic { .. })
    }

    /// Prior weight applied when combining independent sources.
    ///
    /// Deterministic proof outranks pattern matching, which outranks model reasoning.
    /// This ordering is the numeric expression of Quoll's central philosophy.
    pub fn base_weight(&self) -> f64 {
        match self {
            EvidenceSource::Graph { .. } => 1.0,
            EvidenceSource::Dynamic { .. } => 1.0,
            EvidenceSource::Policy { .. } => 0.9,
            EvidenceSource::Scanner { .. } => 0.8,
            EvidenceSource::History { .. } => 0.8,
            EvidenceSource::Detection { .. } => 0.7,
            EvidenceSource::Ai { .. } => 0.5,
        }
    }
}

/// What the evidence argues for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Increases belief that the vulnerability is real.
    Supporting,
    /// Decreases it — a compensating control, a guard, a sanitiser.
    Refuting,
    /// Neither; recorded for the reader's benefit.
    Contextual,
}

/// One indivisible, citable fact.
///
/// Every finding Quoll emits carries the evidence that produced it, and every AI
/// conclusion must cite at least one non-AI item. That invariant is enforced in
/// `Finding::validate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub source: EvidenceSource,
    pub kind: EvidenceKind,
    /// One sentence a human can read without opening the code.
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// How strongly this single fact argues its case, before source weighting.
    pub confidence: Confidence,
}

impl Evidence {
    pub fn new(
        source: EvidenceSource,
        kind: EvidenceKind,
        description: impl Into<String>,
        confidence: Confidence,
    ) -> Evidence {
        let description = description.into();
        let id = ids::stable_id("ev", &[&source.label(), &description]);
        Evidence {
            id,
            source,
            kind,
            description,
            location: None,
            confidence,
        }
    }

    pub fn supporting(
        source: EvidenceSource,
        description: impl Into<String>,
        confidence: Confidence,
    ) -> Evidence {
        Evidence::new(source, EvidenceKind::Supporting, description, confidence)
    }

    pub fn refuting(
        source: EvidenceSource,
        description: impl Into<String>,
        confidence: Confidence,
    ) -> Evidence {
        Evidence::new(source, EvidenceKind::Refuting, description, confidence)
    }

    pub fn contextual(source: EvidenceSource, description: impl Into<String>) -> Evidence {
        Evidence::new(
            source,
            EvidenceKind::Contextual,
            description,
            Confidence::ZERO,
        )
    }

    pub fn at(mut self, location: Location) -> Evidence {
        self.location = Some(location);
        self
    }

    /// Confidence after applying the source's prior weight.
    pub fn weighted_confidence(&self) -> Confidence {
        self.confidence.scale(self.source.base_weight())
    }

    pub fn is_deterministic(&self) -> bool {
        self.source.is_deterministic()
    }
}

/// Combine a bundle of evidence into a single belief.
///
/// Supporting evidence combines by noisy-OR; refuting evidence then subtracts its own
/// combined strength. A single strong refutation — say, a proven authorisation guard on
/// the path — can therefore sink an otherwise well-supported hypothesis.
pub fn correlate(evidence: &[Evidence]) -> Confidence {
    let support = Confidence::combine_all(
        evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::Supporting)
            .map(|e| e.weighted_confidence()),
    );
    let refute = Confidence::combine_all(
        evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::Refuting)
            .map(|e| e.weighted_confidence()),
    );
    support.penalise(refute.value())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner(rule: &str) -> EvidenceSource {
        EvidenceSource::Scanner {
            plugin: "semgrep".into(),
            rule: rule.into(),
        }
    }

    #[test]
    fn ai_evidence_is_marked_non_deterministic() {
        let ai = EvidenceSource::Ai {
            provider: "openai".into(),
            model: "gpt-5.6".into(),
        };
        assert!(!ai.is_deterministic());
        assert!(scanner("r").is_deterministic());
    }

    #[test]
    fn graph_proof_outweighs_model_reasoning() {
        let graph = EvidenceSource::Graph {
            relation: "routes_to".into(),
        };
        let ai = EvidenceSource::Ai {
            provider: "openai".into(),
            model: "m".into(),
        };
        assert!(graph.base_weight() > ai.base_weight());
    }

    #[test]
    fn refutation_lowers_correlated_confidence() {
        let support = vec![
            Evidence::supporting(scanner("a"), "tainted input", Confidence::new(0.7)),
            Evidence::supporting(scanner("b"), "reaches sink", Confidence::new(0.7)),
        ];
        let with_refutation = {
            let mut v = support.clone();
            v.push(Evidence::refuting(
                EvidenceSource::Graph {
                    relation: "guarded_by".into(),
                },
                "authorisation guard on path",
                Confidence::new(0.9),
            ));
            v
        };
        assert!(correlate(&with_refutation) < correlate(&support));
    }

    #[test]
    fn contextual_evidence_does_not_move_the_needle() {
        let base = vec![Evidence::supporting(
            scanner("a"),
            "x",
            Confidence::new(0.5),
        )];
        let mut with_context = base.clone();
        with_context.push(Evidence::contextual(scanner("b"), "note"));
        assert_eq!(correlate(&base), correlate(&with_context));
    }

    #[test]
    fn identical_evidence_gets_identical_ids() {
        let a = Evidence::supporting(scanner("a"), "x", Confidence::new(0.5));
        let b = Evidence::supporting(scanner("a"), "x", Confidence::new(0.9));
        assert_eq!(a.id, b.id, "id should key on source and claim, not strength");
    }
}
