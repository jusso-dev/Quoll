//! Investigation cache keyed on hypothesis content.
//!
//! Re-running a scan on the same commit must not re-spend tokens on a hypothesis the
//! model already settled. The key is a hash of class, location and evidence ids — not the
//! hypothesis id, which can change between builds.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use quoll_core::{AttackHypothesis, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::InvestigationVerdict;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvestigationCache {
    entries: HashMap<String, InvestigationVerdict>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl InvestigationCache {
    pub fn memory() -> InvestigationCache {
        InvestigationCache::default()
    }

    pub fn load(path: impl Into<PathBuf>) -> Result<InvestigationCache> {
        let path = path.into();
        if !path.is_file() {
            return Ok(InvestigationCache {
                path: Some(path),
                ..Default::default()
            });
        }
        let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
        let mut cache: InvestigationCache = serde_json::from_str(&text)?;
        cache.path = Some(path);
        Ok(cache)
    }

    pub fn get(&self, hypothesis: &AttackHypothesis) -> Option<&InvestigationVerdict> {
        self.entries.get(&key(hypothesis))
    }

    pub fn insert(&mut self, hypothesis: &AttackHypothesis, verdict: InvestigationVerdict) {
        self.entries.insert(key(hypothesis), verdict);
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, text).map_err(|e| Error::io(path, e))?;
        Ok(())
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

fn key(hypothesis: &AttackHypothesis) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hypothesis.class.as_str().as_bytes());
    hasher.update(hypothesis.location.path.to_string_lossy().as_bytes());
    hasher.update(hypothesis.location.line().to_string().as_bytes());
    let mut evidence_ids: Vec<&str> = hypothesis.evidence.iter().map(|e| e.id.as_str()).collect();
    evidence_ids.sort_unstable();
    for id in evidence_ids {
        hasher.update(id.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::{
        AttackHypothesis, Confidence, Evidence, EvidenceSource, HypothesisClass, Location,
    };

    fn hyp() -> AttackHypothesis {
        AttackHypothesis::new(
            HypothesisClass::SqlInjection,
            Location::at("a.rs", 1),
            vec![Evidence::supporting(
                EvidenceSource::Scanner {
                    plugin: "semgrep".into(),
                    rule: "sqli".into(),
                },
                "concat",
                Confidence::new(0.8),
            )],
        )
    }

    #[test]
    fn round_trips_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let mut cache = InvestigationCache::load(&path).unwrap();
        let verdict = InvestigationVerdict {
            kind: crate::VerdictKind::Confirmed,
            rationale: "real".into(),
            model: "mock".into(),
            tokens: 10,
        };
        cache.insert(&hyp(), verdict.clone());
        cache.save().unwrap();

        let reloaded = InvestigationCache::load(&path).unwrap();
        assert_eq!(reloaded.get(&hyp()).unwrap().rationale, "real");
    }
}
