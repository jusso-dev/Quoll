//! Persist the last scan so `findings`, `explain` and `export` have something to read.

use std::path::{Path, PathBuf};

use quoll_core::{time_util, AttackHypothesis, Error, Finding, Result};
use quoll_report::Report;
use serde::{Deserialize, Serialize};

const LAST_SCAN: &str = "last-scan.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredScan {
    pub saved_at: String,
    pub report: Report,
    #[serde(default)]
    pub hypotheses: Vec<AttackHypothesis>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl StoredScan {
    pub fn finding(&self, id: &str) -> Option<&Finding> {
        self.findings
            .iter()
            .find(|f| f.id == id || f.fingerprint == id)
            .or_else(|| {
                self.report
                    .findings
                    .iter()
                    .map(|r| &r.finding)
                    .find(|f| f.id == id || f.fingerprint == id)
            })
    }

    pub fn hypothesis(&self, id: &str) -> Option<&AttackHypothesis> {
        self.hypotheses.iter().find(|h| h.id == id)
    }
}

pub fn last_scan_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LAST_SCAN)
}

pub fn save_last_scan(state_dir: &Path, stored: &StoredScan) -> Result<PathBuf> {
    std::fs::create_dir_all(state_dir).map_err(|e| Error::io(state_dir, e))?;
    let path = last_scan_path(state_dir);
    let text = serde_json::to_string_pretty(stored)?;
    std::fs::write(&path, text).map_err(|e| Error::io(&path, e))?;
    Ok(path)
}

pub fn load_last_scan(state_dir: &Path) -> Result<StoredScan> {
    let path = last_scan_path(state_dir);
    if !path.is_file() {
        return Err(Error::other(format!(
            "no previous scan at `{}`; run `quoll scan` first",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn store_from_outcome(
    report: Report,
    hypotheses: Vec<AttackHypothesis>,
    findings: Vec<Finding>,
) -> StoredScan {
    StoredScan {
        saved_at: time_util::now_rfc3339(),
        report,
        hypotheses,
        findings,
    }
}
