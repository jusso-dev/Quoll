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

/// Refuse to write through a symlink anywhere under `path`.
///
/// `.quoll/` lives in the scanned repository, so its contents are attacker-controlled: a
/// committed `.quoll/last-scan.json -> ~/.ssh/authorized_keys` would otherwise be
/// overwritten by the next scan. Checks `path` itself and, if it is a real directory,
/// everything beneath it. A missing path is fine; it will be created fresh.
pub fn ensure_state_dir_safe(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(path, e)),
    };
    if meta.file_type().is_symlink() {
        return Err(Error::config(format!(
            "`{}` is a symlink; Quoll will not write state through it. Remove it and re-run",
            path.display()
        )));
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|e| Error::io(path, e))? {
            let entry = entry.map_err(|e| Error::io(path, e))?;
            ensure_state_dir_safe(&entry.path())?;
        }
    }
    Ok(())
}

pub fn save_last_scan(state_dir: &Path, stored: &StoredScan) -> Result<PathBuf> {
    ensure_state_dir_safe(state_dir)?;
    std::fs::create_dir_all(state_dir).map_err(|e| Error::io(state_dir, e))?;
    let path = last_scan_path(state_dir);
    let text = serde_json::to_string_pretty(stored)?;
    std::fs::write(&path, text).map_err(|e| Error::io(&path, e))?;
    Ok(path)
}

pub fn load_last_scan(state_dir: &Path) -> Result<StoredScan> {
    let path = last_scan_path(state_dir);
    if !path.is_file() {
        return Err(Error::not_found(format!(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_plain_state_dirs_are_safe() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".quoll");
        assert!(ensure_state_dir_safe(&state).is_ok());
        std::fs::create_dir_all(state.join("reports")).unwrap();
        std::fs::write(state.join("reports/report.md"), "# ok").unwrap();
        assert!(ensure_state_dir_safe(&state).is_ok());
    }

    #[test]
    fn a_missing_previous_scan_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(load_last_scan(dir.path()), Err(Error::NotFound(_))));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_in_the_state_dir_are_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("authorized_keys");
        std::fs::write(&victim, "keep me").unwrap();

        // A planted entry inside the state dir.
        let state = dir.path().join("repo/.quoll");
        std::fs::create_dir_all(state.join("reports")).unwrap();
        symlink(&victim, state.join("reports/report.md")).unwrap();
        assert!(matches!(ensure_state_dir_safe(&state), Err(Error::Config(_))));

        // The state dir itself as a link.
        let linked = dir.path().join("other/.quoll");
        std::fs::create_dir_all(linked.parent().unwrap()).unwrap();
        symlink(dir.path(), &linked).unwrap();
        assert!(ensure_state_dir_safe(&linked).is_err());

        // The canonical attack: last-scan.json pointing somewhere precious.
        let state = dir.path().join("third/.quoll");
        std::fs::create_dir_all(&state).unwrap();
        symlink(&victim, last_scan_path(&state)).unwrap();
        assert!(ensure_state_dir_safe(&state).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
    }
}
