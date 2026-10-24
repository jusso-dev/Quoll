//! Changed-file scope for CI gating.
//!
//! With a base ref, CI still reports everything it finds but only fails the build on
//! findings in files the change touched. Any git trouble (shallow clone, unknown ref)
//! falls back to gating on the full scan rather than failing open.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// The base ref to diff against: explicit first, then `GITHUB_BASE_REF` on pull requests.
pub fn effective_base_ref(explicit: Option<&str>) -> Option<String> {
    if let Some(base) = explicit.filter(|b| !b.trim().is_empty()) {
        return Some(base.to_string());
    }
    std::env::var("GITHUB_BASE_REF")
        .ok()
        .filter(|b| !b.trim().is_empty())
        .map(|b| format!("origin/{}", b.trim()))
}

/// Repository-relative paths changed between the merge base of `base_ref` and `HEAD`.
///
/// `None` means the set could not be computed and the caller should gate on everything.
/// Deleted files are left out; a finding cannot point at them.
pub fn changed_files(root: &Path, base_ref: &str) -> Option<BTreeSet<String>> {
    let merge_base = git(root, &["merge-base", base_ref, "HEAD"])?;
    let merge_base = merge_base.trim();
    // `--relative` keeps paths relative to the scan root when it is a subdirectory.
    let diff = git(
        root,
        &["diff", "--name-only", "--relative", "--diff-filter=d", merge_base, "HEAD"],
    )?;
    Some(
        diff.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = match Command::new("git").arg("-C").arg(root).args(args).output() {
        Ok(output) => output,
        Err(err) => {
            tracing::warn!(error = %err, "git unavailable; gating on the full scan");
            return None;
        }
    };
    if !output.status.success() {
        tracing::warn!(
            command = %format!("git {}", args.join(" ")),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "could not compute changed files; gating on the full scan"
        );
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(root: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    #[test]
    fn diff_against_base_lists_only_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        run(root, &["init", "-q", "-b", "main"]);
        std::fs::write(root.join("old.rs"), "a").unwrap();
        run(root, &["add", "."]);
        run(root, &["commit", "-q", "-m", "base"]);
        run(root, &["checkout", "-q", "-b", "feature"]);
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src/new.rs"), "b").unwrap();
        run(root, &["add", "."]);
        run(root, &["commit", "-q", "-m", "change"]);

        let changed = changed_files(root, "main").unwrap();
        assert_eq!(changed.into_iter().collect::<Vec<_>>(), vec!["src/new.rs"]);
    }

    #[test]
    fn unknown_ref_falls_back_to_full_scope() {
        let dir = tempfile::tempdir().unwrap();
        assert!(changed_files(dir.path(), "no-such-ref").is_none());
    }
}
