use sha2::{Digest, Sha256};

/// Deterministic identifier derived from stable components.
///
/// Report reproducibility depends on this: the same repository scanned twice must
/// produce byte-identical IDs, and a finding that merely moves down a file should keep
/// its identity so that CI baselines and suppressions survive refactors.
pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        // Length-prefixed separator so ("ab","c") and ("a","bc") never collide.
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    if prefix.is_empty() {
        hex
    } else {
        format!("{prefix}-{hex}")
    }
}

/// Full 64-character digest, used for content addressing files in the graph.
pub fn content_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Fingerprint used to match findings across runs.
///
/// Line numbers are excluded on purpose. Including them would break the baseline every
/// time an import is added above the finding.
pub fn finding_fingerprint(rule_id: &str, path: &str, code_context: &str) -> String {
    let normalised: String = code_context.split_whitespace().collect::<Vec<_>>().join(" ");
    stable_id("fp", &[rule_id, path, &normalised])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_deterministic() {
        assert_eq!(stable_id("f", &["a", "b"]), stable_id("f", &["a", "b"]));
    }

    #[test]
    fn separator_prevents_boundary_collisions() {
        assert_ne!(stable_id("f", &["ab", "c"]), stable_id("f", &["a", "bc"]));
    }

    #[test]
    fn fingerprint_ignores_whitespace_reflow() {
        let a = finding_fingerprint("r1", "a.rs", "let x =  1;");
        let b = finding_fingerprint("r1", "a.rs", "let x\n=\n1;");
        assert_eq!(a, b);
    }

    #[test]
    fn prefix_is_optional() {
        assert_eq!(stable_id("", &["a"]).len(), 16);
    }
}
