use std::fmt;

use quoll_core::{Confidence, Framework, Language, Technology};
use serde::{Deserialize, Serialize};

/// What part a detected component plays in an application.
///
/// Policy packs bind to roles, not to package names: a pack that applies when the
/// application uses *an* auth library asks for `auth`, and a new auth library becomes
/// supported by adding a rule rather than by editing every pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Decides request routing and the shape of a handler: Next.js, Express, Axum.
    Framework,
    /// Talks to the database: Drizzle, Prisma, SQLx.
    Orm,
    /// Establishes who the caller is: Better Auth, NextAuth, Clerk.
    Auth,
    /// The thing the code runs on: Node, Bun, Deno.
    Runtime,
    /// A continuous integration provider.
    Ci,
    /// Everything else worth recording.
    Library,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Framework => "framework",
            Role::Orm => "orm",
            Role::Auth => "auth",
            Role::Runtime => "runtime",
            Role::Ci => "ci",
            Role::Library => "library",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A detected piece of an application's stack, with the evidence that proved it.
///
/// Evidence is mandatory in practice: a detection with no stated reason cannot be argued
/// with, and `quoll doctor` exists so a user can see exactly why Quoll believes what it
/// believes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Component {
    /// Stable identifier a policy pack can match on, e.g. `nextjs-app-router`.
    pub id: String,
    pub name: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    pub confidence: Confidence,
    /// Human-readable reasons, e.g. `package.json declares "next": "^15.0.0"`.
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl Component {
    pub fn new(id: impl Into<String>, name: impl Into<String>, role: Role) -> Component {
        Component {
            id: id.into(),
            name: name.into(),
            role,
            version: None,
            language: None,
            confidence: Confidence::new(0.5),
            evidence: Vec::new(),
        }
    }

    pub fn with_version(mut self, version: Option<String>) -> Component {
        self.version = version;
        self
    }

    pub fn with_language(mut self, language: Language) -> Component {
        self.language = Some(language);
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Component {
        self.confidence = confidence;
        self
    }

    pub fn because(mut self, reason: impl Into<String>) -> Component {
        let reason = reason.into();
        if !self.evidence.contains(&reason) {
            self.evidence.push(reason);
        }
        self
    }

    /// Major version as an integer, for packs that gate on it (`nextjs >= 15`).
    pub fn major_version(&self) -> Option<u32> {
        let version = self.version.as_ref()?;
        let digits: String = version
            .trim_start_matches(['^', '~', '>', '=', '<', 'v', ' '])
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }

    /// Fold a second sighting of the same component into this one.
    ///
    /// Two independent signals for one component — a manifest entry and a matching import —
    /// raise confidence rather than producing two detections.
    pub fn merge(&mut self, other: Component) {
        self.confidence = self.confidence.combine(other.confidence);
        if self.version.is_none() {
            self.version = other.version;
        }
        if self.language.is_none() {
            self.language = other.language;
        }
        for reason in other.evidence {
            if !self.evidence.contains(&reason) {
                self.evidence.push(reason);
            }
        }
    }

    /// Convert to the shared `Framework` type for consumers that speak `TechStack`.
    pub fn to_framework(&self) -> Framework {
        let mut framework = Framework::new(
            self.id.clone(),
            self.name.clone(),
            self.language.clone().unwrap_or(Language::Other("unknown".into())),
            self.confidence,
        )
        .with_version(self.version.clone());
        framework.evidence = self.evidence.clone();
        framework
    }

    pub fn to_technology(&self) -> Technology {
        let mut technology = Technology::new(self.id.clone(), self.name.clone(), self.confidence);
        technology.version = self.version.clone();
        technology.evidence = self.evidence.clone();
        technology
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_two_signals_raises_confidence() {
        let mut manifest = Component::new("drizzle", "Drizzle ORM", Role::Orm)
            .with_confidence(Confidence::new(0.8))
            .because("package.json declares drizzle-orm");
        let import = Component::new("drizzle", "Drizzle ORM", Role::Orm)
            .with_confidence(Confidence::new(0.6))
            .because("src/db.ts imports drizzle-orm");

        manifest.merge(import);

        assert!(manifest.confidence.value() > 0.8);
        assert_eq!(manifest.evidence.len(), 2);
    }

    #[test]
    fn merging_does_not_duplicate_identical_evidence() {
        let mut a = Component::new("next", "Next.js", Role::Framework).because("same reason");
        let b = Component::new("next", "Next.js", Role::Framework).because("same reason");
        a.merge(b);
        assert_eq!(a.evidence.len(), 1);
    }

    #[test]
    fn merging_fills_in_a_missing_version() {
        let mut without = Component::new("next", "Next.js", Role::Framework);
        let with = Component::new("next", "Next.js", Role::Framework)
            .with_version(Some("^15.2.0".into()));
        without.merge(with);
        assert_eq!(without.version.as_deref(), Some("^15.2.0"));
    }

    #[test]
    fn major_version_survives_semver_range_syntax() {
        let component =
            Component::new("next", "Next.js", Role::Framework).with_version(Some("^15.2.0".into()));
        assert_eq!(component.major_version(), Some(15));

        let pinned =
            Component::new("axum", "Axum", Role::Framework).with_version(Some("0.8.4".into()));
        assert_eq!(pinned.major_version(), Some(0));

        let missing = Component::new("x", "X", Role::Library);
        assert_eq!(missing.major_version(), None);
    }
}
