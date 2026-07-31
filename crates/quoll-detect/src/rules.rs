use quoll_core::Ecosystem;

use crate::component::Role;

/// One package-to-component rule.
///
/// Held as data rather than as code so that supporting a new framework is a table entry.
/// `language` is a string parsed through `Language::from_str` rather than the enum itself,
/// because the enum carries an owned `Other(String)` variant and cannot sit in a `const`.
pub struct Rule {
    /// Identifier a policy pack matches on.
    pub id: &'static str,
    pub name: &'static str,
    pub role: Role,
    pub language: &'static str,
    pub ecosystem: Ecosystem,
    /// Declaring any of these packages proves the component is present.
    pub packages: &'static [&'static str],
    /// An import whose module path starts with one of these supports the detection.
    ///
    /// Imports are corroboration, not proof: a package can be declared and never used, and
    /// in a monorepo it can be used and declared two directories up.
    pub import_prefixes: &'static [&'static str],
}

/// Every package rule Quoll ships.
///
/// The MVP set is deliberate — Next.js, Better Auth, Drizzle, Prisma, Express, Axum and
/// Actix Web are what the first policy packs bind to. The rest are here because the cost of
/// a table row is nothing and an unrecognised stack produces a silently empty detection.
pub const RULES: &[Rule] = &[
    // ---- JavaScript and TypeScript frameworks ----
    Rule {
        id: "nextjs",
        name: "Next.js",
        role: Role::Framework,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["next"],
        import_prefixes: &["next/", "next"],
    },
    Rule {
        id: "express",
        name: "Express",
        role: Role::Framework,
        language: "javascript",
        ecosystem: Ecosystem::Npm,
        packages: &["express"],
        import_prefixes: &["express"],
    },
    Rule {
        id: "fastify",
        name: "Fastify",
        role: Role::Framework,
        language: "javascript",
        ecosystem: Ecosystem::Npm,
        packages: &["fastify"],
        import_prefixes: &["fastify"],
    },
    Rule {
        id: "hono",
        name: "Hono",
        role: Role::Framework,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["hono"],
        import_prefixes: &["hono"],
    },
    Rule {
        id: "nestjs",
        name: "NestJS",
        role: Role::Framework,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["@nestjs/core"],
        import_prefixes: &["@nestjs/"],
    },
    // ---- Authentication ----
    Rule {
        id: "better-auth",
        name: "Better Auth",
        role: Role::Auth,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["better-auth"],
        import_prefixes: &["better-auth"],
    },
    Rule {
        id: "nextauth",
        name: "NextAuth",
        role: Role::Auth,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["next-auth", "@auth/core"],
        import_prefixes: &["next-auth", "@auth/"],
    },
    Rule {
        id: "clerk",
        name: "Clerk",
        role: Role::Auth,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["@clerk/nextjs", "@clerk/clerk-sdk-node"],
        import_prefixes: &["@clerk/"],
    },
    Rule {
        id: "lucia",
        name: "Lucia",
        role: Role::Auth,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["lucia"],
        import_prefixes: &["lucia"],
    },
    Rule {
        id: "passport",
        name: "Passport",
        role: Role::Auth,
        language: "javascript",
        ecosystem: Ecosystem::Npm,
        packages: &["passport"],
        import_prefixes: &["passport"],
    },
    // ---- JavaScript and TypeScript data access ----
    Rule {
        id: "drizzle",
        name: "Drizzle ORM",
        role: Role::Orm,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["drizzle-orm"],
        import_prefixes: &["drizzle-orm"],
    },
    Rule {
        id: "prisma",
        name: "Prisma",
        role: Role::Orm,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["prisma", "@prisma/client"],
        import_prefixes: &["@prisma/"],
    },
    Rule {
        id: "typeorm",
        name: "TypeORM",
        role: Role::Orm,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["typeorm"],
        import_prefixes: &["typeorm"],
    },
    Rule {
        id: "sequelize",
        name: "Sequelize",
        role: Role::Orm,
        language: "javascript",
        ecosystem: Ecosystem::Npm,
        packages: &["sequelize"],
        import_prefixes: &["sequelize"],
    },
    Rule {
        id: "mongoose",
        name: "Mongoose",
        role: Role::Orm,
        language: "javascript",
        ecosystem: Ecosystem::Npm,
        packages: &["mongoose"],
        import_prefixes: &["mongoose"],
    },
    Rule {
        id: "kysely",
        name: "Kysely",
        role: Role::Orm,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["kysely"],
        import_prefixes: &["kysely"],
    },
    // ---- JavaScript and TypeScript libraries worth knowing about ----
    Rule {
        id: "react",
        name: "React",
        role: Role::Library,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["react"],
        import_prefixes: &["react"],
    },
    Rule {
        id: "trpc",
        name: "tRPC",
        role: Role::Library,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["@trpc/server"],
        import_prefixes: &["@trpc/"],
    },
    Rule {
        id: "zod",
        name: "Zod",
        role: Role::Library,
        language: "typescript",
        ecosystem: Ecosystem::Npm,
        packages: &["zod"],
        import_prefixes: &["zod"],
    },
    // ---- Rust frameworks ----
    Rule {
        id: "axum",
        name: "Axum",
        role: Role::Framework,
        language: "rust",
        ecosystem: Ecosystem::Cargo,
        packages: &["axum"],
        import_prefixes: &["axum"],
    },
    Rule {
        id: "actix-web",
        name: "Actix Web",
        role: Role::Framework,
        language: "rust",
        ecosystem: Ecosystem::Cargo,
        packages: &["actix-web"],
        import_prefixes: &["actix_web"],
    },
    Rule {
        id: "rocket",
        name: "Rocket",
        role: Role::Framework,
        language: "rust",
        ecosystem: Ecosystem::Cargo,
        packages: &["rocket"],
        import_prefixes: &["rocket"],
    },
    Rule {
        id: "warp",
        name: "Warp",
        role: Role::Framework,
        language: "rust",
        ecosystem: Ecosystem::Cargo,
        packages: &["warp"],
        import_prefixes: &["warp"],
    },
    Rule {
        id: "poem",
        name: "Poem",
        role: Role::Framework,
        language: "rust",
        ecosystem: Ecosystem::Cargo,
        packages: &["poem"],
        import_prefixes: &["poem"],
    },
    // ---- Rust data access ----
    Rule {
        id: "sqlx",
        name: "SQLx",
        role: Role::Orm,
        language: "rust",
        ecosystem: Ecosystem::Cargo,
        packages: &["sqlx"],
        import_prefixes: &["sqlx"],
    },
    Rule {
        id: "diesel",
        name: "Diesel",
        role: Role::Orm,
        language: "rust",
        ecosystem: Ecosystem::Cargo,
        packages: &["diesel"],
        import_prefixes: &["diesel"],
    },
    Rule {
        id: "sea-orm",
        name: "SeaORM",
        role: Role::Orm,
        language: "rust",
        ecosystem: Ecosystem::Cargo,
        packages: &["sea-orm"],
        import_prefixes: &["sea_orm"],
    },
];

/// Find the rule that owns a package name.
pub fn rule_for_package(package: &str) -> Option<&'static Rule> {
    RULES
        .iter()
        .find(|rule| rule.packages.contains(&package))
}

/// Find the rule an import path belongs to.
///
/// Longest prefix wins, so `next-auth` is not swallowed by `next`.
pub fn rule_for_import(module: &str) -> Option<&'static Rule> {
    let mut best: Option<(&'static Rule, usize)> = None;
    for rule in RULES {
        for prefix in rule.import_prefixes {
            let matches = module == *prefix
                || module.starts_with(&format!("{prefix}/"))
                || module.starts_with(&format!("{prefix}::"));
            if matches && best.is_none_or(|(_, len)| prefix.len() > len) {
                best = Some((rule, prefix.len()));
            }
        }
    }
    best.map(|(rule, _)| rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn package_lookup_finds_the_owning_rule() {
        assert_eq!(rule_for_package("next").unwrap().id, "nextjs");
        assert_eq!(rule_for_package("@prisma/client").unwrap().id, "prisma");
        assert_eq!(rule_for_package("actix-web").unwrap().id, "actix-web");
        assert!(rule_for_package("left-pad").is_none());
    }

    #[test]
    fn import_lookup_prefers_the_longest_prefix() {
        assert_eq!(rule_for_import("next/server").unwrap().id, "nextjs");
        assert_eq!(rule_for_import("next-auth/react").unwrap().id, "nextauth");
        assert_eq!(rule_for_import("better-auth/next-js").unwrap().id, "better-auth");
    }

    #[test]
    fn rust_paths_match_on_double_colon() {
        assert_eq!(rule_for_import("axum::routing").unwrap().id, "axum");
        assert_eq!(rule_for_import("actix_web::web").unwrap().id, "actix-web");
        assert_eq!(rule_for_import("sqlx").unwrap().id, "sqlx");
    }

    #[test]
    fn unrelated_imports_match_nothing() {
        assert!(rule_for_import("./local").is_none());
        assert!(rule_for_import("std::collections").is_none());
        assert!(rule_for_import("nextcloud").is_none(), "prefix must not match mid-word");
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut seen = BTreeSet::new();
        for rule in RULES {
            assert!(seen.insert(rule.id), "duplicate rule id `{}`", rule.id);
        }
    }

    #[test]
    fn every_rule_declares_a_language_the_core_understands() {
        for rule in RULES {
            let language: quoll_core::Language = rule.language.parse().unwrap();
            assert!(
                !matches!(language, quoll_core::Language::Other(_)),
                "rule `{}` names an unknown language `{}`",
                rule.id,
                rule.language
            );
        }
    }

    #[test]
    fn no_package_is_claimed_by_two_rules() {
        let mut seen = BTreeSet::new();
        for rule in RULES {
            for package in rule.packages {
                assert!(
                    seen.insert(*package),
                    "package `{package}` is claimed by more than one rule"
                );
            }
        }
    }

    #[test]
    fn the_mvp_stack_is_covered() {
        for id in [
            "nextjs",
            "better-auth",
            "drizzle",
            "prisma",
            "express",
            "axum",
            "actix-web",
        ] {
            assert!(RULES.iter().any(|r| r.id == id), "missing rule `{id}`");
        }
    }
}
