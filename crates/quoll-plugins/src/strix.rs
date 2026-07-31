//! Strix: optional dynamic validation against a running application.
//!
//! Every other adapter reads files. This one sends traffic at a live service, which makes
//! it the only plugin capable of causing harm outside the scan. Most of this module is
//! therefore the gate rather than the tool: a target must be explicitly allowlisted, must
//! not look like production, and dynamic validation must be switched on deliberately.
//!
//! The refusal is the feature. Quoll would rather run no dynamic validation than run it
//! against the wrong host once.

use std::fmt;
use std::path::Path;

use quoll_core::{Confidence, Location, RawFinding, Result, Severity};
use quoll_plugin::{
    async_trait, BinaryRequirement, Capability, CostTier, Plugin, PluginManifest, PluginOutput,
    ScanContext,
};
use serde::{Deserialize, Serialize};

use crate::common;

/// Hostnames that are never production, whatever the allowlist says.
const LOOPBACK_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"];

/// Suffixes reserved by RFC 6761 and RFC 2606 for local and test use.
const LOCAL_SUFFIXES: &[&str] = &[".localhost", ".local", ".test", ".invalid", ".example"];

/// Substrings that mark a hostname as a non-production environment.
const NON_PRODUCTION_MARKERS: &[&str] = &[
    "staging", "stage.", "-stage", "dev.", "-dev", "develop", "test.", "-test", "qa.", "-qa",
    "sandbox", "preview", "uat", "ephemeral", "preprod", "pre-prod",
];

/// Why a dynamic validation run was refused.
///
/// Each variant is a distinct safety rule. They are kept separate rather than collapsed
/// into one string so the orchestrator can map a refusal to the dedicated exit code and a
/// user can tell "I forgot the flag" from "I nearly scanned production".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// No target URL was supplied.
    NoTarget,
    /// The profile does not permit dynamic validation.
    ProfileDisallows { profile: String },
    /// The URL could not be understood.
    Unparseable { url: String },
    /// The scheme is not HTTP or HTTPS.
    UnsupportedScheme { scheme: String },
    /// No allowlist was configured, so nothing is permitted.
    NoAllowlist,
    /// The host is not on the allowlist.
    NotAllowlisted { host: String },
    /// The host looks like production.
    LooksLikeProduction { host: String },
}

impl Refusal {
    pub fn describe(&self) -> String {
        match self {
            Refusal::NoTarget => {
                "no target URL was supplied; dynamic validation needs --target-url".into()
            }
            Refusal::ProfileDisallows { profile } => format!(
                "the `{profile}` profile does not permit dynamic validation; use `release`"
            ),
            Refusal::Unparseable { url } => format!("`{url}` is not a URL Quoll can parse"),
            Refusal::UnsupportedScheme { scheme } => {
                format!("`{scheme}` is not a supported scheme; use http or https")
            }
            Refusal::NoAllowlist => {
                "no hostnames are allowlisted for dynamic validation, so every target is refused"
                    .into()
            }
            Refusal::NotAllowlisted { host } => {
                format!("`{host}` is not on the dynamic validation allowlist")
            }
            Refusal::LooksLikeProduction { host } => format!(
                "`{host}` looks like a production host; Quoll will not send attack traffic at it"
            ),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// A target that has passed every safety check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTarget {
    pub url: String,
    pub host: String,
}

/// Hostnames dynamic validation may touch.
///
/// Empty by default, and an empty allowlist refuses everything. Defaulting to "anything
/// that does not look like production" would make the safety of a scan depend on a
/// hostname-naming convention, and plenty of production hosts are called `api`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetPolicy {
    pub allowed_hosts: Vec<String>,
}

impl TargetPolicy {
    pub fn new(hosts: impl IntoIterator<Item = String>) -> TargetPolicy {
        TargetPolicy {
            allowed_hosts: hosts.into_iter().collect(),
        }
    }

    /// Read the allowlist from plugin configuration.
    ///
    /// `[plugins.strix] config = ["staging.example.com", "localhost"]` — the `config` field
    /// is plugin-interpreted, and for a dynamic validator the thing worth configuring is
    /// which hosts it may touch.
    pub fn from_settings(ctx: &ScanContext) -> TargetPolicy {
        TargetPolicy::new(
            ctx.settings()
                .config
                .iter()
                .map(|host| host.trim().to_ascii_lowercase()),
        )
    }

    fn permits(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|allowed| {
            let allowed = allowed.trim().to_ascii_lowercase();
            // A leading dot allows the domain and its subdomains, and nothing else. Bare
            // wildcards are not accepted: `*` in an allowlist is an allowlist in name only.
            match allowed.strip_prefix('.') {
                Some(domain) => host == domain || host.ends_with(&format!(".{domain}")),
                None => host == allowed,
            }
        })
    }
}

/// Decide whether a target may be validated.
///
/// Both gates must pass: the host is on the allowlist *and* it does not look like
/// production. Either alone is insufficient — an allowlist entry can be a typo away from a
/// live host, and a naming convention is not a permission.
pub fn check_target(
    url: Option<&str>,
    policy: &TargetPolicy,
) -> std::result::Result<ValidatedTarget, Refusal> {
    let url = url.map(str::trim).filter(|u| !u.is_empty());
    let url = match url {
        Some(url) => url,
        None => return Err(Refusal::NoTarget),
    };

    let (scheme, rest) = match url.split_once("://") {
        Some(parts) => parts,
        None => {
            return Err(Refusal::Unparseable {
                url: url.to_string(),
            })
        }
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(Refusal::UnsupportedScheme { scheme });
    }

    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    // Credentials in the authority are dropped before the host is read, so
    // `https://staging.example.com@evil.test/` cannot masquerade as an allowlisted host.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = strip_port(authority).to_ascii_lowercase();

    if host.is_empty() {
        return Err(Refusal::Unparseable {
            url: url.to_string(),
        });
    }
    if policy.allowed_hosts.is_empty() {
        return Err(Refusal::NoAllowlist);
    }
    if !policy.permits(&host) {
        return Err(Refusal::NotAllowlisted { host });
    }
    if looks_like_production(&host) {
        return Err(Refusal::LooksLikeProduction { host });
    }

    Ok(ValidatedTarget {
        url: url.to_string(),
        host,
    })
}

/// Remove a port, handling bracketed IPv6 authorities.
fn strip_port(authority: &str) -> &str {
    if let Some(end) = authority.find(']') {
        return &authority[..=end];
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// Whether a hostname should be treated as production.
///
/// Deliberately pessimistic: anything not recognisably local or non-production is treated
/// as production. The cost of a false positive is a refused scan; the cost of a false
/// negative is attack traffic against a live service.
pub fn looks_like_production(host: &str) -> bool {
    if LOOPBACK_HOSTS.contains(&host) {
        return false;
    }
    if LOCAL_SUFFIXES.iter().any(|suffix| host.ends_with(suffix)) {
        return false;
    }
    if is_private_address(host) {
        return false;
    }
    !NON_PRODUCTION_MARKERS
        .iter()
        .any(|marker| host.contains(marker))
}

/// Whether the host is a literal address in a private range.
fn is_private_address(host: &str) -> bool {
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() != 4 || !octets.iter().all(|o| o.chars().all(|c| c.is_ascii_digit())) {
        // Unique local IPv6.
        return host.starts_with("fd") || host.starts_with("[fd");
    }
    let numbers: Vec<u16> = octets.iter().filter_map(|o| o.parse().ok()).collect();
    if numbers.len() != 4 {
        return false;
    }
    match (numbers[0], numbers[1]) {
        (10, _) => true,
        (192, 168) => true,
        (172, second) if (16..=31).contains(&second) => true,
        (127, _) => true,
        _ => false,
    }
}

/// The bounded brief handed to a dynamic validator.
///
/// Scope is stated explicitly rather than inferred. A validator that has to guess what it
/// may touch will eventually guess wrong.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationRequest {
    pub target_url: String,
    /// Hostnames the validator may contact. Everything else is out of scope.
    pub allowed_hosts: Vec<String>,
    /// The attack being tested, in one sentence.
    pub hypothesis: String,
    /// Endpoints worth probing, from the code graph.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Actions the validator is permitted to take.
    pub permitted_actions: Vec<String>,
    /// Actions it must not take, whatever it concludes.
    pub denied_actions: Vec<String>,
    pub timeout_seconds: u64,
}

impl ValidationRequest {
    /// Actions no validation run may take, whatever the hypothesis.
    ///
    /// A validator exists to demonstrate reachability, not to prove impact by causing it.
    pub const ALWAYS_DENIED: &'static [&'static str] = &[
        "delete-data",
        "modify-data",
        "exfiltrate-data",
        "denial-of-service",
        "brute-force",
        "lateral-movement",
        "persistence",
    ];

    pub fn new(
        target: &ValidatedTarget,
        policy: &TargetPolicy,
        hypothesis: impl Into<String>,
        timeout_seconds: u64,
    ) -> ValidationRequest {
        ValidationRequest {
            target_url: target.url.clone(),
            allowed_hosts: policy.allowed_hosts.clone(),
            hypothesis: hypothesis.into(),
            endpoints: Vec::new(),
            permitted_actions: vec![
                "http-request".into(),
                "authentication-bypass-probe".into(),
                "authorisation-probe".into(),
            ],
            denied_actions: Self::ALWAYS_DENIED.iter().map(|s| s.to_string()).collect(),
            timeout_seconds,
        }
    }

    pub fn with_endpoints(mut self, endpoints: Vec<String>) -> ValidationRequest {
        self.endpoints = endpoints;
        self
    }
}

/// Strix, wired as an optional dynamic validator.
pub struct Strix {
    manifest: PluginManifest,
}

impl Default for Strix {
    fn default() -> Self {
        Strix::new()
    }
}

impl Strix {
    pub fn new() -> Strix {
        Strix {
            manifest: PluginManifest::builder("strix", "Strix")
                .description("Exercises a running application to prove a hypothesis is reachable")
                .capability(Capability::DynamicValidation)
                // Minutes to hours, and it sends traffic. Never in a fast profile.
                .cost(CostTier::Expensive)
                .license("Apache-2.0")
                .homepage("https://github.com/usestrix/strix")
                // A reproduced request is strong evidence, but a validator that fails to
                // reproduce has not proved absence.
                .confidence(Confidence::new(0.9))
                .requires_network()
                .requires(
                    BinaryRequirement::new("strix").install_hint("pip install strix-agent"),
                )
                .build(),
        }
    }
}

#[async_trait]
impl Plugin for Strix {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// Only ever relevant when a target was supplied and the profile permits it. The
    /// registry also gates on `requires_running_target`; this is the second lock.
    fn applies_to(&self, ctx: &ScanContext) -> bool {
        ctx.target_url().is_some() && ctx.profile().allows_dynamic_validation()
    }

    async fn run(&self, ctx: &ScanContext) -> Result<PluginOutput> {
        if !ctx.profile().allows_dynamic_validation() {
            return Ok(PluginOutput::skipped(
                Refusal::ProfileDisallows {
                    profile: ctx.profile().as_str().to_string(),
                }
                .describe(),
            ));
        }

        let policy = TargetPolicy::from_settings(ctx);
        let target = match check_target(ctx.target_url(), &policy) {
            Ok(target) => target,
            // A refusal is a skip, not an error: the scan continues and reports that
            // dynamic validation did not run, and why.
            Err(refusal) => return Ok(PluginOutput::skipped(refusal.describe())),
        };

        let request = ValidationRequest::new(
            &target,
            &policy,
            "Confirm whether the reported entry point is reachable without authentication",
            ctx.timeout().as_secs(),
        );
        let brief_path = ctx.ensure_work_dir()?.join("strix-request.json");
        std::fs::write(
            &brief_path,
            serde_json::to_string_pretty(&request).unwrap_or_default(),
        )
        .map_err(|e| quoll_core::Error::io(brief_path.clone(), e))?;

        let exec = common::command(ctx, "strix")
            .arg("--target")
            .arg(&target.url)
            .arg("--brief")
            .path_arg(&brief_path)
            .arg("--format")
            .arg("json");

        let output = common::with_extra_args(exec, ctx).run_lenient().await?;
        let _ = std::fs::remove_file(&brief_path);

        Ok(PluginOutput::default()
            .with_findings(parse(ctx.root(), &output.stdout)?)
            .note(format!("dynamic validation ran against {}", target.host)))
    }
}

#[derive(Debug, Deserialize)]
struct Report {
    #[serde(default)]
    findings: Vec<Confirmed>,
}

#[derive(Debug, Deserialize)]
struct Confirmed {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    reproduced: bool,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
}

/// Convert a Strix report into findings.
///
/// Only reproduced results become findings. A validator that tried and failed has produced
/// an absence of evidence, and reporting that as a finding would invert the meaning of the
/// whole exercise.
pub fn parse(_root: &Path, json: &str) -> Result<Vec<RawFinding>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let report: Report = common::parse_json("strix", json)?;

    Ok(report
        .findings
        .into_iter()
        .filter(|confirmed| confirmed.reproduced)
        .map(|confirmed| {
            let endpoint = confirmed.endpoint.clone().unwrap_or_default();
            let mut finding = RawFinding::new(
                "strix",
                if confirmed.id.is_empty() {
                    "strix/reproduced"
                } else {
                    &confirmed.id
                },
                if confirmed.title.is_empty() {
                    "Dynamic validation reproduced the issue".to_string()
                } else {
                    confirmed.title.clone()
                },
                common::severity(&confirmed.severity, Severity::High),
                // A dynamic finding has no source line of its own. Correlation attributes
                // it to code through the graph; inventing a line here would be a guess.
                Location::file(std::path::PathBuf::from(if endpoint.is_empty() {
                    "<dynamic>".to_string()
                } else {
                    endpoint.clone()
                })),
            )
            .with_description(confirmed.description)
            .with_confidence(Confidence::new(0.9));

            finding.metadata.insert("reproduced".into(), true.into());
            if !endpoint.is_empty() {
                finding.metadata.insert("endpoint".into(), endpoint.into());
            }
            if let Some(evidence) = confirmed.evidence {
                finding.metadata.insert("evidence".into(), evidence.into());
            }
            finding
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::Profile;

    fn policy(hosts: &[&str]) -> TargetPolicy {
        TargetPolicy::new(hosts.iter().map(|h| h.to_string()))
    }

    #[test]
    fn no_target_is_refused() {
        assert_eq!(
            check_target(None, &policy(&["localhost"])).unwrap_err(),
            Refusal::NoTarget
        );
        assert_eq!(
            check_target(Some("  "), &policy(&["localhost"])).unwrap_err(),
            Refusal::NoTarget
        );
    }

    #[test]
    fn an_empty_allowlist_refuses_everything_including_localhost() {
        let err = check_target(Some("http://localhost:3000"), &TargetPolicy::default()).unwrap_err();
        assert_eq!(err, Refusal::NoAllowlist);
    }

    #[test]
    fn an_allowlisted_local_target_is_accepted() {
        let target = check_target(Some("http://localhost:3000/api"), &policy(&["localhost"])).unwrap();
        assert_eq!(target.host, "localhost");
    }

    #[test]
    fn a_host_not_on_the_allowlist_is_refused() {
        let err = check_target(Some("https://staging.example.com"), &policy(&["localhost"]))
            .unwrap_err();
        assert_eq!(
            err,
            Refusal::NotAllowlisted {
                host: "staging.example.com".into()
            }
        );
    }

    #[test]
    fn an_allowlisted_production_host_is_still_refused() {
        // Both gates must pass. An allowlist entry is not permission to attack production.
        let err = check_target(Some("https://api.example.com"), &policy(&["api.example.com"]))
            .unwrap_err();
        assert_eq!(
            err,
            Refusal::LooksLikeProduction {
                host: "api.example.com".into()
            }
        );
    }

    #[test]
    fn staging_hosts_are_recognised_as_non_production() {
        for host in [
            "staging.example.com",
            "app-staging.example.com",
            "dev.example.com",
            "qa.example.com",
            "preview-123.example.com",
            "uat.example.com",
        ] {
            assert!(!looks_like_production(host), "`{host}` should be non-production");
        }
    }

    #[test]
    fn ordinary_hosts_are_treated_as_production() {
        for host in [
            "example.com",
            "api.example.com",
            "www.acme.io",
            "checkout.bank.com",
        ] {
            assert!(looks_like_production(host), "`{host}` should be production");
        }
    }

    #[test]
    fn loopback_and_reserved_suffixes_are_never_production() {
        for host in ["localhost", "127.0.0.1", "::1", "app.localhost", "api.test", "svc.local"] {
            assert!(!looks_like_production(host), "`{host}`");
        }
    }

    #[test]
    fn private_ranges_are_never_production() {
        for host in ["10.0.0.5", "192.168.1.10", "172.16.4.2", "172.31.255.1"] {
            assert!(!looks_like_production(host), "`{host}`");
        }
        assert!(looks_like_production("172.32.0.1"), "outside the private range");
        assert!(looks_like_production("8.8.8.8"));
    }

    #[test]
    fn credentials_cannot_disguise_the_real_host() {
        // The host is `evil.example.com`, not the allowlisted prefix before the `@`.
        let err = check_target(
            Some("https://staging.example.com@evil.example.com/"),
            &policy(&["staging.example.com"]),
        )
        .unwrap_err();
        assert_eq!(
            err,
            Refusal::NotAllowlisted {
                host: "evil.example.com".into()
            }
        );
    }

    #[test]
    fn a_subdomain_does_not_match_a_bare_allowlist_entry() {
        let err = check_target(
            Some("https://evil.staging.example.com"),
            &policy(&["staging.example.com"]),
        )
        .unwrap_err();
        assert!(matches!(err, Refusal::NotAllowlisted { .. }));
    }

    #[test]
    fn a_leading_dot_allows_the_domain_and_its_subdomains() {
        let policy = policy(&[".staging.example.com"]);
        assert!(check_target(Some("https://staging.example.com"), &policy).is_ok());
        assert!(check_target(Some("https://a.staging.example.com"), &policy).is_ok());
        assert!(check_target(Some("https://notstaging.example.com"), &policy).is_err());
    }

    #[test]
    fn a_literal_wildcard_is_not_a_wildcard() {
        let err = check_target(Some("http://localhost"), &policy(&["*"])).unwrap_err();
        assert!(matches!(err, Refusal::NotAllowlisted { .. }));
    }

    #[test]
    fn non_http_schemes_are_refused() {
        for url in ["file:///etc/passwd", "ssh://staging.example.com", "gopher://x"] {
            let err = check_target(Some(url), &policy(&["staging.example.com"])).unwrap_err();
            assert!(matches!(err, Refusal::UnsupportedScheme { .. }), "{url}: {err:?}");
        }
    }

    #[test]
    fn a_url_with_no_scheme_is_refused_rather_than_assumed() {
        let err = check_target(Some("staging.example.com"), &policy(&["staging.example.com"]))
            .unwrap_err();
        assert!(matches!(err, Refusal::Unparseable { .. }));
    }

    #[test]
    fn ports_are_stripped_before_the_host_is_matched() {
        assert!(check_target(Some("http://localhost:8080/x"), &policy(&["localhost"])).is_ok());
        assert!(check_target(Some("http://[::1]:8080/"), &policy(&["[::1]"])).is_ok());
    }

    #[test]
    fn only_the_release_profile_permits_dynamic_validation() {
        let strix = Strix::new();
        for profile in Profile::ALL {
            let ctx = ScanContext::new("/repo", profile)
                .with_target_url(Some("http://localhost:3000".into()));
            assert_eq!(
                strix.applies_to(&ctx),
                profile == Profile::Release,
                "{profile}"
            );
        }
    }

    #[test]
    fn without_a_target_url_strix_never_applies() {
        let ctx = ScanContext::new("/repo", Profile::Release);
        assert!(!Strix::new().applies_to(&ctx));
    }

    #[tokio::test]
    async fn a_refused_target_skips_rather_than_failing_the_scan() {
        let ctx = ScanContext::new("/repo", Profile::Release)
            .with_target_url(Some("https://api.example.com".into()));
        let output = Strix::new().run(&ctx).await.unwrap();

        assert!(output.was_skipped());
        assert!(output.findings.is_empty());
    }

    #[tokio::test]
    async fn strix_never_runs_in_a_fast_profile_even_with_a_local_target() {
        let ctx = ScanContext::new("/repo", Profile::Fast)
            .with_target_url(Some("http://localhost:3000".into()));
        let output = Strix::new().run(&ctx).await.unwrap();
        assert!(output.was_skipped());
    }

    #[test]
    fn the_allowlist_is_read_from_plugin_configuration() {
        let settings = quoll_core::config::PluginSettings {
            config: vec!["Staging.Example.com".into(), "localhost".into()],
            ..Default::default()
        };
        let ctx = ScanContext::new("/repo", Profile::Release).with_settings(settings);
        let policy = TargetPolicy::from_settings(&ctx);

        assert_eq!(policy.allowed_hosts.len(), 2);
        assert!(check_target(Some("https://staging.example.com"), &policy).is_ok());
    }

    #[test]
    fn destructive_actions_are_denied_in_every_request() {
        let target = ValidatedTarget {
            url: "http://localhost:3000".into(),
            host: "localhost".into(),
        };
        let request = ValidationRequest::new(&target, &policy(&["localhost"]), "test", 60);

        for denied in ValidationRequest::ALWAYS_DENIED {
            assert!(
                request.denied_actions.contains(&denied.to_string()),
                "`{denied}` must be denied"
            );
        }
        assert!(!request.permitted_actions.iter().any(|a| a.contains("delete")));
    }

    #[test]
    fn only_reproduced_results_become_findings() {
        let json = r#"{
          "findings": [
            {"id":"a","title":"Auth bypass","severity":"critical","reproduced":true,"endpoint":"/api/users"},
            {"id":"b","title":"Maybe","severity":"high","reproduced":false}
          ]
        }"#;
        let findings = parse(Path::new("/repo"), json).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].metadata.get("endpoint").unwrap(), "/api/users");
    }

    #[test]
    fn an_empty_report_is_not_an_error() {
        assert!(parse(Path::new("/repo"), r#"{"findings":[]}"#).unwrap().is_empty());
        assert!(parse(Path::new("/repo"), "").unwrap().is_empty());
    }

    #[test]
    fn refusals_explain_themselves() {
        assert!(Refusal::NoAllowlist.describe().contains("allowlisted"));
        assert!(Refusal::LooksLikeProduction { host: "x".into() }
            .describe()
            .contains("production"));
    }
}
