//! End-to-end scan pipeline.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quoll_ai::{from_config as ai_from_config, Budget, InvestigationCache, Investigator};
use quoll_core::config::Config;
use quoll_core::{
    time_util, AttackHypothesis, Confidence, Error, Finding, Profile, RawFinding, Result, Severity,
};
use quoll_detect::Detector;
use quoll_graph::{Graph, Indexer, Walker};
use quoll_plugin::{
    Availability, Plugin, PluginRun, RunStatus, ScanContext, Selection,
};
use quoll_policy::Registry as PolicyRegistry;
use quoll_report::{Coverage, Format, Report, ScanInfo, Verifier};

use crate::baseline::{apply_baseline, load_baseline};
use crate::correlate::{apply_threshold, investigation_queue, merge_promoted, correlate};
use crate::normalize::{from_policy_violations, normalize};
use crate::store::{save_last_scan, store_from_outcome};
use crate::suppress::apply_suppressions;

/// Options for one scan invocation.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub config: Config,
    pub profile: Profile,
    pub offline: bool,
    pub no_ai: bool,
    pub fail_on: Severity,
    pub formats: Vec<Format>,
    pub target_url: Option<String>,
    /// When set, write SARIF here in addition to configured formats.
    pub sarif_path: Option<PathBuf>,
    /// CI mode: prefer incremental scope when a base ref is known.
    pub ci: bool,
    pub base_ref: Option<String>,
}

impl ScanOptions {
    pub fn from_config(config: &Config) -> ScanOptions {
        let formats = config
            .report
            .formats
            .iter()
            .filter_map(|s| s.parse::<Format>().ok())
            .collect();
        ScanOptions {
            profile: config.scan.profile,
            offline: false,
            no_ai: false,
            fail_on: config.fail_on(),
            formats,
            target_url: None,
            sarif_path: None,
            ci: false,
            base_ref: config.scan.base_ref.clone(),
            config: config.clone(),
        }
    }

    pub fn with_profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self.config.scan.profile = profile;
        self
    }

    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    pub fn with_no_ai(mut self, no_ai: bool) -> Self {
        self.no_ai = no_ai;
        self
    }

    pub fn with_fail_on(mut self, severity: Severity) -> Self {
        self.fail_on = severity;
        self
    }

    pub fn with_formats(mut self, formats: Vec<Format>) -> Self {
        self.formats = formats;
        self
    }

    pub fn with_ci(mut self, ci: bool) -> Self {
        self.ci = ci;
        self
    }

    pub fn with_base_ref(mut self, base_ref: Option<String>) -> Self {
        self.base_ref = base_ref;
        self
    }

    pub fn with_sarif_path(mut self, path: Option<PathBuf>) -> Self {
        self.sarif_path = path;
        self
    }

    pub fn with_target_url(mut self, url: Option<String>) -> Self {
        self.target_url = url;
        self
    }
}

/// Progress labels for callers that print phase banners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Discover,
    Detect,
    Index,
    Plugins,
    Policy,
    Correlate,
    Investigate,
    Report,
}

/// Everything a scan produced.
#[derive(Debug)]
pub struct ScanOutcome {
    pub report: Report,
    pub hypotheses: Vec<AttackHypothesis>,
    pub findings: Vec<Finding>,
    pub stored_path: PathBuf,
    pub written: Vec<PathBuf>,
    pub fail_on: Severity,
    pub scanner_failures: bool,
}

impl ScanOutcome {
    /// Exit-relevant: actionable findings at or above the gate.
    pub fn breaches_gate(&self) -> bool {
        self.report.breaches(self.fail_on)
    }
}

/// Run a full scan.
pub async fn run_scan(options: ScanOptions) -> Result<ScanOutcome> {
    let config = &options.config;
    let root = config.root.clone();
    let scan_id = format!("scan-{}", time_util::now_unix());
    let started = Instant::now();

    // --- discover -----------------------------------------------------------
    let walker = Walker::from_config(config);
    let discovery = walker.discover()?;
    let files = discovery.files.clone();
    let files_scanned = files.len();

    // --- detect -------------------------------------------------------------
    let detection = Detector::new(&root).detect(&files)?;
    let tech_stack = detection.to_tech_stack();

    // --- index --------------------------------------------------------------
    let graph = if config.graph.enabled {
        let mut graph = Graph::open(config.graph_path())?;
        let rebuild = config.graph.rebuild && !options.ci;
        Indexer::new(Walker::from_config(config))
            .rebuild(rebuild)
            .index(&mut graph, &scan_id)?;
        Some(graph)
    } else {
        None
    };

    // --- plugins ------------------------------------------------------------
    let registry = quoll_plugins::registry();
    let work_dir = config.state_dir().join("work").join(&scan_id);
    std::fs::create_dir_all(&work_dir).map_err(|e| Error::io(&work_dir, e))?;

    let base_ctx = ScanContext::new(&root, options.profile)
        .with_files(files.clone())
        .with_tech_stack(tech_stack.clone())
        .with_offline(options.offline)
        .with_work_dir(&work_dir)
        .with_target_url(options.target_url.clone());

    let plan = registry.plan(&config.plugins, &base_ctx);
    let (plugin_runs, raw_findings) = run_plugins(&plan, &config.plugins, &base_ctx).await;
    let scanner_failures = plugin_runs.iter().any(|r| {
        matches!(
            r.status,
            RunStatus::Failed { .. } | RunStatus::TimedOut { .. }
        )
    });

    // --- policy -------------------------------------------------------------
    let mut policy_findings = Vec::new();
    let mut policy_packs = Vec::new();
    let mut policy_nodes = 0usize;
    let mut extra_evidence = Vec::new();
    if let Some(graph) = graph.as_ref() {
        let policy_registry = PolicyRegistry::from_config(config)?;
        let policy_report = policy_registry.evaluate(graph, &detection)?;
        policy_packs = policy_report.packs_applied.clone();
        policy_nodes = policy_report.nodes_evaluated;
        for outcome in &policy_report.outcomes {
            extra_evidence.push(outcome.to_evidence());
        }
        policy_findings = from_policy_violations(policy_report.violations().cloned());
    }

    // --- normalize + correlate ----------------------------------------------
    let mut findings = normalize(raw_findings);
    findings.extend(policy_findings);

    let mut hypotheses = correlate(&findings, &extra_evidence);
    let threshold = if options.no_ai {
        Confidence::CERTAIN
    } else {
        config.investigation_threshold()
    };
    apply_threshold(&mut hypotheses, threshold);

    // --- AI investigation ---------------------------------------------------
    let ai_used = !options.no_ai && config.ai_enabled() && options.profile.allows_ai();
    if ai_used {
        let provider = ai_from_config(&config.ai)?;
        let budget = Budget::from_config(&config.ai);
        let cache_path = config.state_dir().join("investigation-cache.json");
        let cache = InvestigationCache::load(&cache_path)?;
        let mut investigator =
            Investigator::new(ProviderArc(provider), budget).with_cache(cache);
        let queue = investigation_queue(&hypotheses, threshold, config.max_investigations());
        let provider_id = investigator.provider_id().to_string();
        for hyp in queue {
            match investigator.investigate(&hyp).await {
                Ok(verdict) => {
                    if let Some(slot) = hypotheses.iter_mut().find(|h| h.id == hyp.id) {
                        verdict.apply(slot, &provider_id);
                    }
                }
                Err(Error::Budget(msg)) => {
                    tracing::warn!(%msg, "investigation budget exhausted; remaining hypotheses skipped");
                    break;
                }
                Err(err) if err.is_recoverable() => {
                    tracing::warn!(error = %err, id = %hyp.id, "investigation failed; continuing");
                }
                Err(err) => return Err(err),
            }
        }
        let _ = investigator.cache().save();
    }

    let reporting_threshold = options.profile.reporting_threshold();
    let mut final_findings = merge_promoted(
        findings,
        &hypotheses,
        reporting_threshold,
        config.report.include_suppressed,
    );

    apply_suppressions(&mut final_findings, &config.suppress);
    if let Some(baseline_path) = &config.report.baseline {
        let path = config.resolve(baseline_path);
        let baseline = load_baseline(&path)?;
        apply_baseline(&mut final_findings, &baseline);
    }

    if !config.report.include_suppressed {
        // Keep suppressed out of the rendered report unless asked.
        // They remain in stored findings for audit via `findings list --all`.
    }

    let report_findings: Vec<Finding> = if config.report.include_suppressed {
        final_findings.clone()
    } else {
        final_findings
            .iter()
            .filter(|f| f.status != quoll_core::FindingStatus::Suppressed)
            .cloned()
            .collect()
    };

    // --- verify + report ----------------------------------------------------
    let mut verifier = Verifier::new(&root);
    let scan_info = ScanInfo::new(&scan_id, options.profile, &root)
        .with_commit(git_head(&root))
        .completed(files_scanned);

    let report = Report::build(scan_info, report_findings, &mut verifier)
        .with_plugin_runs(plugin_runs)
        .with_coverage(Coverage {
            plugins_run: 0, // filled by with_plugin_runs
            plugins_skipped: 0,
            plugins_degraded: vec![],
            policy_packs_applied: policy_packs,
            policy_nodes_evaluated: policy_nodes,
            ai_used,
        });

    // write formats
    let mut written = Vec::new();
    if !options.formats.is_empty() {
        written.extend(quoll_report::write_all(
            &report,
            config.report_dir(),
            &options.formats,
        )?);
    }
    if let Some(sarif) = &options.sarif_path {
        Format::Sarif.write(&report, sarif)?;
        written.push(sarif.clone());
    } else if options.ci && !options.formats.contains(&Format::Sarif) {
        let path = config.report_dir().join("report.sarif");
        Format::Sarif.write(&report, &path)?;
        written.push(path);
    }

    let stored = store_from_outcome(report.clone(), hypotheses.clone(), final_findings.clone());
    let stored_path = save_last_scan(&config.state_dir(), &stored)?;

    tracing::info!(
        findings = report.findings.len(),
        hypotheses = hypotheses.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "scan complete"
    );

    // silence unused if graph not further used
    let _ = graph;

    Ok(ScanOutcome {
        report,
        hypotheses,
        findings: final_findings,
        stored_path,
        written,
        fail_on: options.fail_on,
        scanner_failures,
    })
}

/// Dyn-provider wrapper so Investigator can hold `Arc<dyn Provider>`.
struct ProviderArc(Arc<dyn quoll_ai::Provider>);

#[async_trait::async_trait]
impl quoll_ai::Provider for ProviderArc {
    fn id(&self) -> &str {
        self.0.id()
    }

    async fn complete(
        &self,
        request: quoll_ai::CompletionRequest,
    ) -> Result<quoll_ai::CompletionResponse> {
        self.0.complete(request).await
    }
}

async fn run_plugins(
    plan: &[(Arc<dyn Plugin>, Selection)],
    plugins_config: &quoll_core::config::PluginsConfig,
    base_ctx: &ScanContext,
) -> (Vec<PluginRun>, Vec<RawFinding>) {
    let mut runs = Vec::new();
    let mut findings = Vec::new();

    for (plugin, selection) in plan {
        let id = plugin.id().to_string();
        match selection {
            Selection::Skipped(reason) => {
                runs.push(PluginRun {
                    plugin_id: id,
                    status: RunStatus::Skipped {
                        reason: reason.describe(),
                    },
                    duration: Duration::from_millis(0),
                    findings_count: 0,
                    diagnostics: vec![],
                    tool_version: None,
                });
                continue;
            }
            Selection::Selected => {}
        }

        let settings = plugins_config
            .settings_for(plugin.id())
            .cloned()
            .unwrap_or_default();
        let ctx = base_ctx.clone().with_settings(settings);

        let availability = plugin.availability().await;
        if !availability.is_ready() {
            let reason = match &availability {
                Availability::Missing { reason, .. } => reason.clone(),
                Availability::Ready { .. } => unreachable!(),
            };
            runs.push(PluginRun {
                plugin_id: id,
                status: RunStatus::Unavailable { reason },
                duration: Duration::from_millis(0),
                findings_count: 0,
                diagnostics: vec![],
                tool_version: None,
            });
            continue;
        }

        let tool_version = match &availability {
            Availability::Ready { tool_version } => tool_version.clone(),
            _ => None,
        };

        let started = Instant::now();
        match plugin.run(&ctx).await {
            Ok(output) => {
                let skipped = output.was_skipped();
                let count = output.findings.len();
                let status = if skipped {
                    let reason = output
                        .diagnostics
                        .iter()
                        .find_map(|d| match d {
                            quoll_plugin::Diagnostic::Skipped(r) => Some(r.clone()),
                            _ => None,
                        })
                        .unwrap_or_else(|| "skipped".into());
                    RunStatus::Skipped { reason }
                } else {
                    RunStatus::Completed
                };
                findings.extend(output.findings);
                runs.push(PluginRun {
                    plugin_id: id,
                    status,
                    duration: started.elapsed(),
                    findings_count: count,
                    diagnostics: output.diagnostics,
                    tool_version: output.tool_version.or(tool_version),
                });
            }
            Err(err) => {
                tracing::warn!(plugin = %id, error = %err, "plugin failed");
                runs.push(PluginRun {
                    plugin_id: id,
                    status: RunStatus::Failed {
                        error: err.to_string(),
                    },
                    duration: started.elapsed(),
                    findings_count: 0,
                    diagnostics: vec![],
                    tool_version,
                });
            }
        }
    }

    (runs, findings)
}

fn git_head(root: &std::path::Path) -> Option<String> {
    let head = root.join(".git/HEAD");
    let text = std::fs::read_to_string(head).ok()?;
    let text = text.trim();
    if let Some(rest) = text.strip_prefix("ref: ") {
        let refer = root.join(".git").join(rest);
        std::fs::read_to_string(refer)
            .ok()
            .map(|s| s.trim().to_string())
    } else if text.len() >= 7 {
        Some(text.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoll_core::config::Config;

    #[tokio::test]
    async fn scan_empty_repo_produces_empty_report() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "# hi\n").unwrap();
        let mut config = Config {
            root: dir.path().to_path_buf(),
            ..Config::default()
        };
        config.graph.enabled = true;
        // Disable all plugins so the test does not need binaries.
        config.plugins.disabled = vec![
            "semgrep".into(),
            "gitleaks".into(),
            "osv-scanner".into(),
            "trivy".into(),
            "cargo-audit".into(),
            "strix".into(),
        ];
        config.ai.enabled = false;
        config.report.formats = vec!["json".into()];

        let outcome = run_scan(ScanOptions::from_config(&config).with_no_ai(true))
            .await
            .unwrap();
        assert!(outcome.report.findings.is_empty());
        assert!(outcome.stored_path.is_file());
        assert!(!outcome.breaches_gate());
    }
}
