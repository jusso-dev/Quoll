use quoll_ai::{from_config, Budget, InvestigationCache, Investigator, Provider};
use quoll_core::{Error, Result};
use quoll_engine::{load_last_scan, save_last_scan};

use crate::cli::InvestigateArgs;
use crate::commands::Context;
use crate::exit::Exit;

pub async fn run(context: &Context, args: &InvestigateArgs) -> Result<Exit> {
    let printer = &context.printer;
    let config = context.config()?;
    let mut stored = load_last_scan(&config.state_dir())?;

    let targets: Vec<_> = match &args.id {
        Some(id) => {
            let hyp = stored
                .hypothesis(id)
                .cloned()
                .ok_or_else(|| Error::other(format!("no hypothesis `{id}`")))?;
            vec![hyp]
        }
        None => stored
            .hypotheses
            .iter()
            .filter(|h| h.warrants_investigation(config.investigation_threshold()))
            .take(config.max_investigations())
            .cloned()
            .collect(),
    };

    if targets.is_empty() {
        printer.warn("no hypotheses warrant investigation");
        return Ok(Exit::Ok);
    }

    if args.dry_run {
        let provider: std::sync::Arc<dyn Provider> = from_config(&config.ai)
            .unwrap_or_else(|_| std::sync::Arc::new(quoll_ai::NullProvider));
        let investigator =
            Investigator::new(DynProvider(provider), Budget::from_config(&config.ai));
        for hyp in &targets {
            let (system, user) = investigator.dry_run_prompt(hyp);
            printer.heading(&hyp.id);
            printer.line("System:");
            printer.line(system);
            printer.line("User:");
            printer.line(user);
        }
        return Ok(Exit::Ok);
    }

    if !config.ai_enabled() {
        return Err(Error::NoAiProvider);
    }

    let provider = from_config(&config.ai)?;
    let cache = InvestigationCache::load(config.state_dir().join("investigation-cache.json"))?;
    let mut investigator =
        Investigator::new(DynProvider(provider), Budget::from_config(&config.ai)).with_cache(cache);
    let provider_id = investigator.provider_id().to_string();

    for hyp in targets {
        printer.line(format!("Investigating {} …", hyp.id));
        match investigator.investigate(&hyp).await {
            Ok(verdict) => {
                if let Some(slot) = stored.hypotheses.iter_mut().find(|h| h.id == hyp.id) {
                    verdict.clone().apply(slot, &provider_id);
                    printer.success(format!(
                        "{} → {:?}",
                        hyp.id,
                        verdict.kind
                    ));
                    printer.line(format!("  {}", verdict.rationale));
                }
            }
            Err(Error::Budget(msg)) => {
                printer.warn(msg);
                return Ok(Exit::BudgetExceeded);
            }
            Err(err) => return Err(err),
        }
    }
    let _ = investigator.cache().save();
    save_last_scan(&config.state_dir(), &stored)?;
    Ok(Exit::Ok)
}

struct DynProvider(std::sync::Arc<dyn Provider>);

#[async_trait::async_trait]
impl Provider for DynProvider {
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
