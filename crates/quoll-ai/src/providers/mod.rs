//! Built-in model backends.

mod command;
mod http;
mod mock;
mod null;

use std::sync::Arc;

use quoll_core::config::{AiConfig, ProviderConfig};
use quoll_core::{Error, Result};

pub use command::CommandProvider;
pub use http::HttpProvider;
pub use mock::MockProvider;
pub use null::NullProvider;

use crate::Provider;

/// Build the configured provider, or a null provider when AI is off.
pub fn from_config(config: &AiConfig) -> Result<Arc<dyn Provider>> {
    if !config.enabled {
        return Ok(Arc::new(NullProvider));
    }
    let provider_id = config
        .provider
        .as_deref()
        .ok_or(Error::NoAiProvider)?;
    let provider_config = config
        .providers
        .get(provider_id)
        .ok_or_else(|| {
            Error::config(format!(
                "ai.provider `{provider_id}` is set but has no [ai.providers.{provider_id}] table"
            ))
        })?;
    build(provider_id, provider_config, config)
}

fn build(
    id: &str,
    config: &ProviderConfig,
    ai: &AiConfig,
) -> Result<Arc<dyn Provider>> {
    match config.kind.as_str() {
        "mock" => Ok(Arc::new(MockProvider::confirming())),
        "null" | "none" => Ok(Arc::new(NullProvider)),
        "command" => Ok(Arc::new(CommandProvider::from_config(id, config)?)),
        "openai" | "openai-compatible" | "anthropic" | "ollama" => {
            Ok(Arc::new(HttpProvider::from_config(id, config, ai)?))
        }
        other => Err(Error::config(format!(
            "unknown ai provider kind `{other}` (expected openai, anthropic, ollama, command, mock)"
        ))),
    }
}
