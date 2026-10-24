//! OpenAI-compatible chat completions (also Ollama and many gateways).

use async_trait::async_trait;
use quoll_core::config::{AiConfig, ProviderConfig};
use quoll_core::{Error, Result};
use serde_json::json;

use crate::provider::{CompletionRequest, CompletionResponse, Provider, Role};

pub struct HttpProvider {
    id: String,
    base_url: String,
    api_key: Option<String>,
    investigate_model: String,
    report_model: String,
    timeout_secs: u64,
}

impl HttpProvider {
    pub fn from_config(id: &str, config: &ProviderConfig, ai: &AiConfig) -> Result<HttpProvider> {
        let base_url = config
            .base_url
            .clone()
            .unwrap_or_else(|| default_base(&config.kind).to_string())
            .trim_end_matches('/')
            .to_string();
        check_base_url(id, &base_url)?;

        let api_key = match &config.api_key_env {
            Some(env_name) => match std::env::var(env_name) {
                Ok(value) if !value.is_empty() => Some(value),
                _ => {
                    return Err(Error::Ai {
                        provider: id.to_string(),
                        message: format!("environment variable `{env_name}` is not set"),
                    })
                }
            },
            None if config.kind == "ollama" => None,
            None => {
                return Err(Error::config(format!(
                    "provider `{id}` needs api_key_env (or kind=ollama)"
                )))
            }
        };

        let investigate_model = ai
            .models
            .investigate
            .clone()
            .or_else(|| config.extra.get("model").cloned())
            .unwrap_or_else(|| default_model(&config.kind).to_string());
        let report_model = ai
            .models
            .report
            .clone()
            .unwrap_or_else(|| investigate_model.clone());

        Ok(HttpProvider {
            id: id.to_string(),
            base_url,
            api_key,
            investigate_model,
            report_model,
            timeout_secs: config.timeout_secs.unwrap_or(120),
        })
    }
}

#[async_trait]
impl Provider for HttpProvider {
    fn id(&self) -> &str {
        &self.id
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let model = request.model.clone().unwrap_or_else(|| match request.role {
            Role::Investigate => self.investigate_model.clone(),
            Role::Report => self.report_model.clone(),
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .map_err(|e| Error::Ai {
                provider: self.id.clone(),
                message: e.to_string(),
            })?;

        let url = format!("{}/chat/completions", self.base_url);
        let mut builder = client.post(&url).json(&json!({
            "model": model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            "temperature": 0.0,
        }));
        if let Some(key) = &self.api_key {
            builder = builder.bearer_auth(key);
        }

        let response = builder.send().await.map_err(|e| Error::Ai {
            provider: self.id.clone(),
            message: e.to_string(),
        })?;

        let status = response.status();
        let body = response.text().await.map_err(|e| Error::Ai {
            provider: self.id.clone(),
            message: e.to_string(),
        })?;
        if !status.is_success() {
            return Err(Error::Ai {
                provider: self.id.clone(),
                message: format!("HTTP {status}: {}", truncate(&body, ERROR_BODY_LIMIT)),
            });
        }

        let value: serde_json::Value = serde_json::from_str(&body).map_err(|e| Error::Ai {
            provider: self.id.clone(),
            message: format!("invalid JSON: {e}"),
        })?;

        let text = value
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let input_tokens = value
            .pointer("/usage/prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(request.estimated_tokens / 2);
        let output_tokens = value
            .pointer("/usage/completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or((text.len() as u64 / 4).max(1));

        Ok(CompletionResponse {
            text,
            model,
            input_tokens,
            output_tokens,
        })
    }
}

/// Most of an error response carried into an error message. Gateways answer failures with
/// whole HTML pages, and some echo the request — prompt and source code included.
const ERROR_BODY_LIMIT: usize = 2048;

fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes truncated)", &text[..end], text.len() - end)
}

/// Refuse to send prompts — which carry source code — and the API key over plain HTTP,
/// except to this machine, where a local model server (Ollama) has no TLS to offer.
fn check_base_url(id: &str, base_url: &str) -> Result<()> {
    let url = reqwest::Url::parse(base_url).map_err(|e| {
        Error::config(format!("provider `{id}` has an invalid base_url `{base_url}`: {e}"))
    })?;
    let loopback = url.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        scheme => Err(Error::config(format!(
            "provider `{id}` base_url must use https (got `{scheme}://`); plain http is only \
             allowed to localhost"
        ))),
    }
}

fn default_base(kind: &str) -> &'static str {
    match kind {
        "anthropic" => "https://api.anthropic.com/v1",
        "ollama" => "http://127.0.0.1:11434/v1",
        _ => "https://api.openai.com/v1",
    }
}

fn default_model(kind: &str) -> &'static str {
    match kind {
        "ollama" => "llama3.2",
        "anthropic" => "claude-sonnet-4-20250514",
        _ => "gpt-4.1-mini",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_refused_except_to_loopback() {
        assert!(check_base_url("p", "https://api.example.com/v1").is_ok());
        assert!(check_base_url("p", "http://127.0.0.1:11434/v1").is_ok());
        assert!(check_base_url("p", "http://localhost:8080").is_ok());
        assert!(check_base_url("p", "http://[::1]:8080/v1").is_ok());
        assert!(check_base_url("p", "http://gateway.internal/v1").is_err());
        assert!(check_base_url("p", "http://127.0.0.1.evil.com/v1").is_err());
        assert!(check_base_url("p", "ftp://localhost/v1").is_err());
        assert!(check_base_url("p", "not a url").is_err());
    }

    #[test]
    fn the_default_bases_pass_the_check() {
        for kind in ["openai", "anthropic", "ollama"] {
            assert!(check_base_url(kind, default_base(kind)).is_ok(), "{kind}");
        }
    }

    #[test]
    fn error_bodies_are_bounded() {
        let body = "é".repeat(5000);
        let short = truncate(&body, ERROR_BODY_LIMIT);
        assert!(short.len() < ERROR_BODY_LIMIT + 64, "{}", short.len());
        assert!(short.ends_with("bytes truncated)"));
        assert_eq!(truncate("short", ERROR_BODY_LIMIT), "short");
    }
}
