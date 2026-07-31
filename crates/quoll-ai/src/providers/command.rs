use async_trait::async_trait;
use quoll_core::config::ProviderConfig;
use quoll_core::{Error, Result};
use tokio::process::Command;

use crate::provider::{CompletionRequest, CompletionResponse, Provider};

/// Shell-out provider: stdin is the user prompt, stdout is the completion.
///
/// Used for local CLIs (`codex`, `claude`, …). Never runs through a shell — the
/// executable and args are an argument vector.
pub struct CommandProvider {
    id: String,
    program: String,
    args: Vec<String>,
    timeout_secs: u64,
}

impl CommandProvider {
    pub fn from_config(id: &str, config: &ProviderConfig) -> Result<CommandProvider> {
        let program = config
            .command
            .clone()
            .ok_or_else(|| Error::config(format!("provider `{id}` is kind=command but has no command")))?;
        Ok(CommandProvider {
            id: id.to_string(),
            program,
            args: config.args.clone(),
            timeout_secs: config.timeout_secs.unwrap_or(120),
        })
    }
}

#[async_trait]
impl Provider for CommandProvider {
    fn id(&self) -> &str {
        &self.id
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        command.stdin(std::process::Stdio::piped());
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());

        let mut child = command.spawn().map_err(|e| Error::Ai {
            provider: self.id.clone(),
            message: format!("failed to spawn `{}`: {e}", self.program),
        })?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let body = format!("{}\n\n{}", request.system, request.user);
            stdin.write_all(body.as_bytes()).await.map_err(|e| Error::Ai {
                provider: self.id.clone(),
                message: format!("failed to write prompt: {e}"),
            })?;
        }

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| Error::Timeout {
            what: format!("ai provider `{}`", self.id),
            seconds: self.timeout_secs,
        })?
        .map_err(|e| Error::Ai {
            provider: self.id.clone(),
            message: e.to_string(),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Ai {
                provider: self.id.clone(),
                message: format!("command exited {}: {stderr}", output.status),
            });
        }

        let text = String::from_utf8_lossy(&output.stdout).to_string();
        let tokens = (text.len() as u64 / 4).max(1);
        Ok(CompletionResponse {
            text,
            model: self.program.clone(),
            input_tokens: request.estimated_tokens / 2,
            output_tokens: tokens,
        })
    }
}
