//! Subprocess execution for plugins that wrap external tools.
//!
//! Every scanner Quoll orchestrates is a separate binary, so this module is the single
//! choke point where process spawning, timeouts and output capture are handled
//! consistently. Plugins never call `std::process` directly.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use quoll_core::{Error, Result};
use tokio::process::Command;

/// Captured result of running an external tool.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    /// The shortest useful description of a failure, for diagnostics.
    ///
    /// Scanners are verbose on stderr; dumping all of it into a report is noise. The
    /// last non-empty line is almost always the actual error.
    pub fn error_summary(&self) -> String {
        self.stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .map(str::trim)
            .map(str::to_string)
            .unwrap_or_else(|| match self.status {
                Some(code) => format!("exited with status {code}"),
                None => "terminated by signal".to_string(),
            })
    }
}

/// A configured invocation of an external tool.
pub struct Exec {
    program: PathBuf,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: BTreeMap<String, String>,
    timeout: Duration,
    /// Exit codes that mean "ran fine, found things" rather than "failed".
    ///
    /// Most scanners exit non-zero when they report findings, so treating any non-zero
    /// exit as an error would discard every useful result.
    success_codes: Vec<i32>,
}

impl Exec {
    pub fn new(program: impl Into<PathBuf>) -> Exec {
        Exec {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            timeout: Duration::from_secs(300),
            success_codes: vec![0],
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Append a path argument, lossily converting non-UTF-8 paths.
    pub fn path_arg(mut self, path: impl AsRef<Path>) -> Self {
        self.args.push(path.as_ref().to_string_lossy().into_owned());
        self
    }

    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn envs(mut self, vars: &BTreeMap<String, String>) -> Self {
        for (k, v) in vars {
            self.env.insert(k.clone(), v.clone());
        }
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Declare which exit codes count as a successful run.
    pub fn success_codes(mut self, codes: impl IntoIterator<Item = i32>) -> Self {
        self.success_codes = codes.into_iter().collect();
        self
    }

    pub fn command_line(&self) -> String {
        let mut parts = vec![self.program.to_string_lossy().into_owned()];
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }

    /// Run to completion, capturing output.
    ///
    /// On timeout the child is killed and a `Timeout` error is returned; partial output
    /// is discarded because a half-written JSON document is worse than none.
    pub async fn run(self) -> Result<CommandOutput> {
        let started = Instant::now();
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(dir) = &self.cwd {
            command.current_dir(dir);
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }

        tracing::debug!(command = %self.command_line(), "running external tool");

        let child = command.output();
        let output = match tokio::time::timeout(self.timeout, child).await {
            Err(_) => {
                return Err(Error::Timeout {
                    what: self.command_line(),
                    seconds: self.timeout.as_secs(),
                })
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::MissingBinary {
                    binary: self.program.to_string_lossy().into_owned(),
                })
            }
            Ok(Err(e)) => return Err(Error::io(self.program.clone(), e)),
            Ok(Ok(output)) => output,
        };

        let result = CommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration: started.elapsed(),
        };

        match result.status {
            Some(code) if self.success_codes.contains(&code) => Ok(result),
            _ => Err(Error::plugin(
                self.program.to_string_lossy().into_owned(),
                result.error_summary(),
            )),
        }
    }

    /// Run, tolerating any exit code. The caller inspects `status` itself.
    pub async fn run_lenient(mut self) -> Result<CommandOutput> {
        self.success_codes = (0..=255).collect();
        self.run().await
    }
}

/// Locate an executable on `PATH`.
///
/// Implemented directly rather than via a crate: the logic is fifteen lines, and one
/// fewer dependency in the supply chain of a security tool is worth fifteen lines.
pub fn which(program: impl AsRef<OsStr>) -> Option<PathBuf> {
    let program = Path::new(program.as_ref());
    if program.components().count() > 1 {
        return program.is_file().then(|| program.to_path_buf());
    }

    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(program);
        is_executable(&candidate).then_some(candidate)
    })
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Ask a tool for its version, returning `None` if it cannot be determined.
///
/// Never fails the scan: a scanner that refuses to report a version still scans.
pub async fn tool_version(program: &Path, flag: &str) -> Option<String> {
    let output = Exec::new(program)
        .arg(flag)
        .timeout(Duration::from_secs(10))
        .run_lenient()
        .await
        .ok()?;
    let text = if output.stdout.trim().is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    text.lines().next().map(str::trim).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_binary_that_exists_everywhere() {
        assert!(which("sh").is_some());
    }

    #[test]
    fn returns_none_for_nonexistent_binaries() {
        assert!(which("quoll-definitely-not-a-real-binary").is_none());
    }

    #[test]
    fn explicit_paths_bypass_path_lookup() {
        assert!(which("/bin/sh").is_some());
        assert!(which("/bin/quoll-nope").is_none());
    }

    #[tokio::test]
    async fn captures_stdout_and_exit_status() {
        let output = Exec::new("/bin/sh")
            .args(["-c", "echo hello"])
            .run()
            .await
            .unwrap();
        assert!(output.success());
        assert_eq!(output.stdout.trim(), "hello");
    }

    #[tokio::test]
    async fn nonzero_exit_is_an_error_by_default() {
        let result = Exec::new("/bin/sh")
            .args(["-c", "echo boom >&2; exit 3"])
            .run()
            .await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
        assert!(err.is_recoverable());
    }

    #[tokio::test]
    async fn declared_success_codes_are_accepted() {
        let output = Exec::new("/bin/sh")
            .args(["-c", "echo found; exit 1"])
            .success_codes([0, 1])
            .run()
            .await
            .unwrap();
        assert_eq!(output.status, Some(1));
        assert_eq!(output.stdout.trim(), "found");
    }

    #[tokio::test]
    async fn timeout_kills_the_child() {
        let result = Exec::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .timeout(Duration::from_millis(150))
            .run()
            .await;
        assert!(matches!(result, Err(Error::Timeout { .. })));
    }

    #[tokio::test]
    async fn missing_binary_is_reported_distinctly() {
        let result = Exec::new("quoll-definitely-not-a-real-binary").run().await;
        assert!(matches!(result, Err(Error::MissingBinary { .. })));
    }

    #[tokio::test]
    async fn environment_is_passed_through() {
        let output = Exec::new("/bin/sh")
            .args(["-c", "echo $QUOLL_TEST"])
            .env("QUOLL_TEST", "42")
            .run()
            .await
            .unwrap();
        assert_eq!(output.stdout.trim(), "42");
    }

    #[test]
    fn error_summary_prefers_the_last_meaningful_stderr_line() {
        let output = CommandOutput {
            status: Some(2),
            stdout: String::new(),
            stderr: "warming up\nfatal: bad ruleset\n\n".into(),
            duration: Duration::ZERO,
        };
        assert_eq!(output.error_summary(), "fatal: bad ruleset");
    }
}
