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
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

/// Environment variables every tool inherits from Quoll's own environment.
///
/// Everything else is withheld. Quoll usually runs with model API keys, `GITHUB_TOKEN` and
/// cloud credentials in its environment, and a scanner — or a rule pack it downloads — has
/// no business seeing them. This is the minimum for a process to find its binaries, its
/// home and temp directories, its locale and the network. Entries ending in `*` are
/// prefixes; tools that need more declare it with [`Exec::inherit_env`].
const BASE_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_*",
    "XDG_*",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    // Windows cannot start most processes without these.
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "PATHEXT",
    "COMSPEC",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
];

/// Most stdout Quoll will hold for one tool. Far beyond any real report; a tool that
/// exceeds it is misbehaving, and its output is treated as a failure.
const STDOUT_LIMIT: usize = 256 * 1024 * 1024;

/// Most stderr Quoll will hold. Only the tail is kept, because that is where the error is.
const STDERR_LIMIT: usize = 1024 * 1024;

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
    /// Names (or `PREFIX*` patterns) inherited on top of [`BASE_ENV`].
    inherit: Vec<String>,
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
            inherit: Vec::new(),
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

    /// Let the tool see these variables from Quoll's environment, beyond [`BASE_ENV`].
    ///
    /// A trailing `*` makes a prefix, e.g. `SEMGREP_*`. Values set with [`Exec::env`] are
    /// applied afterwards and always win.
    pub fn inherit_env<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inherit.extend(names.into_iter().map(Into::into));
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
    /// On timeout the child's whole process group is killed and a `Timeout` error is
    /// returned; partial output is discarded because a half-written JSON document is worse
    /// than none.
    pub async fn run(self) -> Result<CommandOutput> {
        let started = Instant::now();
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // Scanners fork workers (semgrep-core, language servers). Their own group lets a
        // timeout kill all of them, not just the entry point.
        #[cfg(unix)]
        command.process_group(0);
        if let Some(dir) = &self.cwd {
            command.current_dir(dir);
        }
        command.env_clear();
        for (key, value) in std::env::vars_os() {
            if key.to_str().is_some_and(|name| self.inherits(name)) {
                command.env(key, value);
            }
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }

        tracing::debug!(command = %self.command_line(), "running external tool");

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::MissingBinary {
                    binary: self.program.to_string_lossy().into_owned(),
                })
            }
            Err(e) => return Err(Error::io(self.program.clone(), e)),
        };
        let pid = child.id();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let finished = async {
            tokio::try_join!(
                capture(stdout, STDOUT_LIMIT, false),
                capture(stderr, STDERR_LIMIT, true),
                child.wait(),
            )
        };

        let ((stdout, stdout_truncated), (stderr, _), status) =
            match tokio::time::timeout(self.timeout, finished).await {
                Err(_) => {
                    kill_group(pid);
                    return Err(Error::Timeout {
                        what: self.command_line(),
                        seconds: self.timeout.as_secs(),
                    });
                }
                Ok(Err(e)) => {
                    kill_group(pid);
                    return Err(Error::io(self.program.clone(), e));
                }
                Ok(Ok(output)) => output,
            };

        let result = CommandOutput {
            status: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            duration: started.elapsed(),
        };

        if stdout_truncated {
            // A truncated report parses as garbage at best and as a clean scan at worst.
            return Err(Error::plugin(
                self.program.to_string_lossy().into_owned(),
                format!("output exceeded {} MiB and was discarded", STDOUT_LIMIT >> 20),
            ));
        }

        match result.status {
            Some(code) if self.success_codes.contains(&code) => Ok(result),
            _ => Err(Error::plugin(
                self.program.to_string_lossy().into_owned(),
                match result.status {
                    Some(code) => format!("exited with status {code}: {}", result.error_summary()),
                    None => result.error_summary(),
                },
            )),
        }
    }

    /// Whether a variable from Quoll's environment may be passed to the tool.
    fn inherits(&self, name: &str) -> bool {
        BASE_ENV
            .iter()
            .copied()
            .chain(self.inherit.iter().map(String::as_str))
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                // Windows variable names are case-insensitive (`Path`, `SystemRoot`).
                None if cfg!(windows) => name.eq_ignore_ascii_case(pattern),
                None => name == pattern,
            })
    }

    /// Run, tolerating any exit code. The caller inspects `status` itself.
    pub async fn run_lenient(mut self) -> Result<CommandOutput> {
        self.success_codes = (0..=255).collect();
        self.run().await
    }
}

/// Read a pipe to the end, holding at most `limit` bytes.
///
/// The pipe is always drained — a child blocked on a full pipe would otherwise hang until
/// the timeout. `keep_tail` keeps the last `limit` bytes instead of the first. Returns the
/// bytes and whether any were dropped.
async fn capture<R: AsyncRead + Unpin>(
    reader: Option<R>,
    limit: usize,
    keep_tail: bool,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut truncated = false;
    let Some(mut reader) = reader else {
        return Ok((kept, truncated));
    };
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if keep_tail {
            kept.extend_from_slice(&chunk[..n]);
            // Trim in batches so the copy is amortised rather than paid per read.
            if kept.len() > limit * 2 {
                kept.drain(..kept.len() - limit);
                truncated = true;
            }
        } else {
            let room = limit.saturating_sub(kept.len());
            kept.extend_from_slice(&chunk[..n.min(room)]);
            truncated |= n > room;
        }
    }
    if kept.len() > limit {
        kept.drain(..kept.len() - limit);
        truncated = true;
    }
    Ok((kept, truncated))
}

/// Kill every process in the child's group. The child leads the group (`process_group(0)`),
/// so its pid is the group id.
#[cfg(unix)]
fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: killpg has no memory-safety preconditions. A group id is not reused while
        // any member is alive, so this cannot reach an unrelated group; if the group is
        // already gone the call fails with ESRCH, which is the desired outcome anyway.
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
}

/// Without process groups, `kill_on_drop` takes the direct child and that is the best
/// available.
#[cfg(not(unix))]
fn kill_group(_pid: Option<u32>) {}

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

    #[tokio::test]
    async fn the_ambient_environment_is_withheld_unless_allowlisted() {
        std::env::set_var("QUOLL_EXEC_TEST_SECRET", "hunter2");
        let script = "echo \"[$QUOLL_EXEC_TEST_SECRET][${PATH:+path}]\"";
        let withheld = Exec::new("/bin/sh").args(["-c", script]).run().await.unwrap();
        assert_eq!(withheld.stdout.trim(), "[][path]");

        let inherited = Exec::new("/bin/sh")
            .args(["-c", script])
            .inherit_env(["QUOLL_EXEC_TEST_*"])
            .run()
            .await
            .unwrap();
        assert_eq!(inherited.stdout.trim(), "[hunter2][path]");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_grandchildren_too() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("sleep 30 & echo $! > '{}'; wait", pid_file.display());
        let result = Exec::new("/bin/sh")
            .args(["-c", &script])
            .timeout(Duration::from_millis(300))
            .run()
            .await;
        assert!(matches!(result, Err(Error::Timeout { .. })));

        let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
        // The killed grandchild may linger as a zombie until init reaps it; give it a moment.
        let mut alive = true;
        for _ in 0..50 {
            let state = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            let state = String::from_utf8_lossy(&state.stdout);
            if state.trim().is_empty() || state.trim().starts_with('Z') {
                alive = false;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!alive, "grandchild {pid} survived the timeout");
    }

    #[tokio::test]
    async fn capture_bounds_what_it_keeps() {
        let (kept, truncated) = capture(Some(&b"abcdefgh"[..]), 4, false).await.unwrap();
        assert_eq!((kept.as_slice(), truncated), (&b"abcd"[..], true));

        let (kept, truncated) = capture(Some(&b"abcdefgh"[..]), 4, true).await.unwrap();
        assert_eq!((kept.as_slice(), truncated), (&b"efgh"[..], true));

        let (kept, truncated) = capture(Some(&b"abc"[..]), 4, false).await.unwrap();
        assert_eq!((kept.as_slice(), truncated), (&b"abc"[..], false));
    }

    #[tokio::test]
    async fn a_failure_names_the_exit_status() {
        let err = Exec::new("/bin/sh")
            .args(["-c", "echo nope >&2; exit 2"])
            .success_codes([0, 1])
            .run()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("status 2"), "{err}");
        assert!(err.to_string().contains("nope"), "{err}");
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
