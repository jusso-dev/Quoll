use std::io::IsTerminal;

/// Terminal rendering.
///
/// Colour is decided once, at startup, from three signals in priority order: an explicit
/// `--no-color`, the `NO_COLOR` convention, and whether stdout is actually a terminal.
/// Deciding per-call would let a redirected log end up half-escaped.
#[derive(Debug, Clone, Copy)]
pub struct Printer {
    colour: bool,
    quiet: bool,
}

impl Printer {
    pub fn new(no_color: bool, quiet: bool) -> Printer {
        let colour = !no_color
            && std::env::var_os("NO_COLOR").is_none()
            && std::io::stdout().is_terminal();
        Printer { colour, quiet }
    }

    /// A printer that is never coloured and never suppressed.
    #[cfg(test)]
    pub fn plain() -> Printer {
        Printer {
            colour: false,
            quiet: false,
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.colour {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    pub fn green(&self, text: &str) -> String {
        self.paint("32", text)
    }

    pub fn yellow(&self, text: &str) -> String {
        self.paint("33", text)
    }

    pub fn red(&self, text: &str) -> String {
        self.paint("31", text)
    }

    /// A section heading.
    pub fn heading(&self, text: &str) {
        if self.quiet {
            return;
        }
        println!("\n{}", self.bold(text));
    }

    /// Ordinary output. Suppressed by `--quiet`.
    pub fn line(&self, text: impl AsRef<str>) {
        if self.quiet {
            return;
        }
        println!("{}", text.as_ref());
    }

    /// A `label: value` row, aligned to a fixed label width.
    pub fn field(&self, label: &str, value: impl AsRef<str>) {
        self.line(format!("  {:<22} {}", self.dim(label), value.as_ref()));
    }

    /// Something went right.
    pub fn success(&self, text: impl AsRef<str>) {
        self.line(format!("{} {}", self.green("✓"), text.as_ref()));
    }

    /// Something is missing but the command still succeeded.
    pub fn warn(&self, text: impl AsRef<str>) {
        self.line(format!("{} {}", self.yellow("!"), text.as_ref()));
    }

    /// An error. Goes to stderr so that piped stdout stays machine-readable.
    pub fn error(&self, error: &quoll_core::Error) {
        eprintln!("{} {error}", self.red("error:"));

        // Walk the source chain: the outer message names what failed, the inner ones say
        // why, and dropping them turns "io error" into an unactionable message.
        let mut source = std::error::Error::source(error);
        while let Some(inner) = source {
            eprintln!("  {} {inner}", self.dim("caused by:"));
            source = std::error::Error::source(inner);
        }
    }
}

/// Right-pad a table cell.
pub fn pad(text: &str, width: usize) -> String {
    let mut out = text.to_string();
    // Character count, not byte length: a multi-byte name must not shift the column.
    for _ in text.chars().count()..width {
        out.push(' ');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_printers_emit_no_escape_sequences() {
        let printer = Printer::plain();
        assert_eq!(printer.bold("hi"), "hi");
        assert_eq!(printer.red("hi"), "hi");
    }

    #[test]
    fn padding_counts_characters_not_bytes() {
        assert_eq!(pad("ab", 4), "ab  ");
        assert_eq!(pad("café", 5).chars().count(), 5);
        assert_eq!(pad("toolong", 3), "toolong");
    }
}
