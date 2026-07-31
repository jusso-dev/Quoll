use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A 1-indexed line/column range inside a file.
///
/// Line and column are 1-indexed to match every scanner and editor Quoll talks to.
/// Byte offsets are optional because most external tools do not report them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start_line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_byte: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_byte: Option<u32>,
}

impl Span {
    pub fn line(line: u32) -> Span {
        Span {
            start_line: line.max(1),
            start_column: None,
            end_line: None,
            end_column: None,
            start_byte: None,
            end_byte: None,
        }
    }

    pub fn lines(start: u32, end: u32) -> Span {
        Span {
            start_line: start.max(1),
            start_column: None,
            end_line: Some(end.max(start.max(1))),
            end_column: None,
            start_byte: None,
            end_byte: None,
        }
    }

    pub fn with_columns(mut self, start: u32, end: u32) -> Span {
        self.start_column = Some(start.max(1));
        self.end_column = Some(end.max(1));
        self
    }

    pub fn with_bytes(mut self, start: u32, end: u32) -> Span {
        self.start_byte = Some(start);
        self.end_byte = Some(end);
        self
    }

    pub fn last_line(&self) -> u32 {
        self.end_line.unwrap_or(self.start_line)
    }

    /// Whether two spans touch, used to merge evidence pointing at the same code.
    pub fn overlaps(&self, other: &Span) -> bool {
        self.start_line <= other.last_line() && other.start_line <= self.last_line()
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.end_line, self.start_column) {
            (Some(end), _) if end != self.start_line => write!(f, "{}-{}", self.start_line, end),
            (_, Some(col)) => write!(f, "{}:{}", self.start_line, col),
            _ => write!(f, "{}", self.start_line),
        }
    }
}

/// A repository-relative pointer to source code.
///
/// Paths are always relative to the repository root so that findings stay comparable
/// between a developer laptop and a CI runner with a different checkout directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,
    /// Verbatim source excerpt, populated lazily for reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// Enclosing function or method, when the code graph can attribute one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

impl Location {
    pub fn file(path: impl Into<PathBuf>) -> Location {
        Location {
            path: path.into(),
            span: None,
            snippet: None,
            symbol: None,
        }
    }

    pub fn at(path: impl Into<PathBuf>, line: u32) -> Location {
        Location {
            path: path.into(),
            span: Some(Span::line(line)),
            snippet: None,
            symbol: None,
        }
    }

    pub fn with_span(mut self, span: Span) -> Location {
        self.span = Some(span);
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Location {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_symbol(mut self, symbol: impl Into<String>) -> Location {
        self.symbol = Some(symbol.into());
        self
    }

    pub fn line(&self) -> u32 {
        self.span.map(|s| s.start_line).unwrap_or(1)
    }

    /// Normalise an absolute path against the repository root.
    ///
    /// Falls back to the input when the path lies outside the root, which happens for
    /// scanners that report on vendored SDK paths or temp directories.
    pub fn relative_to(mut self, root: &Path) -> Location {
        if let Ok(rel) = self.path.strip_prefix(root) {
            self.path = rel.to_path_buf();
        }
        self
    }

    /// `path:line` — the form editors and terminals turn into clickable links.
    pub fn display(&self) -> String {
        match &self.span {
            Some(span) => format!("{}:{}", self.path.display(), span),
            None => self.path.display().to_string(),
        }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_clamp_to_one_indexed_lines() {
        assert_eq!(Span::line(0).start_line, 1);
        assert_eq!(Span::lines(10, 3).last_line(), 10);
    }

    #[test]
    fn overlap_is_symmetric() {
        let a = Span::lines(10, 20);
        let b = Span::lines(15, 25);
        let c = Span::lines(30, 40);
        assert!(a.overlaps(&b) && b.overlaps(&a));
        assert!(!a.overlaps(&c) && !c.overlaps(&a));
    }

    #[test]
    fn strips_repository_root() {
        let loc = Location::at("/repo/src/main.rs", 4).relative_to(Path::new("/repo"));
        assert_eq!(loc.display(), "src/main.rs:4");
    }
}
