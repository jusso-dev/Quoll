//! Tree-sitter extraction of declarations, imports and call sites.
//!
//! What this module does *not* do is as important as what it does. It records the calls a
//! file makes by name; it does not resolve overloads, follow trait dispatch or track
//! values across function boundaries. Quoll's reports describe call relationships as
//! evidence, never as proof of reachability, and this is why.

use std::collections::HashMap;

use quoll_core::{Language, Result, Span};
use tree_sitter::{Node as TsNode, Parser};

use crate::model::{Symbol, SymbolKind};
use crate::walk::SourceFile;

/// A call site: one name this file invokes, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Bare callee name, e.g. `execute` in `db.execute(...)`.
    pub name: String,
    /// Receiver or path prefix when there was one, e.g. `db` or `std::process::Command`.
    pub receiver: Option<String>,
    /// The declaration this call appears inside, when it appears inside one.
    pub caller: Option<String>,
    pub span: Span,
}

impl Reference {
    /// `receiver.name`, the form framework detection matches against.
    pub fn qualified(&self) -> String {
        match &self.receiver {
            Some(receiver) => format!("{receiver}.{}", self.name),
            None => self.name.clone(),
        }
    }
}

/// An import or `use` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// Module path as written: `better-auth/next-js`, `std::process::Command`.
    pub module: String,
    /// Named bindings, when the grammar exposes them.
    pub names: Vec<String>,
    pub span: Span,
}

/// Everything one file contributed to the graph.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedFile {
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub references: Vec<Reference>,
    /// True when tree-sitter reported syntax errors.
    ///
    /// Partial results are still used: a file that fails to parse cleanly usually still
    /// yields correct declarations, and dropping it would silently shrink the graph.
    pub had_errors: bool,
}

/// Node type names that matter, per grammar.
///
/// Keeping these in data rather than in `match` arms means adding Python or Go is a table
/// entry plus a name-extraction case, not a new traversal.
struct Spec {
    functions: &'static [&'static str],
    methods: &'static [&'static str],
    types: &'static [&'static str],
    modules: &'static [&'static str],
    imports: &'static [&'static str],
    calls: &'static [&'static str],
    /// Declarations that name the container their children belong to.
    containers: &'static [&'static str],
    /// Wrapper that marks its child as publicly visible.
    export_markers: &'static [&'static str],
}

const RUST: Spec = Spec {
    functions: &["function_item"],
    methods: &["function_signature_item"],
    types: &["struct_item", "enum_item", "trait_item", "union_item"],
    modules: &["mod_item"],
    imports: &["use_declaration"],
    // Macros are calls for our purposes: `sqlx::query!` and `Command::new` are both ways
    // of reaching a sink, and ignoring macros would hide most Rust SQL.
    calls: &["call_expression", "macro_invocation"],
    containers: &["impl_item", "trait_item", "mod_item"],
    export_markers: &["visibility_modifier"],
};

const ECMASCRIPT: Spec = Spec {
    functions: &[
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "arrow_function",
    ],
    methods: &["method_definition"],
    types: &[
        "class_declaration",
        "interface_declaration",
        "type_alias_declaration",
        "enum_declaration",
    ],
    modules: &["namespace_declaration", "internal_module"],
    imports: &["import_statement"],
    calls: &["call_expression", "new_expression"],
    containers: &["class_declaration", "class", "interface_declaration"],
    export_markers: &["export_statement"],
};

fn spec_for(language: &Language) -> Option<&'static Spec> {
    match language {
        Language::Rust => Some(&RUST),
        Language::JavaScript | Language::TypeScript | Language::Tsx => Some(&ECMASCRIPT),
        _ => None,
    }
}

fn grammar_for(language: &Language) -> Option<tree_sitter::Language> {
    Some(match language {
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        _ => return None,
    })
}

/// Whether Quoll can extract structure from this language today.
pub fn is_supported(language: &Language) -> bool {
    grammar_for(language).is_some()
}

/// Reusable tree-sitter parsers, one per grammar.
///
/// Constructing a `Parser` allocates and loads a grammar; indexing a repository does this
/// once per language instead of once per file.
#[derive(Default)]
pub struct Parsers {
    parsers: HashMap<String, Parser>,
}

impl Parsers {
    pub fn new() -> Parsers {
        Parsers::default()
    }

    /// Parse one file. Returns `None` for languages with no grammar wired up.
    pub fn parse(&mut self, file: &SourceFile) -> Result<Option<ParsedFile>> {
        let language = match &file.language {
            Some(language) => language,
            None => return Ok(None),
        };
        let (grammar, spec) = match (grammar_for(language), spec_for(language)) {
            (Some(grammar), Some(spec)) => (grammar, spec),
            _ => return Ok(None),
        };

        let parser = match self.parsers.get_mut(language.as_str()) {
            Some(parser) => parser,
            None => {
                let mut parser = Parser::new();
                parser.set_language(&grammar).map_err(|err| {
                    quoll_core::Error::Graph(format!(
                        "failed to load the {language} grammar: {err}"
                    ))
                })?;
                self.parsers.insert(language.as_str().to_string(), parser);
                self.parsers.get_mut(language.as_str()).expect("just inserted")
            }
        };

        let tree = match parser.parse(&file.text, None) {
            Some(tree) => tree,
            // Tree-sitter returns `None` only on cancellation or a grammar/ABI mismatch.
            None => return Ok(None),
        };

        let mut extractor = Extractor {
            source: file.text.as_bytes(),
            path: &file.path,
            spec,
            out: ParsedFile {
                had_errors: tree.root_node().has_error(),
                ..Default::default()
            },
        };
        extractor.walk(tree.root_node(), &mut Vec::new(), &mut Vec::new());
        Ok(Some(extractor.out))
    }
}

struct Extractor<'a> {
    source: &'a [u8],
    path: &'a std::path::Path,
    spec: &'static Spec,
    out: ParsedFile,
}

impl Extractor<'_> {
    /// Depth-first walk carrying two stacks: the enclosing type/module names, and the
    /// enclosing callable, so every call site can be attributed to the function it is in.
    fn walk(&mut self, node: TsNode<'_>, containers: &mut Vec<String>, callers: &mut Vec<String>) {
        let kind = node.kind();
        let mut pushed_container = false;
        let mut pushed_caller = false;

        if self.spec.imports.contains(&kind) {
            if let Some(import) = self.import(node) {
                self.out.imports.push(import);
            }
        } else if self.spec.calls.contains(&kind) {
            if let Some(reference) = self.reference(node, callers.last()) {
                self.out.references.push(reference);
            }
        } else if let Some((name, symbol_kind)) = self.declaration(node) {
            let container = containers.last().cloned();
            let symbol = Symbol {
                name: name.clone(),
                // A free function nested inside a class or `impl` is a method; the grammar
                // node alone cannot tell us that, the container stack can.
                kind: match (symbol_kind, container.is_some()) {
                    (SymbolKind::Function, true) => SymbolKind::Method,
                    (kind, _) => kind,
                },
                path: self.path.to_path_buf(),
                span: span_of(node),
                container: container.clone(),
                exported: self.is_exported(node),
            };
            let qualified = symbol.qualified_name();
            if symbol.kind.is_callable() {
                callers.push(qualified.clone());
                pushed_caller = true;
            }
            if self.spec.containers.contains(&kind) || !symbol.kind.is_callable() {
                containers.push(name);
                pushed_container = true;
            }
            self.out.symbols.push(symbol);
        } else if self.spec.containers.contains(&kind) {
            // An `impl` block has no name of its own; it takes the name of its type.
            if let Some(name) = self.container_name(node) {
                containers.push(name);
                pushed_container = true;
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk(child, containers, callers);
        }

        if pushed_caller {
            callers.pop();
        }
        if pushed_container {
            containers.pop();
        }
    }

    /// Classify a node as a declaration, if it is one.
    fn declaration(&self, node: TsNode<'_>) -> Option<(String, SymbolKind)> {
        let kind = node.kind();
        let symbol_kind = if self.spec.methods.contains(&kind) {
            SymbolKind::Method
        } else if self.spec.functions.contains(&kind) {
            SymbolKind::Function
        } else if self.spec.modules.contains(&kind) {
            SymbolKind::Module
        } else if self.spec.types.contains(&kind) {
            type_symbol_kind(kind)
        } else {
            return None;
        };

        let name = self
            .field_text(node, "name")
            // An arrow function assigned to a variable takes the variable's name, which is
            // how most Next.js and Express handlers are written.
            .or_else(|| self.assigned_name(node))?;
        Some((name, symbol_kind))
    }

    /// The name an anonymous function is bound to, walking up through the declarator.
    fn assigned_name(&self, node: TsNode<'_>) -> Option<String> {
        let mut current = node.parent()?;
        for _ in 0..3 {
            match current.kind() {
                "variable_declarator" | "public_field_definition" | "pair" => {
                    return self.field_text(current, "name").or_else(|| self.field_text(current, "key"))
                }
                "assignment_expression" => return self.field_text(current, "left"),
                _ => current = current.parent()?,
            }
        }
        None
    }

    /// The type an `impl`/`class` block introduces as a container.
    fn container_name(&self, node: TsNode<'_>) -> Option<String> {
        self.field_text(node, "type")
            .or_else(|| self.field_text(node, "name"))
    }

    fn is_exported(&self, node: TsNode<'_>) -> bool {
        // Rust: a `visibility_modifier` child. ECMAScript: an `export_statement` parent.
        let mut cursor = node.walk();
        if node
            .children(&mut cursor)
            .any(|child| self.spec.export_markers.contains(&child.kind()))
        {
            return true;
        }
        let mut current = node.parent();
        for _ in 0..3 {
            let parent = match current {
                Some(parent) => parent,
                None => return false,
            };
            if self.spec.export_markers.contains(&parent.kind()) {
                return true;
            }
            current = parent.parent();
        }
        false
    }

    fn import(&self, node: TsNode<'_>) -> Option<Import> {
        let text = self.text(node);
        let module = extract_module(&text)?;
        Some(Import {
            names: extract_imported_names(&text),
            module,
            span: span_of(node),
        })
    }

    fn reference(&self, node: TsNode<'_>, caller: Option<&String>) -> Option<Reference> {
        // `function` for call/new expressions, `macro` for Rust macro invocations.
        let callee = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("constructor"))
            .or_else(|| node.child_by_field_name("macro"))?;

        let (receiver, name) = match callee.kind() {
            "member_expression" | "field_expression" => (
                callee.child_by_field_name("object").map(|n| self.text(n)),
                self.field_text(callee, "property")
                    .or_else(|| self.field_text(callee, "field"))?,
            ),
            "scoped_identifier" => {
                let full = self.text(callee);
                let (path, name) = full.rsplit_once("::")?;
                (Some(path.to_string()), name.to_string())
            }
            _ => (None, self.text(callee)),
        };

        if name.is_empty() {
            return None;
        }
        Some(Reference {
            name,
            receiver,
            caller: caller.cloned(),
            span: span_of(node),
        })
    }

    fn field_text(&self, node: TsNode<'_>, field: &str) -> Option<String> {
        node.child_by_field_name(field).map(|child| self.text(child))
    }

    fn text(&self, node: TsNode<'_>) -> String {
        node.utf8_text(self.source).unwrap_or("").to_string()
    }
}

fn type_symbol_kind(node_kind: &str) -> SymbolKind {
    match node_kind {
        "struct_item" => SymbolKind::Struct,
        "enum_item" | "enum_declaration" => SymbolKind::Enum,
        "trait_item" => SymbolKind::Trait,
        "interface_declaration" => SymbolKind::Interface,
        "type_alias_declaration" => SymbolKind::TypeAlias,
        _ => SymbolKind::Class,
    }
}

/// Tree-sitter positions are 0-indexed; every other part of Quoll is 1-indexed.
fn span_of(node: TsNode<'_>) -> Span {
    let start = node.start_position();
    let end = node.end_position();
    Span {
        start_line: start.row as u32 + 1,
        end_line: Some(end.row as u32 + 1),
        start_column: Some(start.column as u32 + 1),
        end_column: Some(end.column as u32 + 1),
        start_byte: Some(node.start_byte() as u32),
        end_byte: Some(node.end_byte() as u32),
    }
}

/// The module path from an import statement's source text.
///
/// Done on text rather than on grammar fields because the two grammars disagree on where
/// the path lives (`source` in ECMAScript, an unnamed `use` tree in Rust) and the text form
/// is what policy packs match on anyway.
fn extract_module(text: &str) -> Option<String> {
    if let Some(start) = text.find(['"', '\'']) {
        let quote = text.as_bytes()[start] as char;
        let rest = &text[start + 1..];
        let end = rest.find(quote)?;
        return Some(rest[..end].to_string());
    }
    // Rust: `use std::process::Command;` or `use axum::{Router, routing::get};`
    let trimmed = text.trim().trim_start_matches("pub ").trim_start_matches("use ");
    let path = trimmed.split(['{', ';']).next()?.trim().trim_end_matches("::");
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

/// Named bindings inside `{ ... }`, for both `import { a, b }` and `use x::{a, b}`.
fn extract_imported_names(text: &str) -> Vec<String> {
    let inner = match (text.find('{'), text.rfind('}')) {
        (Some(open), Some(close)) if close > open => &text[open + 1..close],
        _ => return Vec::new(),
    };
    inner
        .split(',')
        .map(|part| {
            part.split(" as ")
                .last()
                .unwrap_or(part)
                .trim()
                .trim_end_matches(&[';', '"', '\''][..])
                .to_string()
        })
        .filter(|name| !name.is_empty() && !name.contains("::"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(path: &str, text: &str) -> ParsedFile {
        let path = PathBuf::from(path);
        let file = SourceFile {
            language: Language::from_path(&path),
            path,
            hash: String::new(),
            size: text.len() as u64,
            text: text.to_string(),
        };
        Parsers::new()
            .parse(&file)
            .unwrap()
            .expect("language should be supported")
    }

    fn names(parsed: &ParsedFile) -> Vec<&str> {
        parsed.symbols.iter().map(|s| s.name.as_str()).collect()
    }

    #[test]
    fn extracts_rust_functions_with_spans() {
        let parsed = parse("src/lib.rs", "pub fn create_user() {}\nfn helper() {}\n");
        assert_eq!(names(&parsed), vec!["create_user", "helper"]);
        assert_eq!(parsed.symbols[0].span.start_line, 1);
        assert_eq!(parsed.symbols[1].span.start_line, 2);
    }

    #[test]
    fn rust_visibility_marks_exports() {
        let parsed = parse("src/lib.rs", "pub fn public() {}\nfn private() {}\n");
        assert!(parsed.symbols[0].exported);
        assert!(!parsed.symbols[1].exported);
    }

    #[test]
    fn rust_impl_methods_get_their_type_as_container() {
        let parsed = parse(
            "src/db.rs",
            "struct UserRepo;\nimpl UserRepo {\n  pub fn create(&self) {}\n}\n",
        );
        let create = parsed.symbols.iter().find(|s| s.name == "create").unwrap();
        assert_eq!(create.kind, SymbolKind::Method);
        assert_eq!(create.container.as_deref(), Some("UserRepo"));
        assert_eq!(create.qualified_name(), "UserRepo::create");
    }

    #[test]
    fn rust_calls_record_their_path_and_caller() {
        let parsed = parse(
            "src/main.rs",
            "fn run() {\n  std::process::Command::new(\"sh\");\n}\n",
        );
        let call = parsed
            .references
            .iter()
            .find(|r| r.name == "new")
            .expect("call site");
        assert_eq!(call.receiver.as_deref(), Some("std::process::Command"));
        assert_eq!(call.caller.as_deref(), Some("run"));
        assert_eq!(call.span.start_line, 2);
    }

    #[test]
    fn rust_macros_count_as_calls() {
        let parsed = parse("src/db.rs", "fn q() {\n  sqlx::query!(\"SELECT 1\");\n}\n");
        let call = parsed
            .references
            .iter()
            .find(|r| r.name == "query")
            .unwrap_or_else(|| panic!("{:?}", parsed.references));
        assert_eq!(call.receiver.as_deref(), Some("sqlx"));
        assert_eq!(call.qualified(), "sqlx.query");
    }

    #[test]
    fn rust_use_declarations_become_imports() {
        let parsed = parse(
            "src/main.rs",
            "use std::process::Command;\nuse axum::{Router, Json};\n",
        );
        let modules: Vec<&str> = parsed.imports.iter().map(|i| i.module.as_str()).collect();
        assert_eq!(modules, vec!["std::process::Command", "axum"]);
        assert_eq!(parsed.imports[1].names, vec!["Router", "Json"]);
    }

    #[test]
    fn extracts_typescript_functions_and_classes() {
        let parsed = parse(
            "src/api.ts",
            "export function handler() {}\nclass Service {\n  run() {}\n}\n",
        );
        assert!(names(&parsed).contains(&"handler"));
        assert!(names(&parsed).contains(&"Service"));
        let run = parsed.symbols.iter().find(|s| s.name == "run").unwrap();
        assert_eq!(run.kind, SymbolKind::Method);
        assert_eq!(run.container.as_deref(), Some("Service"));
    }

    #[test]
    fn export_statements_mark_typescript_exports() {
        let parsed = parse("src/api.ts", "export function a() {}\nfunction b() {}\n");
        let a = parsed.symbols.iter().find(|s| s.name == "a").unwrap();
        let b = parsed.symbols.iter().find(|s| s.name == "b").unwrap();
        assert!(a.exported);
        assert!(!b.exported);
    }

    #[test]
    fn arrow_functions_take_the_name_they_are_bound_to() {
        let parsed = parse("app/route.ts", "export const POST = async () => {};\n");
        assert!(names(&parsed).contains(&"POST"), "{:?}", names(&parsed));
    }

    #[test]
    fn typescript_member_calls_record_the_receiver() {
        let parsed = parse(
            "src/db.ts",
            "export async function save() {\n  await db.insert(users).values(x);\n}\n",
        );
        let insert = parsed.references.iter().find(|r| r.name == "insert").unwrap();
        assert_eq!(insert.receiver.as_deref(), Some("db"));
        assert_eq!(insert.qualified(), "db.insert");
        assert_eq!(insert.caller.as_deref(), Some("save"));
    }

    #[test]
    fn typescript_imports_capture_module_and_bindings() {
        let parsed = parse(
            "src/auth.ts",
            "import { auth } from \"better-auth/next-js\";\nimport db from './db';\n",
        );
        assert_eq!(parsed.imports[0].module, "better-auth/next-js");
        assert_eq!(parsed.imports[0].names, vec!["auth"]);
        assert_eq!(parsed.imports[1].module, "./db");
    }

    #[test]
    fn tsx_is_parsed_with_the_tsx_grammar() {
        let parsed = parse(
            "app/page.tsx",
            "export default function Page() {\n  return <div>hi</div>;\n}\n",
        );
        assert!(names(&parsed).contains(&"Page"));
        assert!(!parsed.had_errors);
    }

    #[test]
    fn syntax_errors_still_yield_the_declarations_that_parsed() {
        let parsed = parse("src/lib.rs", "fn good() {}\nfn broken( {\n");
        assert!(parsed.had_errors);
        assert!(names(&parsed).contains(&"good"));
    }

    #[test]
    fn unsupported_languages_are_skipped_not_failed() {
        let path = PathBuf::from("main.py");
        let file = SourceFile {
            language: Language::from_path(&path),
            path,
            hash: String::new(),
            size: 0,
            text: "def x(): pass\n".into(),
        };
        assert!(Parsers::new().parse(&file).unwrap().is_none());
        assert!(!is_supported(&Language::Python));
        assert!(is_supported(&Language::Rust));
    }

    #[test]
    fn aliased_imports_record_the_local_binding() {
        assert_eq!(
            extract_imported_names("import { auth as checkAuth } from 'x';"),
            vec!["checkAuth"]
        );
    }
}
