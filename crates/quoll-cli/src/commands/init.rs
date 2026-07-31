use quoll_core::config::{Config, CONFIG_FILE};
use quoll_core::{Error, Result};

use crate::cli::InitArgs;
use crate::commands::Context;
use crate::exit::Exit;

/// Write a starter `quoll.toml`.
///
/// The file is generated from the defaults rather than from a template string, so it can
/// never drift out of step with what Quoll actually reads.
pub fn run(context: &Context, args: &InitArgs) -> Result<Exit> {
    let printer = &context.printer;
    let root = context
        .root
        .canonicalize()
        .map_err(|e| Error::io(context.root.clone(), e))?;
    let target = root.join(CONFIG_FILE);

    if target.exists() && !args.force {
        return Err(Error::config(format!(
            "{} already exists; pass --force to overwrite it",
            target.display()
        )));
    }

    let mut config = Config::default();
    config.scan.profile = args.profile.into();
    config.root = root.clone();
    // Fail fast if the defaults themselves are ever made invalid.
    config.validate()?;

    let toml = config.to_toml()?;
    let contents = format!(
        "# Quoll configuration. Every field here is already the default; the file exists\n\
         # to override, never to enable. Delete anything you are happy with.\n\
         #\n\
         # Reference: https://github.com/jusso-dev/Quoll#configuration\n\n{toml}"
    );
    std::fs::write(&target, contents).map_err(|e| Error::io(target.clone(), e))?;

    printer.success(format!("wrote {}", target.display()));
    printer.field("profile", config.scan.profile.as_str());
    printer.field("graph", config.graph.path.display().to_string());
    printer.field("ai", if config.ai.enabled { "enabled" } else { "disabled" });
    printer.line("");
    printer.line("Next: `quoll graph build` to index the repository.");
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ProfileArg;
    use crate::output::Printer;

    fn context(root: &std::path::Path) -> Context {
        Context {
            printer: Printer::plain(),
            root: root.to_path_buf(),
            config_override: None,
        }
    }

    fn args(force: bool) -> InitArgs {
        InitArgs {
            force,
            profile: ProfileArg::Fast,
        }
    }

    #[test]
    fn writes_a_config_that_loads_back() {
        let dir = tempfile::tempdir().unwrap();
        let context = context(dir.path());
        assert_eq!(run(&context, &args(false)).unwrap(), Exit::Ok);

        let written = Config::load(&dir.path().join(CONFIG_FILE)).unwrap();
        assert_eq!(written.scan.profile, quoll_core::Profile::Fast);
    }

    #[test]
    fn refuses_to_clobber_an_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        let context = context(dir.path());
        run(&context, &args(false)).unwrap();

        let error = run(&context, &args(false)).unwrap_err();
        assert_eq!(Exit::from_error(&error), Exit::InvalidConfig);
        assert!(error.to_string().contains("--force"), "{error}");
    }

    #[test]
    fn force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let context = context(dir.path());
        run(&context, &args(false)).unwrap();
        assert_eq!(run(&context, &args(true)).unwrap(), Exit::Ok);
    }

    #[test]
    fn the_generated_file_documents_itself() {
        let dir = tempfile::tempdir().unwrap();
        run(&context(dir.path()), &args(false)).unwrap();
        let text = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        assert!(text.starts_with("# Quoll configuration"));
        assert!(text.contains("[scan]"));
    }
}
