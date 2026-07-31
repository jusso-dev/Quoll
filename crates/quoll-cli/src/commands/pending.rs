use crate::commands::Context;
use crate::exit::Exit;

/// Report a command whose implementing crate has not been written yet.
///
/// This exists so that an unbuilt command and a broken one never look the same. A user who
/// runs `quoll scan` today gets told which crate is missing and what it will provide, and
/// gets a distinct exit code (`70`) that no scan outcome uses — so a CI pipeline pointed at
/// a pre-alpha build fails loudly rather than reporting a clean scan.
pub fn report(
    context: &Context,
    command: &str,
    crate_name: &str,
    provides: &str,
) -> Exit {
    let printer = &context.printer;
    eprintln!(
        "{} `quoll {command}` is not implemented in this build",
        printer.yellow("pending:")
    );
    eprintln!("  waiting on {}, which will provide {provides}.", printer.bold(crate_name));
    eprintln!();
    eprintln!("  Working today: {}", printer.bold("init, graph, plugins, doctor"));
    eprintln!("  Progress:      https://github.com/jusso-dev/Quoll#roadmap");
    Exit::NotImplemented
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Printer;

    #[test]
    fn pending_commands_never_report_success() {
        let context = Context {
            printer: Printer::plain(),
            root: std::path::PathBuf::from("."),
            config_override: None,
        };
        let exit = report(&context, "scan", "quoll-engine", "orchestration");
        assert_eq!(exit, Exit::NotImplemented);
        assert_ne!(exit, Exit::Ok);
    }
}
