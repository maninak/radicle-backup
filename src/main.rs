//! `rad-backup`, which `rad` runs from `PATH` as `rad backup`.

mod archives;
mod cli;
mod cmd;
mod container;
mod credits;
mod crypt;
mod db;
mod error;
mod exec;
mod git;
mod home;
mod inventory;
mod key;
mod man;
mod manifest;
mod perms;
mod rad;
mod state;
mod term;

use std::io::Write;
use std::process::ExitCode;

use clap::CommandFactory;

use crate::cli::{Cli, Command};
use crate::cmd::Ctx;
use crate::error::Result;
use crate::home::Home;
use crate::term::{Term, Verbosity};

fn backup_exit_code(outcome: cmd::backup::Outcome) -> ExitCode {
    if outcome.is_incomplete {
        ExitCode::from(crate::error::EXIT_CHECKS_FAILED)
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let cli = cli::parse_from_env();
    let term = Term::new(
        cli.global.yes,
        if cli.global.quiet {
            Verbosity::Quiet
        } else {
            Verbosity::Normal
        },
        cli.global.no_color,
    );

    match run(&cli, term) {
        Ok(code) => code,
        Err(error) => {
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "✗ {error}");
            error.exit_code()
        }
    }
}

/// Writes generated output to stdout, treating a closed pipe as success, because `| head`
/// closes it on purpose.
fn emit(stdout: &mut dyn Write, bytes: &[u8]) -> Result<ExitCode> {
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(ExitCode::SUCCESS),
        Err(e) => Err(error::Error::PathlessIo(e)),
    }
}

fn run(cli: &Cli, term: Term) -> Result<ExitCode> {
    // Completions and the manual page need no home, because package builds generate them on
    // machines that have never run Radicle
    match &cli.command {
        Some(Command::Completions(args)) => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            // Rendered into memory first, because clap_complete panics when the writer
            // fails, and `| head` makes it fail
            let mut rendered = Vec::new();
            clap_complete::generate(args.shell, &mut command, name, &mut rendered);
            return emit(&mut std::io::stdout(), &rendered);
        }
        Some(Command::Man) => return man::run(man::Stdout::detect(), &mut std::io::stdout()),
        _ => {}
    }

    let ctx = Ctx {
        term,
        home: Home::from_env(cli.global.home.clone())?,
        global: cli.global.clone(),
    };

    let outcome = dispatch(&ctx, cli);

    // Schema drift is reported after every verb, or a reader told "the routing table is empty"
    // starts a node that is already running. A blank line keeps it from reading as one more
    // line of what the verb printed last, such as the `doctor` tally.
    let drift = db::drain_schema_drift();
    if !drift.is_empty() {
        ctx.term.blank();
    }
    for drift in &drift {
        ctx.term.warn(&db::schema_drift_warning(drift));
    }
    outcome
}

fn dispatch(ctx: &Ctx, cli: &Cli) -> Result<ExitCode> {
    match &cli.command {
        // Exit 3 when a run wrote an archive but lost a repository, the code `doctor` and
        // `diff` use for "it worked and you should look", so a timer can tell the two apart
        None => {
            cmd::backup::run(ctx, &cli.create, cmd::backup::Purpose::Backup).map(backup_exit_code)
        }
        Some(Command::Create(args)) => {
            cmd::backup::run(ctx, args, cmd::backup::Purpose::Backup).map(backup_exit_code)
        }
        Some(Command::Restore(args)) => cmd::restore::run(ctx, args),
        Some(Command::Verify(args)) => cmd::verify::run(ctx, args),
        Some(Command::Ls(args)) => cmd::ls::run(ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Show(args)) => cmd::show::run(ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Prune(args)) => cmd::prune::run(ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Schedule(args)) => cmd::schedule::run(ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Doctor(args)) => cmd::doctor::run(ctx, args),
        Some(Command::Paper(args)) => cmd::paper::run(ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Move(args)) => cmd::migrate::run(ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Diff) => cmd::diff::run(ctx),
        Some(Command::Completions(_) | Command::Man) => Ok(ExitCode::SUCCESS),
    }
}
