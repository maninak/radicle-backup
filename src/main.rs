//! `rad-backup`: back up, restore and migrate a Radicle identity.
//!
//! `rad` runs `rad-<name>` from `PATH` for any subcommand it does not know, so installing this
//! binary is all it takes for `rad backup` to work.

mod archive;
mod cli;
mod cmd;
mod crypt;
mod db;
mod error;
mod exec;
mod git;
mod home;
mod inventory;
mod key;
mod manifest;
mod rad;
mod state;
mod term;

use std::io::Write;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};
use crate::cmd::Ctx;
use crate::error::Result;
use crate::home::Home;
use crate::term::{Term, Verbosity};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let term = Term::new(
        if cli.global.quiet {
            Verbosity::Quiet
        } else {
            Verbosity::Normal
        },
        cli.global.yes,
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

fn run(cli: &Cli, term: Term) -> Result<ExitCode> {
    // Generating completions and the manual page needs no home, and must work on a machine
    // that has never run Radicle: package builds do exactly that.
    match &cli.command {
        Some(Command::Completions(args)) => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(args.shell, &mut command, name, &mut std::io::stdout());
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Man) => {
            clap_mangen::Man::new(Cli::command())
                .render(&mut std::io::stdout())
                .map_err(error::Error::Bare)?;
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }

    let ctx = Ctx {
        term,
        home: Home::from_env(cli.global.home.clone())?,
        global: cli.global.clone(),
    };

    match &cli.command {
        None => cmd::backup::run(&ctx, &cli.create).map(|_| ExitCode::SUCCESS),
        Some(Command::Create(args)) => cmd::backup::run(&ctx, args).map(|_| ExitCode::SUCCESS),
        Some(Command::Restore(args)) => cmd::restore::run(&ctx, args),
        Some(Command::Verify(args)) => cmd::verify::run(&ctx, args),
        Some(Command::List(args)) => cmd::list::run(&ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Doctor(args)) => cmd::doctor::run(&ctx, args),
        Some(Command::Paper(args)) => cmd::paper::run(&ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Migrate(args)) => cmd::migrate::run(&ctx, args).map(|()| ExitCode::SUCCESS),
        Some(Command::Diff) => cmd::diff::run(&ctx),
        Some(Command::Completions(_) | Command::Man) => Ok(ExitCode::SUCCESS),
    }
}
