//! The command line.
//!
//! `rad` runs `rad-backup` for `rad backup`, so every verb here reads as the second word of a
//! `rad backup ...` sentence. Creating an archive is what an unqualified `rad backup` does,
//! because that is the thing people came for.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::parser::ValueSource;
use clap::{ArgAction, ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};

use crate::manifest::{RepoSelection, Tier};

#[derive(Parser, Debug)]
#[command(
    name = "rad-backup",
    version,
    about = "Back up, restore and move a Radicle identity",
    long_about = "Back up, restore and move a Radicle identity, node state and repositories.\n\n\
                  With no command, `rad-backup` creates an archive, the same as `rad-backup \
                  create`. The options listed under Options are for that. Global options work \
                  with or without a command.\n\n\
                  When rad-backup is on your PATH, you can also run it as `rad backup`.",
    after_long_help = crate::credits::help_footer(),
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Arguments for creating an archive, which is what running with no subcommand does.
    #[command(flatten)]
    pub create: Create,

    /// Under a heading of their own, so that neither `--help` nor the man page mixes them in
    /// with the options that shape an archive and mean nothing to any other command. Last,
    /// because clap files every field declared after it under the same heading.
    #[command(flatten, next_help_heading = "Global options")]
    pub global: Global,
}

/// The flags that shape an archive, and so mean nothing to any other verb.
///
/// Asked of clap rather than written out. It was a fixed-length array kept by hand, so every
/// new `create` flag had to be remembered in a second place, and one that was not stopped
/// being recognised here: the flag was accepted before the verb, quietly ignored, and nobody
/// was told where it belonged.
fn create_only_flag_ids() -> Vec<String> {
    use clap::CommandFactory as _;

    Create::command()
        .get_arguments()
        .map(|arg| arg.get_id().to_string())
        .filter(|id| id != "help")
        .collect()
}

/// Parse the command line, then enforce the one rule clap cannot state here.
///
/// `args_conflicts_with_subcommands` would reject `--tier full doctor`, which is right, but
/// it also rejects `--home /srv/radicle doctor`, which is how every other tool in this
/// ecosystem is used. So the global flags stay usable in either position and the
/// archive-shaping ones are checked by hand.
pub fn parse_from_env() -> Cli {
    let called = invocation_as_called(std::env::args_os());
    let mut command = Cli::command();
    if let Some(name) = called.bin_name {
        command = command.bin_name(name);
    }
    let matches = command.get_matches_from(called.argv);
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    if let Some(problem) = misplaced_create_flag_complaint(&matches) {
        Cli::command()
            .error(clap::error::ErrorKind::ArgumentConflict, problem)
            .exit();
    }
    cli
}

/// The command line as the name it was started under implies.
///
/// Installed beside the binary, a `rad-restore` symlink makes `rad restore <archive>` work,
/// because `rad` runs `rad-<name>` from `PATH` for any subcommand it does not know. That is
/// the command somebody reaches for when something has already gone wrong, and it should not
/// depend on their remembering that it lives under `rad backup`.
fn invocation_as_called<I: Iterator<Item = OsString>>(args: I) -> Invocation {
    let mut argv: Vec<OsString> = args.collect();
    let called_restore = argv
        .first()
        .map(PathBuf::from)
        .and_then(|path| {
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .is_some_and(|name| name == "rad-restore" || name == "restore");
    if !called_restore {
        return Invocation {
            argv,
            bin_name: None,
        };
    }
    argv.insert(1, OsString::from("restore"));
    Invocation {
        argv,
        // So the help and the usage line say `rad restore`, which is what was typed, rather
        // than the `rad-restore restore` that the rewritten argv would otherwise spell out.
        bin_name: Some("rad"),
    }
}

/// A command line, and the name to show it under.
struct Invocation {
    argv: Vec<OsString>,
    bin_name: Option<&'static str>,
}

/// The complaint to make when an archive-shaping flag was passed to a verb that makes no
/// archive, or `None` when there is nothing to complain about.
///
/// Only flags given on the command line count. A `RAD_BACKUP_TIER` in the environment is
/// there for every run, and failing `doctor` because of it would be absurd.
fn misplaced_create_flag_complaint(matches: &ArgMatches) -> Option<String> {
    let verb = matches.subcommand_name()?;
    let flags = create_only_flag_ids();
    let id = flags
        .iter()
        .find(|id| matches.value_source(id) == Some(ValueSource::CommandLine))?;
    let flag = id.replace('_', "-");
    // The verb may declare the same flag itself, and the top-level copy is not the one
    // dispatch reads, so the flag would be accepted and then quietly ignored. Saying where to
    // put it beats telling somebody that `create` does not create an archive, or that
    // `schedule` does not take the `--output` it plainly has.
    if declares(verb, id) {
        return Some(format!("`--{flag}` belongs after `{verb}`, not before it"));
    }
    Some(format!(
        "`--{flag}` only works when creating an archive. `{verb}` does not create one"
    ))
}

/// Whether this verb has an argument of its own by that name.
fn declares(verb: &str, id: &str) -> bool {
    use clap::CommandFactory as _;

    Cli::command()
        .find_subcommand(verb)
        .is_some_and(|sub| sub.get_arguments().any(|arg| arg.get_id() == id))
}

#[derive(Parser, Debug, Clone)]
pub struct Global {
    /// The Radicle home directory to use. Defaults to RAD_HOME, then ~/.radicle.
    #[arg(long, global = true, value_name = "PATH")]
    pub home: Option<PathBuf>,

    /// Print a JSON report on stdout instead of text on stderr.
    #[arg(long, global = true)]
    pub json: bool,

    /// Answer yes to every question. Use this in scripts and cron jobs.
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Print nothing but errors.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Turn off colour. Setting NO_COLOR does the same.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Where to put temporary working files while a command runs.
    ///
    /// These are copies of node databases and repositories, and the copy a restore checks
    /// before it moves anything into place. By default they go next to the archive being
    /// written or read, or next to the Radicle home being restored into. With `--stdout`
    /// there is no archive file, so they go to the system temporary directory. Set this when
    /// that disk is small or read-only, or when private repository data must not appear there.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "RAD_BACKUP_SCRATCH_DIR"
    )]
    pub scratch_dir: Option<PathBuf>,

    /// Read the archive passphrase from a file instead of asking for it.
    ///
    /// This file is used first. Without it, rad-backup reads RAD_BACKUP_PASSPHRASE. Without
    /// that, it asks you. Prefer the file. Other programs can sometimes read the environment
    /// variables of a running process.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "RAD_BACKUP_PASSPHRASE_FILE"
    )]
    pub passphrase_file: Option<PathBuf>,

    /// A private key file (age or ssh) that opens an archive encrypted to its public key.
    /// Repeatable.
    //
    // The flag stays `--identity`, which is what age and `age-keygen` call this and what every
    // recipe on the internet spells; the field is named for what it holds, because "identity"
    // in every other line of this tool means the Radicle identity, which this is not.
    #[arg(long = "identity", global = true, value_name = "PATH", action = ArgAction::Append)]
    pub age_identity_files: Vec<PathBuf>,

    /// Read the passphrase for the --identity key from a file instead of asking for it.
    ///
    /// This passphrase unlocks the private key file. It is not a passphrase for the archive.
    /// An archive encrypted to a public key has no passphrase of its own. This file is used
    /// first. Without it, rad-backup reads RAD_BACKUP_IDENTITY_PASSPHRASE. Without that, it
    /// asks you. Prefer the file. Other programs can sometimes read the environment variables
    /// of a running process.
    ///
    /// The same passphrase is used for every --identity key. age stops at the first key it
    /// cannot unlock, so in a script pass only the key the archive was encrypted to.
    #[arg(
        long = "identity-passphrase-file",
        global = true,
        value_name = "PATH",
        env = "RAD_BACKUP_IDENTITY_PASSPHRASE_FILE"
    )]
    pub age_identity_passphrase_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create an archive. The default when no command is given.
    Create(Create),

    /// Restore your Radicle identity and data from an archive.
    ///
    /// If a `rad-restore` link to rad-backup is on your PATH, `rad restore <archive>` also
    /// works.
    Restore(Restore),

    /// Check that an archive is complete and can be read.
    Verify(Verify),

    /// List the archives of your identity, newest first.
    #[command(visible_alias = "list")]
    Ls(Ls),

    /// Show what is inside an archive.
    #[command(visible_alias = "inspect")]
    Show(ArchiveArg),

    /// Delete older archives of your identity, keeping the newest few.
    Prune(Prune),

    /// Create archives automatically on a schedule.
    Schedule(Schedule),

    /// Check whether your identity and data could be recovered right now.
    Doctor(Doctor),

    /// Create a recovery sheet to print.
    Paper(Paper),

    /// Move your identity to another machine.
    #[command(name = "move")]
    Move(Migrate),

    /// Show what changed since the last archive.
    Diff,

    /// Print shell completions.
    Completions(Completions),

    /// Print the man page, to save where `man rad-backup` can find it.
    ///
    /// In a terminal it shows how to read the manual instead.
    Man,
}

#[derive(Parser, Debug, Clone)]
pub struct Create {
    /// Where to write the archive. A path ending in `.tar.zst`, `.age` or `.tar` is used as
    /// the file name. Any other path is a directory, created if missing, and the archive gets
    /// a name inside it. Defaults to RAD_BACKUP_DIR, then the current directory.
    #[arg(long, short = 'o', value_name = "PATH", env = "RAD_BACKUP_DIR")]
    pub output: Option<PathBuf>,

    /// How much to include in the archive.
    #[arg(long, value_enum, default_value_t = TierArg::State, env = "RAD_BACKUP_TIER")]
    pub tier: TierArg,

    /// Which repositories to include. Defaults to what --tier includes.
    #[arg(long, value_enum, value_name = "WHICH")]
    pub repos: Option<ReposArg>,

    /// Write the archive to stdout, for piping into restic, borg or ssh.
    ///
    /// Cannot be used with --output or --json.
    #[arg(long, conflicts_with = "output", conflicts_with = "json")]
    pub stdout: bool,

    /// Do not encrypt the archive. Anyone with the file can read everything in it, your key
    /// file included.
    #[arg(long, conflicts_with = "recipient")]
    pub plaintext: bool,

    /// Encrypt to an age or ssh public key instead of to a passphrase. Repeatable.
    #[arg(long, value_name = "KEY", action = ArgAction::Append)]
    pub recipient: Vec<String>,

    /// Stop your node while the archive is created, then start it again.
    #[arg(long)]
    pub stop_node: bool,

    /// Also include the node database of known peers and their addresses. Your node rebuilds
    /// it from the network when it is left out.
    #[arg(long)]
    pub with_node_db: bool,

    /// After writing, delete older archives of your identity in the output directory, keeping
    /// the newest N.
    #[arg(long, value_name = "N", env = "RAD_BACKUP_KEEP")]
    pub keep: Option<usize>,

    /// Show what the archive would include and how big it would be, without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Ls {
    /// The directory to look in. Defaults to RAD_BACKUP_DIR, then the directory of your last
    /// archive.
    #[arg(long, short = 'd', value_name = "PATH", env = "RAD_BACKUP_DIR")]
    pub dir: Option<PathBuf>,

    /// Caught rather than rejected, so that naming an archive here is answered with the verb
    /// that does what was meant instead of with a usage dump.
    #[arg(value_name = "ARCHIVE", hide = true)]
    pub mistaken: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct Prune {
    /// How many of the newest archives to keep.
    #[arg(long, value_name = "N", env = "RAD_BACKUP_KEEP")]
    pub keep: usize,

    /// The directory to delete archives from. Defaults to RAD_BACKUP_DIR, then the directory
    /// of your last archive.
    #[arg(long, short = 'd', value_name = "PATH", env = "RAD_BACKUP_DIR")]
    pub dir: Option<PathBuf>,

    /// List what would be deleted without deleting it.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Schedule {
    /// How often to create an archive: `daily`, `weekly`, `hourly`, or a systemd calendar
    /// expression such as `Mon,Thu 04:00`.
    #[arg(long, value_name = "WHEN", default_value = "daily")]
    pub every: String,

    /// Where the scheduled run should write its archives.
    #[arg(long, short = 'o', value_name = "PATH", env = "RAD_BACKUP_DIR")]
    pub output: Option<PathBuf>,

    /// How many archives the scheduled run should keep.
    #[arg(long, value_name = "N")]
    pub keep: Option<usize>,

    /// Encrypt the scheduled archives to an age or ssh public key instead of to a
    /// passphrase. Repeatable.
    ///
    /// With a public key, the scheduled run needs no passphrase file.
    #[arg(long, value_name = "KEY", action = ArgAction::Append)]
    pub recipient: Vec<String>,

    /// Do not encrypt the scheduled archives. They will hold your private key in the clear.
    #[arg(long, conflicts_with = "recipient")]
    pub plaintext: bool,

    /// Turn the schedule off. The systemd unit files stay in place.
    #[arg(long, conflicts_with_all = ["every", "output", "keep", "recipient", "plaintext"])]
    pub off: bool,

    /// Show whether the schedule is on and when it runs next. Changes nothing.
    #[arg(long, conflicts_with_all = ["every", "output", "keep", "off", "recipient", "plaintext"])]
    pub status: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ArchiveArg {
    /// The archive to read. Defaults to your newest archive.
    #[arg(value_name = "ARCHIVE")]
    pub archive: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct Verify {
    #[command(flatten)]
    pub target: ArchiveArg,

    /// Also restore the archive into a temporary directory and check that its keys match the
    /// identity it names.
    #[arg(long)]
    pub deep: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Restore {
    /// The archive to restore from. Not needed with `--words`.
    #[arg(value_name = "ARCHIVE", required_unless_present = "words")]
    pub archive: Option<PathBuf>,

    /// Restore even when the Radicle home already holds an identity, repositories, a node
    /// database or a config. What is there gets overwritten.
    #[arg(long)]
    pub force: bool,

    /// Skip comparing the restored repositories with the network.
    ///
    /// Other nodes may hold newer work of yours than the archive. Writing to a restored
    /// repository then forks your history. Before you write, clone each repository into a new,
    /// empty RAD_HOME to check what the network holds.
    ///
    /// Without this flag, a restore that could not do the comparison exits 3.
    #[arg(long)]
    pub no_reconcile: bool,

    /// Re-apply seeding and follow policies with `rad` commands instead of copying the policy
    /// database. Use this when the installed Radicle cannot read the archived database.
    #[arg(long)]
    pub replay_policies: bool,

    /// Rebuild the key from a recovery sheet's 24 words instead of from an archive.
    ///
    /// This restores only your identity key. It brings back no policies and no repositories.
    /// Use it when you have the recovery sheet and no archive.
    #[arg(long, conflicts_with = "archive")]
    pub words: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Doctor {
    /// The directory to look in. Defaults to RAD_BACKUP_DIR, then the directory of your last
    /// archive.
    ///
    /// `--backup-dir` is an older name for this option and still works.
    #[arg(
        long,
        short = 'd',
        alias = "backup-dir",
        value_name = "PATH",
        env = "RAD_BACKUP_DIR"
    )]
    pub dir: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct Paper {
    /// Where to write the sheet. Defaults to stdout. RAD_BACKUP_DIR is not consulted.
    //
    // Not read from `RAD_BACKUP_DIR`, unlike the other `--output` flags: that variable names a
    // directory to keep archives in, and honouring it here wrote the sheet to a file named
    // after somebody's archive directory, skipping the refusal that keeps a key off a terminal
    // because stdout was no longer the destination.
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Put the key on the sheet as 24 words instead of the key file.
    ///
    /// The words are your key with no passphrase on it. Keep the sheet as safe as cash. You
    /// can restore from the words alone, and they survive a bad photocopy.
    #[arg(long)]
    pub words: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Migrate {
    /// Where to write the archive to copy to the other machine.
    #[arg(value_name = "PATH")]
    pub output: PathBuf,

    /// Keep the key usable on this machine.
    ///
    /// By default the move renames the key on this machine, so no node here can start with
    /// it. Two nodes running with the same key fork your identity. Only use this flag if you
    /// will never run both.
    #[arg(long)]
    pub keep_source: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Completions {
    /// The shell to write completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierArg {
    /// Your keys and config. Nothing else can give these back.
    Identity,
    /// Keys, config, seeding and follow policies, peer aliases, the list of repositories you
    /// store, and your private repositories.
    State,
    /// Everything in `state`, plus all your own repositories.
    Full,
}

impl From<TierArg> for Tier {
    fn from(tier: TierArg) -> Self {
        match tier {
            TierArg::Identity => Self::Identity,
            TierArg::State => Self::State,
            TierArg::Full => Self::Full,
        }
    }
}

impl TierArg {
    /// What each tier carries when the user did not say. State takes private repositories
    /// because nothing else on earth has them; full takes everything of yours.
    pub fn default_repos(self) -> RepoSelection {
        match self {
            Self::Identity => RepoSelection::None,
            Self::State => RepoSelection::Private,
            Self::Full => RepoSelection::Mine,
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReposArg {
    None,
    Private,
    Mine,
    Seeded,
    All,
}

impl From<ReposArg> for RepoSelection {
    fn from(repos: ReposArg) -> Self {
        match repos {
            ReposArg::None => Self::None,
            ReposArg::Private => Self::Private,
            ReposArg::Mine => Self::Mine,
            ReposArg::Seeded => Self::Seeded,
            ReposArg::All => Self::All,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    /// clap_mangen renders these only with its `env` feature, which is off by default. Without
    /// it the man page loses every `RAD_BACKUP_*` line and says nothing about it, so the loss
    /// is invisible until somebody reads `man rad-backup` looking for the variable. The list
    /// is walked off the command rather than written out here, so a new `env = ` argument is
    /// covered from the moment it is added.
    #[test]
    fn every_option_that_reads_an_environment_variable_says_so_in_the_man_page() {
        let command = Cli::command();
        let man = String::from_utf8(crate::man::render().expect("the man page renders"))
            .expect("roff is text");

        // The page documents the top level's options, then each command's own, except
        // `create`'s, which are the top level's.
        let own = |arg: &&clap::Arg| !arg.is_hide_set() && !arg.is_global_set();
        let documented = command.get_arguments().chain(
            command
                .get_subcommands()
                .filter(|verb| verb.get_name() != "create")
                .flat_map(|verb| verb.get_arguments().filter(own)),
        );
        let mut expected: Vec<String> = documented
            .filter_map(|arg| arg.get_env())
            .map(|var| var.to_string_lossy().into_owned())
            .collect();
        expected.sort();
        assert!(
            expected.len() > 5,
            "only {} options read an environment variable, so this test guards little",
            expected.len()
        );
        let mut variables = expected.clone();
        variables.dedup();
        for var in &variables {
            let said = format!("\\fB{var}\\fR environment variable");
            assert_eq!(
                man.matches(&said).count(),
                expected.iter().filter(|each| *each == var).count(),
                "the man page does not say {var} once for each option that reads it"
            );
        }
    }

    /// A flag whose help names a `RAD_BACKUP_*` variable has to declare one, so that `--help`
    /// and the man page say which flags read the environment.
    ///
    /// `prune --dir` and `doctor --dir` both promised `RAD_BACKUP_DIR` in their help while
    /// declaring no `env` at all. They honoured it anyway, because the command reads the
    /// variable itself when the flag is absent, so the behaviour was right and only the
    /// documentation was wrong: `man rad-backup` listed the variable under `ls --dir` and not
    /// under theirs, so a reader of the prune entry concluded it was not honoured there.
    ///
    /// Which variable is not asserted, because a help text may name one it does not read:
    /// `--passphrase-file` describes the whole precedence chain, `RAD_BACKUP_PASSPHRASE`
    /// included, while reading only `RAD_BACKUP_PASSPHRASE_FILE`.
    #[test]
    fn every_flag_that_names_an_environment_variable_declares_one() {
        fn walk(command: &clap::Command, checked: &mut usize) {
            for arg in command.get_arguments() {
                let help = format!(
                    "{} {}",
                    arg.get_help()
                        .map(|help| help.to_string())
                        .unwrap_or_default(),
                    arg.get_long_help()
                        .map(|help| help.to_string())
                        .unwrap_or_default()
                );
                // The one flag that names the variable in order to say it is not consulted.
                if !help.contains("RAD_BACKUP_") || help.contains("not consulted") {
                    continue;
                }
                assert!(
                    arg.get_env().is_some(),
                    "`{} --{}` names a RAD_BACKUP_ variable in its help but declares no `env`, \
                     so neither --help nor the man page says it reads one",
                    command.get_name(),
                    arg.get_id()
                );
                *checked += 1;
            }
            for sub in command.get_subcommands() {
                walk(sub, checked);
            }
        }

        let mut checked = 0;
        walk(&Cli::command(), &mut checked);
        assert!(
            checked > 0,
            "no help text names a RAD_BACKUP_ variable, so this test guards nothing"
        );
    }

    #[test]
    fn running_with_no_subcommand_creates_an_archive() {
        let cli = Cli::parse_from(["rad-backup", "--tier", "full"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.create.tier, TierArg::Full);
    }

    #[test]
    fn each_tier_carries_the_repositories_it_promises() {
        assert_eq!(TierArg::Identity.default_repos(), RepoSelection::None);
        assert_eq!(TierArg::State.default_repos(), RepoSelection::Private);
        assert_eq!(TierArg::Full.default_repos(), RepoSelection::Mine);
    }

    #[test]
    fn started_as_rad_restore_the_program_is_already_at_the_restore_verb() {
        let called = invocation_as_called(
            ["/usr/bin/rad-restore", "--yes", "archive.tar.zst.age"]
                .into_iter()
                .map(OsString::from),
        );
        assert_eq!(
            called.argv,
            [
                "/usr/bin/rad-restore",
                "restore",
                "--yes",
                "archive.tar.zst.age"
            ]
            .map(OsString::from)
            .to_vec()
        );

        assert_eq!(called.bin_name, Some("rad"));

        let untouched = ["/usr/bin/rad-backup", "doctor"]
            .map(OsString::from)
            .to_vec();
        let called = invocation_as_called(untouched.clone().into_iter());
        assert_eq!(called.argv, untouched);
        assert_eq!(called.bin_name, None);
    }

    #[test]
    fn a_global_flag_may_come_before_a_subcommand_the_way_every_other_tool_allows() {
        for argv in [
            ["rad-backup", "--home", "/srv/radicle", "doctor"],
            ["rad-backup", "doctor", "--home", "/srv/radicle"],
        ] {
            let matches = Cli::command()
                .try_get_matches_from(argv)
                .expect("a global flag is allowed in either position");
            assert_eq!(misplaced_create_flag_complaint(&matches), None);
            let cli = Cli::from_arg_matches(&matches).expect("it parses into the struct");
            assert_eq!(cli.global.home, Some(PathBuf::from("/srv/radicle")));
        }
    }

    #[test]
    fn a_flag_that_shapes_an_archive_is_refused_by_a_verb_that_makes_none() {
        let matches = Cli::command()
            .try_get_matches_from(["rad-backup", "--tier", "full", "doctor"])
            .expect("clap itself allows it; the rule is ours");
        let complaint = misplaced_create_flag_complaint(&matches).expect("it is refused");
        assert!(complaint.contains("--tier"), "{complaint}");
        assert!(complaint.contains("doctor"), "{complaint}");
    }

    #[test]
    fn a_shaping_flag_from_the_environment_never_refuses_another_verb() {
        // RAD_BACKUP_TIER is set for every run in a shell that exports it; failing `doctor`
        // because of it would make the variable unusable.
        let matches = Cli::command()
            .try_get_matches_from(["rad-backup", "doctor"])
            .expect("it parses");
        assert_eq!(
            matches.value_source("tier"),
            Some(ValueSource::DefaultValue)
        );
        assert_eq!(misplaced_create_flag_complaint(&matches), None);
    }

    #[test]
    fn the_recovery_sheet_does_not_take_its_path_from_the_archive_directory() {
        let command = Cli::command();
        let paper = command
            .find_subcommand("paper")
            .expect("`paper` is a subcommand");
        let output = paper
            .get_arguments()
            .find(|arg| arg.get_id() == "output")
            .expect("`paper` has an --output");
        // RAD_BACKUP_DIR names a directory to keep archives in. Read here it became the file
        // path of a sheet holding the key as 24 words, and took the run off the stdout path
        // where the refusal to print a key at a terminal lives.
        assert_eq!(output.get_env(), None);
    }

    #[test]
    fn the_archive_and_the_json_report_cannot_both_own_stdout() {
        // Accepted, they interleaved: the JSON report went out after the archive bytes, so
        // `rad-backup --stdout --json > x.age` produced a file age refuses at restore time.
        assert!(Cli::try_parse_from(["rad-backup", "--stdout", "--json"]).is_err());
    }

    /// clap files every field declared after the `Global` flatten under its heading, so a
    /// top-level flag added below it would be listed as working with every command.
    #[test]
    fn only_a_global_option_is_listed_under_the_global_heading() {
        let command = Cli::command();
        let mut checked = 0;
        for arg in command.get_arguments() {
            if arg.get_help_heading() == Some("Global options") {
                assert!(arg.is_global_set(), "--{} is not global", arg.get_id());
                checked += 1;
            }
        }
        assert!(checked > 5, "only {checked} options are under the heading");
    }

    /// `--help` ends with who makes this, where its issues go and how to support it. `-h` is
    /// for looking up a flag, and so is every command's own help.
    #[test]
    fn only_the_top_level_long_help_ends_with_the_credits() {
        let mut command = Cli::command();
        let long = command.render_long_help().to_string();
        assert!(
            long.trim_end()
                .ends_with(crate::credits::help_footer().as_str()),
            "{long}"
        );
        assert!(
            !command
                .render_help()
                .to_string()
                .contains(crate::credits::DONATE)
        );
        let mut checked = 0;
        // Built, so each command carries the global options its own arguments refer to.
        let mut built = Cli::command();
        built.build();
        for verb in built.get_subcommands() {
            let mut verb = verb.clone();
            let help = verb.render_long_help().to_string();
            assert!(
                !help.contains(crate::credits::DONATE),
                "`{}`: {help}",
                verb.get_name()
            );
            checked += 1;
        }
        assert!(checked > 10, "only {checked} commands were looked at");
    }

    #[test]
    fn the_archive_shaping_flags_are_the_ones_create_declares_and_no_others() {
        let flags = create_only_flag_ids();

        // Derived from `Create`, not from the top-level command: a global belongs before any
        // verb, and reporting `--home doctor` as a misplaced archive flag would be worse than
        // the drift this replaced.
        for global in ["home", "json", "yes", "quiet", "passphrase_file"] {
            assert!(
                !flags.iter().any(|id| id == global),
                "{global} in {flags:?}"
            );
        }
        for shaping in ["tier", "repos", "recipient", "stdout", "dry_run"] {
            assert!(
                flags.iter().any(|id| id == shaping),
                "{shaping} in {flags:?}"
            );
        }
    }

    #[test]
    fn a_create_flag_before_the_create_verb_is_told_where_it_belongs() {
        let matches = Cli::command().get_matches_from(["rad-backup", "--tier", "full", "create"]);
        let complaint = misplaced_create_flag_complaint(&matches).expect("it is refused");
        // Not "`create` does not create an archive", which is what the general wording said
        // here and which is nonsense. The flag cannot be allowed through either: the
        // subcommand's own defaulted copy is the one dispatch reads, so it would be ignored.
        assert!(complaint.contains("belongs after `create`"), "{complaint}");
    }

    #[test]
    fn a_flag_the_verb_itself_has_is_told_where_it_belongs_rather_than_denied() {
        let matches = Cli::command().get_matches_from(["rad-backup", "--output", "/x", "schedule"]);
        let complaint = misplaced_create_flag_complaint(&matches).expect("it is refused");
        // `schedule --output` is a real flag. "`schedule` does not create one" is what the
        // general wording said, and it reads as a denial of a flag the verb documents.
        assert!(
            complaint.contains("belongs after `schedule`"),
            "{complaint}"
        );
    }

    #[test]
    fn a_flag_the_verb_does_not_have_is_denied_rather_than_relocated() {
        let matches = Cli::command().get_matches_from(["rad-backup", "--tier", "full", "doctor"]);
        let complaint = misplaced_create_flag_complaint(&matches).expect("it is refused");
        assert!(
            complaint.contains("`doctor` does not create one"),
            "{complaint}"
        );
    }

    #[test]
    fn stdout_and_an_output_path_cannot_both_be_asked_for() {
        let parsed = Cli::try_parse_from(["rad-backup", "--stdout", "--output", "/tmp/x"]);
        assert!(parsed.is_err());
    }
}
