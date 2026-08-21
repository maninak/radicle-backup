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
                  Installed on PATH, this is also `rad backup`.",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Arguments for creating an archive, which is what running with no subcommand does.
    #[command(flatten)]
    pub create: Create,

    #[command(flatten)]
    pub global: Global,
}

/// The flags that shape an archive, and so mean nothing to any other verb.
const CREATE_ONLY: [&str; 10] = [
    "output",
    "tier",
    "repos",
    "stdout",
    "plaintext",
    "recipient",
    "stop_node",
    "with_node_db",
    "keep",
    "dry_run",
];

/// Parse the command line, then enforce the one rule clap cannot state here.
///
/// `args_conflicts_with_subcommands` would reject `--tier full doctor`, which is right, but
/// it also rejects `--home /srv/radicle doctor`, which is how every other tool in this
/// ecosystem is used. So the global flags stay usable in either position and the
/// archive-shaping ones are checked by hand.
pub fn parse() -> Cli {
    let called = as_called(std::env::args_os());
    let mut command = Cli::command();
    if let Some(name) = called.bin_name {
        command = command.bin_name(name);
    }
    let matches = command.get_matches_from(called.argv);
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    if let Some(problem) = misplaced_create_flag(&matches) {
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
fn as_called<I: Iterator<Item = OsString>>(args: I) -> Invocation {
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
fn misplaced_create_flag(matches: &ArgMatches) -> Option<String> {
    let verb = matches.subcommand_name()?;
    let id = CREATE_ONLY
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
        "`--{flag}` shapes an archive, and `{verb}` does not create one"
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
    /// The Radicle home to work on. Defaults to RAD_HOME, then ~/.radicle.
    #[arg(long, global = true, value_name = "PATH")]
    pub home: Option<PathBuf>,

    /// Report as JSON on stdout instead of prose on stderr.
    #[arg(long, global = true)]
    pub json: bool,

    /// Answer every prompt with yes. What a cron job wants.
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Print nothing but errors.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Never colour the output. NO_COLOR is honoured too.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Where to put working files: database snapshots, freshly built bundles, and the
    /// staging copy a restore is checked in.
    ///
    /// The default is beside whatever the command is producing, which is a filesystem the
    /// user already chose and which has room for the result. Point this elsewhere when that
    /// filesystem is small, read-only, or somewhere a private repository should not appear
    /// even briefly.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "RAD_BACKUP_SCRATCH_DIR"
    )]
    pub scratch_dir: Option<PathBuf>,

    /// Read the archive passphrase from a file instead of asking for it.
    ///
    /// A file is checked first, then RAD_BACKUP_PASSPHRASE, then a hidden prompt. Prefer the
    /// file: an environment variable is readable by anything that can see the process.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "RAD_BACKUP_PASSPHRASE_FILE"
    )]
    pub passphrase_file: Option<PathBuf>,

    /// An age or ssh private key file to decrypt an archive that was encrypted to a key.
    #[arg(long, global = true, value_name = "PATH", action = ArgAction::Append)]
    pub identity: Vec<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create an archive. The default when no subcommand is given.
    Create(Create),

    /// Restore a Radicle home from an archive.
    Restore(Restore),

    /// Check that an archive is complete, readable and holds the identity it claims.
    Verify(Verify),

    /// List the archives of this identity, newest first.
    #[command(visible_alias = "list")]
    Ls(Ls),

    /// Show what is inside an archive.
    #[command(visible_alias = "inspect")]
    Show(Target),

    /// Delete older archives of this identity, keeping the newest few.
    Prune(Prune),

    /// Take an archive automatically, on a timer.
    Schedule(Schedule),

    /// Report how recoverable this identity currently is.
    Doctor(Doctor),

    /// Render a printable recovery sheet.
    Paper(Paper),

    /// Move this identity to another machine.
    #[command(name = "move")]
    Migrate(Migrate),

    /// Show what changed since the last archive was taken.
    Diff,

    /// Write shell completions to stdout.
    Completions(Completions),

    /// Write the manual page to stdout.
    Man,
}

#[derive(Parser, Debug, Clone)]
pub struct Create {
    /// Where to write the archive. A path ending in `.tar.zst`, `.age` or `.tar` names the
    /// file; anything else is a directory, created if it is missing, and the archive is named
    /// inside it. Defaults to the working directory, or to RAD_BACKUP_DIR when it is set.
    #[arg(long, short = 'o', value_name = "PATH", env = "RAD_BACKUP_DIR")]
    pub output: Option<PathBuf>,

    /// How much of the home to carry.
    #[arg(long, value_enum, default_value_t = TierArg::State, env = "RAD_BACKUP_TIER")]
    pub tier: TierArg,

    /// Which repositories to carry. Defaults to what the tier implies.
    #[arg(long, value_enum, value_name = "WHICH")]
    pub repos: Option<ReposArg>,

    /// Write the archive to stdout, for piping into restic, borg or ssh.
    ///
    /// Refuses `--json` because both write to stdout, and a JSON report glued onto the end of
    /// an age stream is an archive that decrypts, fails to decompress, and says so only on
    /// the day somebody needs it back.
    #[arg(long, conflicts_with = "output", conflicts_with = "json")]
    pub stdout: bool,

    /// Do not encrypt. The archive will hold your private key in the clear.
    #[arg(long, conflicts_with = "recipient")]
    pub plaintext: bool,

    /// Encrypt to an age or ssh public key instead of to a passphrase. Repeatable.
    #[arg(long, value_name = "KEY", action = ArgAction::Append)]
    pub recipient: Vec<String>,

    /// Stop the node before reading storage, and start it again afterwards.
    #[arg(long)]
    pub stop_node: bool,

    /// Include the routing table and address book, which otherwise regenerate from gossip.
    #[arg(long)]
    pub with_node_db: bool,

    /// Delete older archives of this identity in the output directory, keeping this many.
    #[arg(long, value_name = "N", env = "RAD_BACKUP_KEEP")]
    pub keep: Option<usize>,

    /// Say what would be carried, and how much of it, without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Ls {
    /// Where to look. Defaults to RAD_BACKUP_DIR, then wherever the last archive went.
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

    /// Where to prune. Defaults to RAD_BACKUP_DIR, then wherever the last archive went.
    #[arg(long, short = 'd', value_name = "PATH")]
    pub dir: Option<PathBuf>,

    /// List what would be deleted, and delete nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Schedule {
    /// How often to take one: `daily`, `weekly`, `hourly`, or any systemd calendar
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
    /// The reason a timer can exist without a passphrase file at all: nothing has to be
    /// unlocked to write to a recipient, so an unattended run has nothing to be asked for.
    #[arg(long, value_name = "KEY", action = ArgAction::Append)]
    pub recipient: Vec<String>,

    /// Do not encrypt the scheduled archives. They will hold your private key in the clear.
    #[arg(long, conflicts_with = "recipient")]
    pub plaintext: bool,

    /// Turn the timer off again. The unit files are left in place.
    #[arg(long, conflicts_with_all = ["every", "output", "keep", "recipient", "plaintext"])]
    pub off: bool,

    /// Say whether it is on, and when it next runs, without changing anything.
    #[arg(long, conflicts_with_all = ["every", "output", "keep", "off", "recipient", "plaintext"])]
    pub status: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Target {
    /// The archive to read. Defaults to the newest one this tool knows about.
    #[arg(value_name = "ARCHIVE")]
    pub archive: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct Verify {
    #[command(flatten)]
    pub target: Target,

    /// Restore into a throwaway home and prove that it comes back as the same identity.
    #[arg(long)]
    pub deep: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Restore {
    /// The archive to read. Not needed with `--words`, which rebuilds the key from a
    /// recovery sheet and has no archive to read.
    #[arg(value_name = "ARCHIVE", required_unless_present = "words")]
    pub archive: Option<PathBuf>,

    /// Restore into a home that already holds an identity, overwriting what is there.
    #[arg(long)]
    pub force: bool,

    /// Skip the check that compares restored repositories with the network.
    ///
    /// Building on a restored repository whose signed refs are behind what the network holds
    /// forks your own history. Only skip this offline, and fetch before you push.
    #[arg(long)]
    pub no_reconcile: bool,

    /// Re-apply seeding and following policies through `rad` instead of copying the database.
    /// For restoring into a Radicle whose schema has moved on.
    #[arg(long)]
    pub replay_policies: bool,

    /// Rebuild the key from a recovery sheet's 24 words instead of from an archive.
    ///
    /// This brings back the identity and nothing else: no policies, no repositories. It is
    /// the path for someone who has the sheet and no archive at all.
    #[arg(long, conflicts_with = "archive")]
    pub words: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Doctor {
    /// Where archives of this identity are kept, for judging how old the newest one is.
    #[arg(long, value_name = "PATH")]
    pub backup_dir: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct Paper {
    /// Where to write the sheet. Defaults to stdout.
    ///
    /// Deliberately not read from `RAD_BACKUP_DIR`, unlike the other `--output` here: that
    /// variable names a directory to keep archives in, and honouring it here wrote the sheet
    /// to a file named after somebody's archive directory, skipping the refusal that keeps a
    /// key off a terminal because stdout was no longer the destination.
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Print the key as 24 words instead of as its encrypted file.
    ///
    /// This decrypts the key, so the sheet must be stored the way cash is stored. In exchange
    /// it needs nothing but itself to restore, and words survive a bad photocopy.
    #[arg(long)]
    pub words: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Migrate {
    /// Where to write the archive the other machine will read.
    #[arg(value_name = "PATH")]
    pub output: PathBuf,

    /// Do not retire the key on this machine.
    ///
    /// Two nodes running one key fork the identity they share, so the source is retired by
    /// default and this flag is for someone who has thought about it.
    #[arg(long)]
    pub keep_source: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct Completions {
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierArg {
    /// Keys and config: the bytes nothing can give back.
    Identity,
    /// Keys, config, policies, aliases, inventory, and any repository the network does not
    /// have a copy of.
    State,
    /// All of the above, plus every repository that is yours.
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

    /// clap_mangen renders these only with its `env` feature, which 0.3 introduced and
    /// defaults off. Without it the man page loses every `RAD_BACKUP_*` line and says nothing
    /// about it, so the loss is invisible until somebody reads `man rad-backup` looking for
    /// the variable. The list is walked off the command rather than written out here, so a
    /// new `env = ` argument is covered from the moment it is added.
    #[test]
    fn every_option_that_reads_an_environment_variable_says_so_in_the_man_page() {
        let command = Cli::command();
        let mut rendered = Vec::new();
        clap_mangen::Man::new(command.clone())
            .render(&mut rendered)
            .expect("the man page renders");
        let man = String::from_utf8(rendered).expect("roff is text");

        let variables: Vec<_> = command
            .get_arguments()
            .filter_map(|arg| arg.get_env())
            .map(|var| var.to_string_lossy().into_owned())
            .collect();
        assert!(
            !variables.is_empty(),
            "no argument reads an environment variable, so this test guards nothing"
        );
        for var in &variables {
            assert!(man.contains(var), "the man page never mentions {var}");
        }
        assert!(
            man.matches("environment variable").count() >= variables.len(),
            "the man page names fewer environment variables than the command reads"
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
        let called = as_called(
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
        let called = as_called(untouched.clone().into_iter());
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
            assert_eq!(misplaced_create_flag(&matches), None);
            let cli = Cli::from_arg_matches(&matches).expect("it parses into the struct");
            assert_eq!(cli.global.home, Some(PathBuf::from("/srv/radicle")));
        }
    }

    #[test]
    fn a_flag_that_shapes_an_archive_is_refused_by_a_verb_that_makes_none() {
        let matches = Cli::command()
            .try_get_matches_from(["rad-backup", "--tier", "full", "doctor"])
            .expect("clap itself allows it; the rule is ours");
        let complaint = misplaced_create_flag(&matches).expect("it is refused");
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
        assert_eq!(misplaced_create_flag(&matches), None);
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

    #[test]
    fn a_create_flag_before_the_create_verb_is_told_where_it_belongs() {
        let matches = Cli::command().get_matches_from(["rad-backup", "--tier", "full", "create"]);
        let complaint = misplaced_create_flag(&matches).expect("it is refused");
        // Not "`create` does not create an archive", which is what the general wording said
        // here and which is nonsense. The flag cannot simply be allowed either: the
        // subcommand's own defaulted copy is the one dispatch reads, so it would be ignored.
        assert!(complaint.contains("belongs after `create`"), "{complaint}");
    }

    #[test]
    fn a_flag_the_verb_itself_has_is_told_where_it_belongs_rather_than_denied() {
        let matches = Cli::command().get_matches_from(["rad-backup", "--output", "/x", "schedule"]);
        let complaint = misplaced_create_flag(&matches).expect("it is refused");
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
        let complaint = misplaced_create_flag(&matches).expect("it is refused");
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
