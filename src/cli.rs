//! The command line.
//!
//! `rad` runs `rad-backup` for `rad backup`, so every verb here reads as the second word of a
//! `rad backup ...` sentence. Creating an archive is what an unqualified `rad backup` does,
//! because that is the thing people came for.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

use crate::manifest::{RepoSelection, Tier};

#[derive(Parser, Debug)]
#[command(
    name = "rad-backup",
    version,
    about = "Back up, restore and migrate a Radicle identity",
    long_about = "Back up, restore and migrate a Radicle identity, node state and repositories.\n\n\
                  Installed on PATH, this is also `rad backup`.",
    args_conflicts_with_subcommands = true,
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

    /// Read the archive passphrase from a file instead of asking for it.
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

    /// Show what is inside an archive.
    List(Target),

    /// Report how recoverable this identity currently is.
    Doctor(Doctor),

    /// Render a printable recovery sheet.
    Paper(Paper),

    /// Migrate this identity to another machine.
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
    #[arg(long, conflicts_with = "output")]
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

    /// Where to put working files while building the archive. Defaults to the output
    /// directory, so that nothing lands on a filesystem you did not choose.
    #[arg(long, value_name = "PATH")]
    pub scratch_dir: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct Target {
    /// The archive to read.
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,
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
    #[arg(long, short = 'o', value_name = "PATH", env = "RAD_BACKUP_DIR")]
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
    fn stdout_and_an_output_path_cannot_both_be_asked_for() {
        let parsed = Cli::try_parse_from(["rad-backup", "--stdout", "--output", "/tmp/x"]);
        assert!(parsed.is_err());
    }
}
