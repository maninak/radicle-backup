//! One error type for the whole tool, and the exit codes it maps to.
//!
//! Exit codes are part of the interface: cron jobs and CI steps branch on them, so they are
//! documented in the README and must not be renumbered.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub type Result<T> = std::result::Result<T, Error>;

/// Exit code for a run that found problems but did not itself fail: a failed verification, a
/// doctor report with at least one failing check, a diff that found drift.
pub const EXIT_CHECKS_FAILED: u8 = 3;
/// Exit code for a run that stopped on purpose to avoid destroying something.
pub const EXIT_REFUSED: u8 = 4;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    #[error("{0}")]
    Bare(#[from] io::Error),

    #[error("could not run `{program}`: {source}\nis it installed and on PATH?")]
    Spawn { program: String, source: io::Error },

    #[error("`{command}` failed with {status}\n{stderr}")]
    Command {
        command: String,
        status: String,
        stderr: String,
    },

    #[error("{path}: not a Radicle home (no keys/radicle)\npass --home, or set RAD_HOME")]
    NotAHome { path: PathBuf },

    #[error("{path}: {reason}")]
    BadKey { path: PathBuf, reason: String },

    #[error("this is a {algorithm} key; Radicle identities are ed25519")]
    NotEd25519 { algorithm: String },

    #[error("wrong passphrase")]
    WrongPassphrase,

    #[error("{path} is not a rad-backup archive: {reason}")]
    NotAnArchive { path: PathBuf, reason: String },

    #[error(
        "archive format v{found} was written by a newer rad-backup; this build reads up to v{supported}"
    )]
    ArchiveTooNew { found: u32, supported: u32 },

    /// A deliberate stop, not a failure. Carries what the user should do next.
    #[error("{what}\n{remedy}")]
    Refused { what: String, remedy: String },

    #[error("{0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("{0}")]
    Age(String),

    #[error("{0}")]
    Ssh(#[from] ssh_key::Error),
}

impl Error {
    pub fn io(path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    pub fn refused(what: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self::Refused {
            what: what.into(),
            remedy: remedy.into(),
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Refused { .. } => ExitCode::from(EXIT_REFUSED),
            _ => ExitCode::FAILURE,
        }
    }
}

impl From<age::EncryptError> for Error {
    fn from(e: age::EncryptError) -> Self {
        Self::Age(e.to_string())
    }
}

impl From<age::DecryptError> for Error {
    fn from(e: age::DecryptError) -> Self {
        match e {
            // age reports a wrong passphrase as "no identity matched", which reads as a bug
            // report rather than as the typo it almost always is.
            age::DecryptError::NoMatchingKeys => Self::WrongPassphrase,
            // Every remaining variant means the ciphertext did not authenticate. With the
            // right passphrase that is damage, not a mistake, and saying so points at the
            // copy of the file rather than at the person typing.
            other => Self::Age(format!(
                "{other}: if the passphrase was right, this archive is damaged"
            )),
        }
    }
}
