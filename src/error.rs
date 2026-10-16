//! The error type and its exit codes, which the README documents and scripts branch on, so
//! no code is ever renumbered.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub type Result<T> = std::result::Result<T, Error>;

/// Exit code for a run that found problems without failing itself, such as a failed
/// verification, a failing doctor check or a diff that found drift.
pub const EXIT_CHECKS_FAILED: u8 = 3;
/// Exit code for a run that stopped on purpose to avoid destroying something.
pub const EXIT_REFUSED: u8 = 4;
/// Exit code for a run that failed, as a number the tests can compare.
pub const EXIT_FAILURE: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    /// An io error with no file to attach it to. It has no `#[from]`, so `?` on an `io::Error`
    /// does not compile and a writer has to choose between this and `Io` with its path.
    #[error("{0}")]
    PathlessIo(io::Error),

    #[error(
        "could not run `{program}`: {source}\ncheck that {program} is installed and on your PATH"
    )]
    Spawn { program: String, source: io::Error },

    #[error("`{command}` failed with {status}\n{stderr}")]
    Command {
        command: String,
        status: String,
        stderr: String,
    },

    #[error(
        "no Radicle identity in {path}. The file keys/radicle is missing\nif your Radicle data is \
         somewhere else, pass --home <path> or set RAD_HOME. To create an identity, run `rad auth`"
    )]
    NotAHome { path: PathBuf },

    #[error("could not read the key at {path}: {reason}")]
    BadKey { path: PathBuf, reason: String },

    /// A file that is there and does not parse, named because a bare `serde_json::Error` names
    /// no file.
    #[error("{path}: {reason}")]
    Malformed { path: PathBuf, reason: String },

    #[error("this is a {algorithm} key. A Radicle identity key is ed25519")]
    NotEd25519 { algorithm: String },

    #[error("wrong passphrase")]
    WrongPassphrase,

    #[error("{path} is not a rad-backup archive: {reason}")]
    NotAnArchive { path: PathBuf, reason: String },

    #[error(
        "this archive was written by a newer rad-backup (archive format v{found})\nthis version \
         reads up to format v{supported}. Install a newer rad-backup to open it"
    )]
    ArchiveTooNew { found: u32, supported: u32 },

    /// A deliberate stop that leaves everything intact, with what the user should do next.
    #[error("{what}\n{remedy}")]
    Refused { what: String, remedy: String },

    /// Keys were offered and none was ever unlocked, so the archive was never tried. `doctor`
    /// reports this as a question it could not put, and never as a backup no key opens.
    #[error("{what}\n{remedy}")]
    KeysStayedLocked { what: String, remedy: String },

    /// A key was unlocked and still could not be used, which age reports alike for a wrong
    /// passphrase and an unsupported key type. This proves nothing about whether the archive
    /// can be opened.
    #[error("{what}\n{remedy}")]
    KeyNotUsable { what: String, remedy: String },

    /// The manual was asked for with stdout on a terminal, where roff is noise. A capture
    /// through a pty (`ssh -t`) would otherwise save this text as the page and report success.
    /// The message names no package, because a list compiled into the binary goes stale.
    #[error(
        "`rad-backup man` prints a file to save, not a page to read\n\
         to read the manual, run `man rad-backup`. If that finds no page, run:\n  \
         rad-backup man > ~/rad-backup.1 && man ~/rad-backup.1\n\
         `rad-backup --help` and `--help` after any command also show the options"
    )]
    ManAtATerminal,

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
    /// Formats this error as one line, each source line a sentence, for a warning that
    /// carries it as a `why` beside a repository id.
    pub fn one_line(&self) -> String {
        let text = self.to_string();
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        let last = lines.len().saturating_sub(1);
        lines
            .iter()
            .enumerate()
            .map(|(at, line)| {
                let mut sentence = match at {
                    0 => (*line).to_string(),
                    _ => capitalised(line),
                };
                if at < last && !sentence.ends_with(['.', ':', '?', '!']) {
                    sentence.push('.');
                }
                sentence
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

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

    /// Maps `Refused` to `EXIT_REFUSED` and everything else to `1`.
    ///
    /// A key that stayed locked or unusable exits `1`, because a script reading `4` as "safe
    /// to retry later" would loop on a typo.
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit_status())
    }

    /// The exit code as a number, because `ExitCode` cannot be compared in a test.
    pub fn exit_status(&self) -> u8 {
        match self {
            Self::Refused { .. } => EXIT_REFUSED,
            _ => EXIT_FAILURE,
        }
    }
}

fn capitalised(line: &str) -> String {
    let mut chars = line.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
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
            age::DecryptError::NoMatchingKeys => Self::WrongPassphrase,
            // Every remaining variant means the ciphertext did not authenticate, which with
            // the right passphrase is damage to the file
            other => Self::Age(format!(
                "{other}. If the passphrase was right, the archive is damaged"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `4` means nothing was written because going on was unsafe. A key that never unlocked,
    /// or one age could not use, exits `1`, so a script retrying on `4` does not loop on a
    /// typo.
    #[test]
    fn only_a_refusal_on_safety_grounds_exits_four() {
        let locked = Error::KeysStayedLocked {
            what: "it stayed locked".to_string(),
            remedy: "unlock it".to_string(),
        };
        let unusable = Error::KeyNotUsable {
            what: "it could not be used".to_string(),
            remedy: "check the passphrase".to_string(),
        };
        assert_eq!(locked.exit_status(), EXIT_FAILURE);
        assert_eq!(unusable.exit_status(), EXIT_FAILURE);
        assert_eq!(Error::WrongPassphrase.exit_status(), EXIT_FAILURE);
        assert_eq!(
            Error::refused("nothing was written", "decide, then run it again").exit_status(),
            EXIT_REFUSED
        );
    }
}
