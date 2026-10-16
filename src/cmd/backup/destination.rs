//! Where an archive goes, written under a `.partial` name until it is complete.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::archives::{archive_name, file_stamp};
use crate::cli::Create;
use crate::crypt::Encryption;
use crate::error::{Error, Result};
use crate::key::Identity;
use crate::perms::create_private_file;
use crate::term::Term;

/// Where the archive goes.
///
/// A file is written under a `.partial` name and renamed once complete, so an interrupted run
/// never leaves something that looks like a usable backup.
pub(super) enum Destination {
    Stdout,
    File {
        final_path: PathBuf,
        partial_path: PathBuf,
        committed: std::cell::Cell<bool>,
    },
}

/// Removes the `.partial` of an uncommitted archive, because nothing lists or prunes those.
///
/// A signal kills the process without running this, so Ctrl-C mid-write leaves the `.partial`
/// until the next run to the same destination overwrites it. Revisit if this tool ever grows a
/// signal handler.
impl Drop for Destination {
    fn drop(&mut self) {
        if let Self::File {
            partial_path,
            committed,
            ..
        } = self
            && !committed.get()
        {
            let _ = std::fs::remove_file(partial_path);
        }
    }
}

impl Destination {
    pub(super) fn directory(&self) -> Option<PathBuf> {
        match self {
            Self::Stdout => None,
            Self::File { final_path, .. } => final_path.parent().map(Path::to_path_buf),
        }
    }

    pub(super) fn open(&self) -> Result<Box<dyn Write>> {
        match self {
            Self::Stdout => Ok(Box::new(std::io::stdout())),
            Self::File { partial_path, .. } => Ok(Box::new(create_private_file(partial_path)?)),
        }
    }

    pub(super) fn commit(&self, term: &Term) -> Result<Option<PathBuf>> {
        match self {
            Self::Stdout => Ok(None),
            Self::File {
                final_path,
                partial_path,
                committed,
            } => {
                // `Write::flush` on a `File` is a no-op, so without `sync_all` the rename
                // can land before the bytes and a crash leaves an empty finished file. The
                // handle is writable, because Windows refuses to flush a read-only one.
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(partial_path)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| Error::io(partial_path, e))?;
                std::fs::rename(partial_path, final_path).map_err(|e| Error::io(final_path, e))?;
                sync_directory(term, final_path.parent());
                committed.set(true);
                Ok(Some(final_path.clone()))
            }
        }
    }
}

/// Fsyncs the directory, so the rename survives a crash.
///
/// Unix only, because no portable call opens a directory as a file and NTFS orders the rename
/// after the file's flushed data. A failure prints a warning, because durability is the point.
fn sync_directory(term: &Term, directory: Option<&Path>) {
    #[cfg(unix)]
    {
        if let Some(directory) = directory
            && let Err(error) = std::fs::File::open(directory).and_then(|dir| dir.sync_all())
        {
            term.warn(&format!(
                "{}: the directory entry could not be flushed, so a crash now could lose the \
                 archive that was just written ({error})",
                directory.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (term, directory);
    }
}

pub(super) fn prepare(
    args: &Create,
    identity: &Identity,
    alias: Option<&str>,
    now: &jiff::Timestamp,
    encryption: &Encryption,
    stdout_is_terminal: bool,
) -> Result<Destination> {
    if args.stdout {
        // A terminal keeps what it shows in scrollback that no zeroized buffer reaches, and a
        // `--plaintext` archive holds the key. `stdout_is_terminal` is a parameter so a test
        // reaches both answers.
        if stdout_is_terminal {
            return Err(Error::refused(
                "an archive is binary, and stdout is a terminal",
                "redirect it to a file or pipe it into something, or drop --stdout",
            ));
        }
        return Ok(Destination::Stdout);
    }
    let name = archive_name(
        alias,
        &identity.node_id(),
        &file_stamp(*now),
        encryption.is_encrypted(),
    );
    let requested = args.output.clone().unwrap_or_else(|| PathBuf::from("."));

    let final_path = if names_an_archive(&requested) {
        if let Some(parent) = requested.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        requested
    } else {
        std::fs::create_dir_all(&requested).map_err(|e| Error::io(&requested, e))?;
        requested.join(name)
    };
    let partial_path = final_path.with_extension("partial");
    Ok(Destination::File {
        final_path,
        partial_path,
        committed: std::cell::Cell::new(false),
    })
}

/// Whether `path` names the archive itself, judged by its extension unless it is an existing
/// directory.
///
/// A bare name counts as a directory, because one archive written where the user expects a
/// folder gets silently replaced by the next run.
fn names_an_archive(path: &Path) -> bool {
    const ARCHIVE_SUFFIXES: [&str; 3] = [".age", ".zst", ".tar"];

    if path.is_dir() {
        return false;
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    ARCHIVE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_output_gets_a_generated_name() {
        let identity = Identity::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfJT4YlvXMI9h98D4SSswNV5S0voNrQaUZMCq0s0zK",
        )
        .expect("the vector parses");
        let now = jiff::Timestamp::from_second(1_786_000_000).expect("a valid instant");

        let into_directory = Create {
            output: Some(PathBuf::from("/tmp")),
            ..blank_create()
        };
        let destination = prepare(
            &into_directory,
            &identity,
            Some("maninak"),
            &now,
            &Encryption::Plaintext,
            false,
        )
        .expect("a directory is a destination");
        match destination {
            Destination::File { ref final_path, .. } => {
                assert!(final_path.starts_with("/tmp"));
                assert!(
                    final_path
                        .file_name()
                        .expect("it has a name")
                        .to_string_lossy()
                        .starts_with("maninak-z6MkvAFBkdph-")
                );
            }
            Destination::Stdout => panic!("a path is not stdout"),
        }
    }

    #[test]
    fn a_path_is_a_directory_unless_it_is_named_like_an_archive() {
        assert!(names_an_archive(Path::new("/backups/mine.tar.zst")));
        assert!(names_an_archive(Path::new("/backups/mine.tar.zst.age")));
        assert!(names_an_archive(Path::new("mine.age")));
        // Directories that do not exist yet, named like directories
        assert!(!names_an_archive(Path::new("/backups")));
        assert!(!names_an_archive(Path::new("backups/radicle")));
        assert!(!names_an_archive(Path::new("/tmp")));
    }

    #[test]
    fn an_archive_is_refused_to_a_terminal_and_allowed_to_a_pipe() {
        let identity = Identity::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfJT4YlvXMI9h98D4SSswNV5S0voNrQaUZMCq0s0zK",
        )
        .expect("the vector parses");
        let now = jiff::Timestamp::from_second(1_786_000_000).expect("a valid instant");
        let args = Create {
            stdout: true,
            ..blank_create()
        };

        // A terminal keeps the bytes in scrollback, so the archive never goes there.
        // `matches!` avoids needing Debug on Destination.
        let refused = prepare(&args, &identity, None, &now, &Encryption::Plaintext, true);
        assert!(
            matches!(refused, Err(Error::Refused { .. })),
            "a terminal should be refused"
        );

        // A pipe or a redirect is the whole point of --stdout and must keep working
        let allowed = prepare(&args, &identity, None, &now, &Encryption::Plaintext, false)
            .expect("a pipe is a destination");
        assert!(matches!(allowed, Destination::Stdout));
    }

    #[test]
    fn asking_for_stdout_never_touches_the_filesystem() {
        let identity = Identity::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfJT4YlvXMI9h98D4SSswNV5S0voNrQaUZMCq0s0zK",
        )
        .expect("the vector parses");
        let now = jiff::Timestamp::from_second(1_786_000_000).expect("a valid instant");
        let args = Create {
            stdout: true,
            ..blank_create()
        };
        let destination = prepare(&args, &identity, None, &now, &Encryption::Plaintext, false)
            .expect("stdout is a destination");
        assert!(matches!(destination, Destination::Stdout));
        assert!(destination.directory().is_none());
    }

    fn blank_create() -> Create {
        Create {
            output: None,
            tier: crate::cli::TierArg::State,
            repos: None,
            stdout: false,
            plaintext: false,
            recipient: Vec::new(),
            stop_node: false,
            with_node_db: false,
            keep: None,
            dry_run: false,
        }
    }
}
