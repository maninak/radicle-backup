//! Where an archive is going, and how it gets there without leaving rubble behind.
//!
//! Separate from the archiving itself because the choice is made before any bytes exist and
//! the cleanup happens after they stop: a `.partial` file that nothing lists and nothing
//! prunes is the one failure a backup tool must not leave lying around.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::archives::{archive_name, file_stamp};
use crate::cli::Create;
use crate::crypt::Encryption;
use crate::error::{Error, Result};
use crate::key::Identity;
use crate::perms::create_private;
use crate::term::Term;

/// Where the archive is going, and how it gets there safely.
///
/// A file is written under a `.partial` name and renamed once it is complete, so an
/// interrupted run cannot leave something that looks like a usable backup.
///
/// The `.partial` is removed on drop when it was never committed. Nothing lists or prunes
/// those files, so every failed run left one behind: a directory of encrypted-looking rubble
/// beside the real archives, growing without limit and impossible to tell apart by eye.
pub(super) enum Destination {
    Stdout,
    File {
        final_path: PathBuf,
        partial: PathBuf,
        committed: std::cell::Cell<bool>,
    },
}

/// Drop runs on a return and on a panic, and on neither when a signal kills the process.
/// A Ctrl-C mid-write therefore leaves the `.partial` behind. Said here rather than fixed,
/// because a handler is the wrong trade for it: the file is named `.partial`, it is never the
/// archive anybody is pointed at, and the next run to the same destination overwrites it.
/// Revisit if this tool ever grows a signal handler for another reason.
impl Drop for Destination {
    fn drop(&mut self) {
        if let Self::File {
            partial, committed, ..
        } = self
            && !committed.get()
        {
            let _ = std::fs::remove_file(partial);
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
            Self::File { partial, .. } => Ok(Box::new(create_private(partial)?)),
        }
    }

    pub(super) fn commit(&self, term: &Term) -> Result<Option<PathBuf>> {
        match self {
            Self::Stdout => Ok(None),
            Self::File {
                final_path,
                partial,
                committed,
            } => {
                // Flushed is not durable: `Write::flush` on a `File` is a no-op, so without
                // this the rename could land before the bytes and a crash would leave an empty
                // file under the finished name, which is what `.partial` exists to stop.
                // Opened for WRITING, because Windows refuses FlushFileBuffers on a read-only
                // handle, which failed every backup there after the whole archive was written.
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(partial)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| Error::io(partial, e))?;
                std::fs::rename(partial, final_path).map_err(|e| Error::io(final_path, e))?;
                sync_directory(term, final_path.parent());
                committed.set(true);
                Ok(Some(final_path.clone()))
            }
        }
    }
}

/// Fsync the directory, so the rename that just happened survives a crash.
///
/// Unix only: there is no portable way to open a directory as a file, and Windows does not
/// need one, since NTFS orders the rename against the file's own flushed data. A failure is
/// reported rather than swallowed, because the whole point of the rename was durability.
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

pub(super) fn choose(
    args: &Create,
    identity: &Identity,
    alias: Option<&str>,
    now: &jiff::Timestamp,
    encryption: &Encryption,
    stdout_is_terminal: bool,
) -> Result<Destination> {
    if args.stdout {
        // An archive is compressed bytes, and a `--plaintext` one is the key among them. A
        // terminal keeps what it is shown in scrollback that no zeroized buffer can reach, and
        // some emulators log it to disk. Taken as a parameter rather than read here, so both
        // answers are reachable from a test.
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
    let chosen = args.output.clone().unwrap_or_else(|| PathBuf::from("."));

    let final_path = if names_an_archive(&chosen) {
        if let Some(parent) = chosen.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        chosen
    } else {
        std::fs::create_dir_all(&chosen).map_err(|e| Error::io(&chosen, e))?;
        chosen.join(name)
    };
    let partial = final_path.with_extension("partial");
    Ok(Destination::File {
        final_path,
        partial,
        committed: std::cell::Cell::new(false),
    })
}

/// Whether a path names the archive itself rather than a directory to put it in.
///
/// An existing directory is a directory. Otherwise the extension decides: someone naming a
/// file names it `.tar.zst` or `.age`, and someone naming a directory that does not exist yet
/// does not. Guessing "file" for a bare name is the worse mistake, because it writes what the
/// user reads as a folder as a single archive, and the next run silently replaces it.
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
    fn a_directory_output_gets_a_generated_name_and_a_file_output_is_taken_as_given() {
        let identity = Identity::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfJT4YlvXMI9h98D4SSswNV5S0voNrQaUZMCq0s0zK",
        )
        .expect("the vector parses");
        let now = jiff::Timestamp::from_second(1_786_000_000).expect("a valid instant");

        let into_directory = Create {
            output: Some(PathBuf::from("/tmp")),
            ..blank_create()
        };
        let destination = choose(
            &into_directory,
            &identity,
            Some("maninak"),
            &now,
            &Encryption::None,
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
        // The trap this guards: a directory that does not exist yet, named like a directory.
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
        // `matches!` rather than `expect_err`, which would want Debug on Destination.
        let refused = choose(&args, &identity, None, &now, &Encryption::None, true);
        assert!(
            matches!(refused, Err(Error::Refused { .. })),
            "a terminal should be refused"
        );

        // A pipe or a redirect is the whole point of --stdout and must keep working.
        let allowed = choose(&args, &identity, None, &now, &Encryption::None, false)
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
        let destination = choose(&args, &identity, None, &now, &Encryption::None, false)
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
