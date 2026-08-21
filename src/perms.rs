//! Making files unreadable by anyone but their owner, on systems that can say that.
//!
//! Every path that has held key material goes through here, so there is exactly one place that
//! knows what "owner only" means on this platform, and exactly one place that has to be honest
//! when the platform cannot promise it.

use std::path::Path;

use crate::error::{Error, Result};

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rad-backup-perms-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
        dir
    }

    #[test]
    fn a_replacement_that_cannot_even_be_staged_leaves_the_original_alone() {
        let dir = scratch("replace-keeps-the-original");
        let path = dir.join("radicle");
        std::fs::write(&path, b"the identity already here").expect("a file worth protecting");
        // Nothing can be created under the staging name, so the replacement fails at its
        // first step, which is the earliest a failure can happen.
        std::fs::create_dir(dir.join("radicle.partial")).expect("the staging name is occupied");

        assert!(replace(&path, b"the identity being restored", SECRET_MODE).is_err());

        // Writing in place unlinked the target first, so any failure after that left a home
        // holding neither the old identity nor the new one.
        assert_eq!(
            std::fs::read(&path).expect("the original is still readable"),
            b"the identity already here"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_replacement_that_worked_leaves_no_staging_file_behind() {
        let dir = scratch("replace-sweeps-up");
        let path = dir.join("radicle");
        replace(&path, b"the identity being restored", SECRET_MODE).expect("the write lands");

        assert_eq!(
            std::fs::read(&path).expect("the new content is readable"),
            b"the identity being restored"
        );
        assert!(
            !dir.join("radicle.partial").exists(),
            "the staging name must not survive a successful write"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A private key, and the archives that carry one.
pub const SECRET_MODE: u32 = 0o600;
/// A public key, a config, a manifest: what a Radicle home keeps world-readable itself.
pub const DOC_MODE: u32 = 0o644;
/// A working directory, or a home.
pub const DIR_MODE: u32 = 0o700;

#[cfg(unix)]
mod platform {
    use super::{Error, Path, Result};

    pub fn create_private(path: &Path) -> Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;

        // Unlink first, then `create_new`, because open(2) applies its mode argument ONLY when
        // it creates the file. Under `create` the mode was silently ignored whenever the path
        // already existed, so restoring over a 0644 key left it 0644, and an existing symlink
        // was followed and the key written to its target instead. `create_new` then fails
        // rather than races if something recreates the path in between.
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(path, e)),
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(super::SECRET_MODE)
            .open(path)
            .map_err(|e| Error::io(path, e))
    }

    pub fn create_private_dir(path: &Path) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;

        std::fs::DirBuilder::new()
            .mode(super::DIR_MODE)
            .create(path)
            .map_err(|e| Error::io(path, e))
    }

    pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions).map_err(|e| Error::io(path, e))
    }

    /// Whether two paths sit on the same filesystem. A different one is proof that a backup
    /// outlives the disk holding the home; the same one proves nothing either way, because a
    /// synced directory is off the machine whatever `dev` says.
    pub fn same_device(left: &Path, right: &Path) -> Option<bool> {
        use std::os::unix::fs::MetadataExt;

        let left = std::fs::metadata(left).ok()?;
        let right = std::fs::metadata(right).ok()?;
        Some(left.dev() == right.dev())
    }
}

#[cfg(not(unix))]
mod platform {
    use std::sync::Once;

    use super::{Error, Path, Result};

    static ANNOUNCED: Once = Once::new();

    /// Windows has no mode bits, and restricting an ACL from here would mean carrying a
    /// Windows API dependency into a tool whose whole point is being easy to audit. So the
    /// file inherits the permissions of the folder it is written into, and this says so once,
    /// out loud, rather than letting a caller believe in a `0600` that is not there. The same
    /// holds for any other platform that cannot express "mine alone".
    fn announce(path: &Path) {
        ANNOUNCED.call_once(|| {
            eprintln!(
                "! {}: this platform cannot restrict a file to one user, so it inherits the \
                 folder's permissions; keep archives and keys inside your own profile",
                path.display()
            );
        });
    }

    pub fn create_private(path: &Path) -> Result<std::fs::File> {
        announce(path);
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| Error::io(path, e))
    }

    pub fn create_private_dir(path: &Path) -> Result<()> {
        announce(path);
        std::fs::create_dir(path).map_err(|e| Error::io(path, e))
    }

    pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
        if mode == super::SECRET_MODE || mode == super::DIR_MODE {
            announce(path);
        }
        Ok(())
    }

    /// The best a filesystem-agnostic check can do here: two paths are on the same device when
    /// they are on the same volume. A junction or a mapped drive can still fool it, so an
    /// undecidable answer is `None` rather than a guess.
    pub fn same_device(left: &Path, right: &Path) -> Option<bool> {
        use std::path::Component;

        let volume = |path: &Path| -> Option<String> {
            std::fs::canonicalize(path).ok().and_then(|path| {
                path.components().next().and_then(|first| match first {
                    Component::Prefix(prefix) => {
                        Some(prefix.as_os_str().to_string_lossy().to_lowercase())
                    }
                    _ => None,
                })
            })
        };
        Some(volume(left)? == volume(right)?)
    }
}

pub use platform::{create_private, same_device, set_mode};

/// Create a directory only its owner can enter, with that mode from the moment it exists.
///
/// Two things a `create_dir_all` followed by a `chmod` does not give: between those two calls
/// anything on the machine can read what lands inside, and `create_dir_all` succeeds on a
/// directory that is already there. A working directory whose name someone else guessed and
/// created first, with permissions of their choosing, is exactly the one this must refuse, so
/// an existing path is an error here rather than a reuse. The parent must exist already.
pub use platform::create_private_dir;

/// Put `bytes` at `path` so that whatever happens, the path holds either what was there
/// before or the whole of the new content, and never a prefix of it or nothing at all.
///
/// `write_owner_only` unlinks the target before creating it, which is what makes the mode
/// argument mean anything (see `create_private`) and what makes the window dangerous: a
/// `restore --force` over an occupied home has already destroyed the old secret key by the
/// time the first byte of the new one is written, so a crash, a full disk or a killed run
/// leaves a home with no identity at all. Staged beside the target and renamed over it, the
/// same failure leaves the old file exactly as it was, because a rename within a directory is
/// atomic. There is no corresponding fsync of the parent: a crash may lose the rename, but
/// losing the rename means keeping the old file, which is the promise this function makes.
pub fn replace(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut beside = path.as_os_str().to_os_string();
    beside.push(".partial");
    let beside = std::path::PathBuf::from(beside);

    let staged = (|| -> Result<()> {
        use std::io::Write as _;

        // Owner-only from its first byte whatever the final mode is, so key material is never
        // briefly readable under a name a watcher can predict.
        let mut file = create_private(&beside)?;
        file.write_all(bytes).map_err(|e| Error::io(&beside, e))?;
        // Before the rename that publishes it: a rename is atomic against a crash, but only
        // over content the filesystem has been told to keep.
        file.sync_all().map_err(|e| Error::io(&beside, e))?;
        drop(file);
        set_mode(&beside, mode)?;
        std::fs::rename(&beside, path).map_err(|e| Error::io(&beside, e))
    })();

    if staged.is_err() {
        // Best effort, and deliberately not reported: the error being returned is the one
        // worth reading, and a leftover staging file changes nothing about the target.
        let _ = std::fs::remove_file(&beside);
    }
    staged
}

/// Write a file only its owner can read, creating it with those permissions rather than
/// fixing them afterwards: a private key that is briefly world-readable has been read.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = create_private(path)?;
    // Named, not bare: this lands private keys and archives, and "No space left on device"
    // with no path attached is the message somebody reads while trying to work out which of
    // their files did not survive.
    file.write_all(bytes).map_err(|e| Error::io(path, e))?;
    file.flush().map_err(|e| Error::io(path, e))
}
