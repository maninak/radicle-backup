//! Making files unreadable by anyone but their owner, on systems that can say that.
//!
//! Every path that has held key material goes through here, so there is exactly one place that
//! knows what "owner only" means on this platform, and exactly one place that has to be honest
//! when the platform cannot promise it.

use std::path::Path;

use crate::error::{Error, Result};

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

        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
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

    /// Whether two paths sit on the same filesystem, which is what decides whether a backup
    /// survives the disk that holds the home it protects.
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

/// Write a file only its owner can read, creating it with those permissions rather than
/// fixing them afterwards: a private key that is briefly world-readable has been read.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = create_private(path)?;
    file.write_all(bytes).map_err(Error::Bare)?;
    file.flush().map_err(Error::Bare)
}
