//! Owner-only files and directories, on systems that can express it.

use std::path::Path;

use crate::error::{Error, Result};

/// Restricts a directory to its owner. Call it before anything is written into it.
pub fn set_dir_owner_only(path: &Path) -> Result<()> {
    set_mode(path, MODE_DIR)
}

/// Copies a file that may hold key material, landing it owner-only. A missing source is
/// skipped, because an archive of one tier does not carry what another tier would.
pub fn copy_secret(from: &Path, to: &Path) -> Result<()> {
    if !from.is_file() {
        return Ok(());
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(from).map_err(|e| Error::io(from, e))?);
    write_atomically(to, &bytes, MODE_SECRET)
}

/// Copies a file that holds nothing secret, landing it at the mode `rad` gives it in a home.
/// The staging copy sat owner-only beside a private key, and that mode must not carry over.
pub fn copy_doc(from: &Path, to: &Path) -> Result<()> {
    if !from.is_file() {
        return Ok(());
    }
    // Staged like a key, because a half-written `config.json` leaves a home that will not
    // start
    let bytes = std::fs::read(from).map_err(|e| Error::io(from, e))?;
    write_atomically(to, &bytes, MODE_DOC)
}

/// The mode of a private key, and of the archives that carry one.
pub const MODE_SECRET: u32 = 0o600;
/// The mode of what a Radicle home keeps world-readable, such as a public key or a config.
pub const MODE_DOC: u32 = 0o644;
/// The mode of a working directory, or a home.
pub const MODE_DIR: u32 = 0o700;

#[cfg(unix)]
mod platform {
    use super::{Error, Path, Result};

    pub fn create_private_file(path: &Path) -> Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;

        // open(2) applies its mode only when it creates the file, and follows an existing
        // symlink, so the path is unlinked first. `create_new` then fails if something
        // recreates the path in between.
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(path, e)),
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(super::MODE_SECRET)
            .open(path)
            .map_err(|e| Error::io(path, e))
    }

    pub fn create_private_dir(path: &Path) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;

        std::fs::DirBuilder::new()
            .mode(super::MODE_DIR)
            .create(path)
            .map_err(|e| Error::io(path, e))
    }

    pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions).map_err(|e| Error::io(path, e))
    }

    /// Whether two paths sit on the same filesystem. `false` proves a backup outlives the
    /// disk holding the home, and `true` proves nothing, because a synced directory leaves the
    /// machine whatever `dev` says.
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

    /// Warns once that this platform cannot restrict a file to one user, so the file inherits
    /// its folder's permissions. Setting an ACL needs a Windows API dependency. Revisit if a
    /// dependency-free way to set an ACL turns up.
    fn announce(path: &Path) {
        ANNOUNCED.call_once(|| {
            eprintln!(
                "! {}: this system cannot restrict a file to one user. The file gets the \
                 permissions of its folder. Keep archives and keys inside your own user folder",
                path.display()
            );
        });
    }

    pub fn create_private_file(path: &Path) -> Result<std::fs::File> {
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
        if mode == super::MODE_SECRET || mode == super::MODE_DIR {
            announce(path);
        }
        Ok(())
    }

    /// Whether two paths sit on the same volume, or `None` when either cannot be resolved. A
    /// junction or a mapped drive can still fool it.
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

pub use platform::{create_private_file, same_device, set_mode};

/// Creates a directory only its owner can enter, with that mode from the moment it exists.
///
/// Refuses an existing path, because a directory someone else created first carries their
/// permissions. The parent must exist already.
pub use platform::create_private_dir;

/// Puts `bytes` at `path` so the path holds either its old content or all of the new, never a
/// prefix or nothing.
///
/// `create_private_file` unlinks the target first, so writing in place would lose the old key
/// on a crash. The content is staged beside the target and renamed over it. The parent is not
/// fsynced, because a lost rename keeps the old file.
pub fn write_atomically(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut staging_path = path.as_os_str().to_os_string();
    staging_path.push(".partial");
    let staging_path = std::path::PathBuf::from(staging_path);

    let staged = (|| -> Result<()> {
        use std::io::Write as _;

        // Owner-only from its first byte, so key material is never readable under a
        // predictable name
        let mut file = create_private_file(&staging_path)?;
        file.write_all(bytes)
            .map_err(|e| Error::io(&staging_path, e))?;
        // Synced before the rename, because a rename is atomic against a crash only over
        // content already on disk
        file.sync_all().map_err(|e| Error::io(&staging_path, e))?;
        drop(file);
        set_mode(&staging_path, mode)?;
        std::fs::rename(&staging_path, path).map_err(|e| Error::io(&staging_path, e))
    })();

    if staged.is_err() {
        // Cleanup is best effort, because the error being returned is the one worth reading
        let _ = std::fs::remove_file(&staging_path);
    }
    staged
}

/// Writes a file only its owner can read, created with those permissions, because a private
/// key that is briefly world-readable has been read.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = create_private_file(path)?;
    // The path is attached, because a bare "No space left on device" does not say which key or
    // archive failed
    file.write_all(bytes).map_err(|e| Error::io(path, e))?;
    file.flush().map_err(|e| Error::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replacement_that_cannot_even_be_staged_leaves_the_original_alone() {
        // Owner-only, like every fixture that writes a file named after a key
        let scratch = crate::key::tests::TestScratch::create("perms-keeps-the-original");
        let path = scratch.path_of("radicle");
        std::fs::write(&path, b"the identity already here").expect("a file worth protecting");
        // The staging name is occupied, so the replacement fails at its first step
        std::fs::create_dir(scratch.path_of("radicle.partial"))
            .expect("the staging name is occupied");

        assert!(write_atomically(&path, b"the identity being restored", MODE_SECRET).is_err());

        // Writing in place would unlink the target first and lose both identities
        assert_eq!(
            std::fs::read(&path).expect("the original is still readable"),
            b"the identity already here"
        );
    }

    #[test]
    fn a_replacement_that_worked_leaves_no_staging_file_behind() {
        let scratch = crate::key::tests::TestScratch::create("perms-sweeps-up");
        let path = scratch.path_of("radicle");
        write_atomically(&path, b"the identity being restored", MODE_SECRET)
            .expect("the write lands");

        assert_eq!(
            std::fs::read(&path).expect("the new content is readable"),
            b"the identity being restored"
        );
        assert!(
            !scratch.path_of("radicle.partial").exists(),
            "the staging name must not survive a successful write"
        );
    }

    /// Pins the mode values themselves, because a test comparing a mode read back with the
    /// constant it was written from still passes when the constant is wrong.
    #[test]
    fn a_secret_and_a_directory_are_owner_only_and_a_document_is_not() {
        assert_eq!(MODE_SECRET, 0o600);
        assert_eq!(MODE_DIR, 0o700);
        assert_eq!(MODE_DOC, 0o644);
    }

    /// The staging file is created owner-only, so the requested mode is applied afterwards or
    /// not at all. Without that step every restored `config.json` comes out `0600`.
    #[cfg(unix)]
    #[test]
    fn a_document_lands_at_the_mode_a_native_home_would_have() {
        use std::os::unix::fs::PermissionsExt as _;

        let scratch = crate::key::tests::TestScratch::create("perms-carries-the-mode");
        let secret = scratch.path_of("radicle");
        let doc = scratch.path_of("config.json");
        write_atomically(&secret, b"a key", MODE_SECRET).expect("the key lands");
        write_atomically(&doc, b"{}", MODE_DOC).expect("the config lands");

        let mode_of = |path: &std::path::Path| {
            std::fs::metadata(path)
                .expect("the file was just written")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode_of(&secret), MODE_SECRET);
        assert_eq!(mode_of(&doc), MODE_DOC);
    }
}
