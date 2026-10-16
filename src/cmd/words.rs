//! Rebuilding an identity from the 24 words on a recovery sheet that `paper` prints.

use zeroize::Zeroizing;

use crate::cmd::Ctx;
use crate::crypt;
use crate::error::{Error, Result};
use crate::perms::{MODE_DOC, set_dir_owner_only, write_atomically, write_owner_only};

/// The byte length of the longest 24-word English BIP-39 line, with spaces and line ending.
const TYPED_LINE: usize = 24 * 8 + 23 + 2;

/// Rebuild an identity from a mnemonic, for when the paper sheet is all that is left.
pub fn restore(ctx: &Ctx) -> Result<()> {
    use std::io::BufRead;

    let home = &ctx.home;
    if home.holds_identity()? {
        return Err(Error::refused(
            format!("{} already holds an identity", home.path().display()),
            "pass --home with an empty directory, or move the existing identity aside first",
        ));
    }
    // The words arrive on stdin, which keeps them out of the process table and shell history
    if ctx.term.is_interactive() {
        ctx.term
            .headline("Type the 24 words from your recovery sheet, separated by spaces:");
    }
    // The line holds the key itself, so it is zeroized and sized before the first byte. Each
    // growth of a buffer in `read_line` frees a block still holding the words read so far, and
    // the `Zeroizing` around the final buffer never wipes that block.
    let mut line = Zeroizing::new(String::with_capacity(TYPED_LINE));
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(Error::PathlessIo)?;

    let mnemonic = bip39::Mnemonic::parse_normalized(line.trim()).map_err(|e| {
        Error::refused(
            format!("those words are not a valid recovery phrase: {e}"),
            "check the sheet and try again",
        )
    })?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(<[u8; 32]>::try_from(entropy.as_slice()).map_err(|_| {
            Error::refused(
                "those words are not a Radicle key",
                "a Radicle recovery sheet has 24 words. Check that you typed all of them",
            )
        })?);

    let identity = crate::key::identity_from_seed(&seed)?;
    ctx.term.ok(&format!(
        "those words belong to the identity {}",
        identity.did()
    ));
    if !ctx.term.confirm("Is that the identity you expected?")? {
        let remedy = match ctx.term.is_interactive() {
            true => "check the words on the sheet and run again",
            false => "rad-backup could not ask for confirmation. Add --yes to accept the identity",
        };
        return Err(Error::refused("nothing was written", remedy));
    }

    let passphrase = crypt::read_passphrase(
        crypt::Protects::RadicleKey,
        // `--passphrase-file` holds the archive passphrase, so reading it here would silently
        // give the restored key the same secret
        None,
        "New passphrase for the restored key: ",
        crypt::Purpose::Sealing,
        ctx.term.is_interactive(),
    )?;
    let openssh = crate::key::openssh_from_seed(&seed, Some(&passphrase))?;

    std::fs::create_dir_all(home.keys_dir()).map_err(|e| Error::io(home.keys_dir(), e))?;
    set_dir_owner_only(home.path())?;
    // `keys/` is tightened before the key lands in it, because `create_dir_all` takes the
    // umask and leaves the directory world-listable on a default one
    set_dir_owner_only(&home.keys_dir())?;
    write_owner_only(&home.secret_key(), openssh.as_bytes())?;
    // `fs::write` follows a symlink at the name and truncates its target. `write_atomically`
    // unlinks first, so a link there is replaced and its target left alone, and the file
    // lands at `0644` whatever the umask.
    write_atomically(
        &home.public_key(),
        identity.to_openssh()?.as_bytes(),
        MODE_DOC,
    )?;

    ctx.term
        .ok(&format!("wrote the key into {}", home.keys_dir().display()));
    ctx.term
        .hint("only the key was restored. Run `rad node start` to reconnect to the network");
    ctx.term
        .hint("to get your repositories back, run `rad clone <rid>` for each one");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_typed_line_has_room_for_the_longest_words_english_spells() {
        let longest = bip39::Language::English
            .word_list()
            .iter()
            .map(|word| word.len())
            .max()
            .expect("the english word list is not empty");
        assert!(
            TYPED_LINE >= 24 * longest + 23 + 2,
            "the longest word is {longest} letters, so 24 of them do not fit in {TYPED_LINE}"
        );
    }
}
