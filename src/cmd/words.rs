//! Rebuilding an identity from the 24 words on a recovery sheet.
//!
//! The other half of `paper`, which prints the sheet. It shares nothing with restoring an
//! archive but the home it writes into: there is no archive, no manifest and no repository
//! here, only a seed that a key is derived back from.

use zeroize::Zeroizing;

use crate::cmd::Ctx;
use crate::crypt;
use crate::error::{Error, Result};
use crate::perms::{set_dir_owner_only, write_owner_only};

/// Room for the longest 24-word BIP-39 line in English, so the buffer it is read into never
/// grows: 24 words of 8 letters, 23 spaces, and a line ending.
const TYPED_LINE: usize = 24 * 8 + 23 + 2;

/// Rebuild an identity from a mnemonic, for when the paper sheet is all that is left.
pub fn restore(ctx: &Ctx) -> Result<()> {
    use std::io::BufRead;

    let home = &ctx.home;
    if home.holds_identity()? {
        return Err(Error::refused(
            format!("{} already holds an identity", home.path().display()),
            "restore into an empty --home",
        ));
    }
    // Read from stdin whether a person is typing or a script is piping. The words are secret,
    // but a pipe keeps them out of the process table and out of shell history, which is more
    // than a command-line argument would do.
    if ctx.term.is_interactive() {
        ctx.term
            .headline("Type the 24 words from your recovery sheet, separated by spaces:");
    }
    // Zeroizing, like every other buffer that holds key material: these 24 words ARE the key,
    // so the line they arrive on cannot be left in freed heap for a later allocation to see.
    //
    // Sized before the first byte, because `read_line` grows a buffer that starts empty, and
    // every growth frees a block still holding the words read so far, which the `Zeroizing`
    // around the final buffer never reaches. Room for the longest mnemonic English spells: 24
    // words of at most 8 letters, their separators, and a line ending.
    let mut line = Zeroizing::new(String::with_capacity(TYPED_LINE));
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(Error::PathlessIo)?;

    let mnemonic = bip39::Mnemonic::parse_normalized(line.trim()).map_err(|e| {
        Error::refused(
            format!("those words are not a valid mnemonic: {e}"),
            "check the sheet and try again",
        )
    })?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(<[u8; 32]>::try_from(entropy.as_slice()).map_err(|_| {
            Error::refused(
                "that mnemonic does not carry 32 bytes",
                "a Radicle key is 24 words; a 12-word phrase is something else",
            )
        })?);

    let identity = crate::key::identity_from_seed(&seed)?;
    ctx.term
        .ok(&format!("those words rebuild {}", identity.did()));
    if !ctx.term.confirm("Is that the identity you expected?")? {
        return Err(Error::refused(
            "stopped before writing anything",
            "check the words",
        ));
    }

    let passphrase = crypt::read_passphrase(
        crypt::Protects::RadicleKey,
        // No file: `--passphrase-file` holds the ARCHIVE passphrase, and reading it here gave
        // the restored key the same secret, silently, without ever asking for a new one.
        None,
        "New passphrase for the restored key: ",
        crypt::Purpose::Sealing,
        ctx.term.is_interactive(),
    )?;
    let openssh = crate::key::openssh_from_seed(&seed, Some(&passphrase))?;

    std::fs::create_dir_all(home.keys_dir()).map_err(|e| Error::io(home.keys_dir(), e))?;
    set_dir_owner_only(home.path())?;
    // The keys directory too, and before the key is written into it. `create_dir_all` takes
    // the umask, so `keys/` came out world-listable on a default one while the key inside it
    // was owner-only: a home this tool rebuilt was subtly less private than one `rad` made.
    set_dir_owner_only(&home.keys_dir())?;
    write_owner_only(&home.secret_key(), openssh.as_bytes())?;
    std::fs::write(home.public_key(), identity.to_openssh()?)
        .map_err(|e| Error::io(home.public_key(), e))?;

    ctx.term
        .ok(&format!("wrote the key into {}", home.keys_dir().display()));
    ctx.term
        .hint("the key is all this restored: `rad node start` rebuilds the routing table,");
    ctx.term
        .hint("your repositories come back with `rad clone <rid>` or `rad seed <rid>`");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constant against the word list itself, not against a number typed twice. A buffer
    /// one byte short still grows, and growing is the whole of what it is there to stop.
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
