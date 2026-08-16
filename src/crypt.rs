//! Encryption of the archive, and where the passphrase for it comes from.
//!
//! An archive holds the 32 bytes that are the user's identity, so encryption is the default
//! and plaintext is something the caller has to ask for out loud. Revisit never: an
//! unencrypted copy of a private key is the failure this tool exists to prevent.

use std::io::{self, Read, Write};
use std::path::Path;
use std::str::FromStr;

use age::secrecy::SecretString;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Environment variable holding the archive passphrase, for cron jobs that cannot be asked.
pub const PASSPHRASE_ENV: &str = "RAD_BACKUP_PASSPHRASE";
/// Environment variable `rad` itself uses for the key passphrase, honoured for the same
/// reason: so that a scheduled run needs no interactive terminal.
pub const KEY_PASSPHRASE_ENV: &str = "RAD_PASSPHRASE";

/// How an archive is protected.
#[derive(Clone)]
pub enum Encryption {
    /// A passphrase only a person holds. The default.
    Passphrase(Zeroizing<String>),
    /// age recipients: `age1...` keys, or `ssh-ed25519 AAAA...` public keys, so an archive can
    /// be encrypted to another machine or to a friend holding escrow.
    Recipients(Vec<String>),
    /// No encryption. Only ever chosen explicitly.
    None,
}

impl Encryption {
    pub fn is_encrypted(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Passphrase(_) => "passphrase",
            Self::Recipients(_) => "recipients",
            Self::None => "none",
        }
    }
}

/// Hand-written, because `Zeroizing` derives `Debug` and hands it straight to the string it
/// wraps: a derived `Debug` here would print the passphrase into whatever log, panic message
/// or `dbg!` reached for it, undoing the wiping the rest of this file exists to do. Nothing
/// formats an `Encryption` today, and this is what keeps that from mattering later.
impl std::fmt::Debug for Encryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Encryption::{}", self.label())
    }
}

/// The writing half of the container. Owns whichever layer sits directly on the output, so
/// that finishing is a single call whatever the encryption mode is.
pub enum Sink<'a> {
    Plain(Box<dyn Write + 'a>),
    Encrypted(Box<age::stream::StreamWriter<Box<dyn Write + 'a>>>),
}

impl<'a> Sink<'a> {
    pub fn new(output: Box<dyn Write + 'a>, encryption: &Encryption) -> Result<Self> {
        let encryptor = match encryption {
            Encryption::None => return Ok(Self::Plain(output)),
            Encryption::Passphrase(passphrase) => {
                age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_string()))
            }
            Encryption::Recipients(specs) => {
                let recipients = parse_recipients(specs)?;
                let borrowed: Vec<&dyn age::Recipient> =
                    recipients.iter().map(std::convert::AsRef::as_ref).collect();
                age::Encryptor::with_recipients(borrowed.into_iter())?
            }
        };
        Ok(Self::Encrypted(Box::new(encryptor.wrap_output(output)?)))
    }

    /// Close the encryption layer. Skipping this writes a truncated archive that will not
    /// decrypt, so every writing path must end here.
    pub fn finish(self) -> Result<()> {
        match self {
            Self::Plain(mut output) => output.flush().map_err(Error::Bare),
            Self::Encrypted(writer) => {
                let mut output = writer.finish().map_err(Error::Bare)?;
                output.flush().map_err(Error::Bare)
            }
        }
    }
}

impl Write for Sink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(w) => w.write(buf),
            Self::Encrypted(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(w) => w.flush(),
            Self::Encrypted(w) => w.flush(),
        }
    }
}

/// Wrap a reader so that it yields plaintext, whatever the archive was encrypted with.
pub fn decrypting_reader<'a, R: Read + 'a>(
    input: R,
    passphrase: Option<&Zeroizing<String>>,
    identity_files: &[std::path::PathBuf],
) -> Result<Box<dyn Read + 'a>> {
    let buffered = io::BufReader::new(input);
    let decryptor = match age::Decryptor::new_buffered(buffered) {
        Ok(decryptor) => decryptor,
        // A plaintext archive is not an age file at all, so failing to read an age header is
        // how we learn that, rather than something to report.
        Err(_) => return Err(Error::Age("not an age-encrypted stream".to_string())),
    };

    if decryptor.is_scrypt() {
        let passphrase = passphrase.ok_or_else(|| {
            Error::refused(
                "this archive is passphrase-protected",
                format!("re-run and enter the passphrase, or set {PASSPHRASE_ENV}"),
            )
        })?;
        let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));
        let reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            // Unwrapping the file key is the only step a passphrase can be wrong at, so at
            // this point every failure is that typo and nothing else. Errors from the payload
            // that follows arrive later, as io errors, and keep their own wording.
            .map_err(|_| Error::WrongPassphrase)?;
        return Ok(Box::new(Authenticated(reader)));
    }

    let identities = read_identity_files(identity_files)?;
    if identities.is_empty() {
        return Err(Error::refused(
            "this archive is encrypted to a key, not a passphrase",
            "pass --identity <file> with the age or ssh private key it was encrypted to",
        ));
    }
    let borrowed: Vec<&dyn age::Identity> =
        identities.iter().map(std::convert::AsRef::as_ref).collect();
    let reader = decryptor.decrypt(borrowed.into_iter())?;
    Ok(Box::new(Authenticated(reader)))
}

/// A reader that says what a failure in the encrypted payload means.
///
/// age reports a chunk that fails authentication as a bare io error reading "decryption
/// error", which sounds like a wrong passphrase. By the time the payload is being read the
/// passphrase has already been proven right, so the only remaining explanation is that the
/// bytes changed after they were written.
struct Authenticated<R>(R);

impl<R: Read> Read for Authenticated<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{e}: this archive did not authenticate, so it is damaged"),
            )
        })
    }
}

/// Whether a file begins with an age header, which is how a reader decides to decrypt without
/// trusting the file name.
pub fn looks_encrypted(path: &Path) -> Result<bool> {
    use std::io::Read as _;

    const AGE_MAGIC: &[u8] = b"age-encryption.org/";
    let mut file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
    let mut head = [0u8; AGE_MAGIC.len()];
    match file.read_exact(&mut head) {
        Ok(()) => Ok(head == AGE_MAGIC),
        Err(_) => Ok(false),
    }
}

/// Whether opening this archive will ask for a passphrase, read from the archive's own header.
///
/// An archive encrypted to an age or ssh recipient is opened with `--identity`, not a
/// passphrase, and every age file starts with the same magic, so `looks_encrypted` cannot tell
/// the two kinds apart. Callers that asked for a passphrase on `looks_encrypted` alone made a
/// recipient-encrypted archive impossible to restore unattended: the prompt had nobody to
/// answer it. The header itself says which kind it is, so ask it rather than infer from
/// whether `--identity` happened to be passed, which would stop prompting for a passphrase
/// archive that someone opens with `--identity` also on the command line.
pub fn needs_passphrase(path: &Path) -> Result<bool> {
    if !looks_encrypted(path)? {
        return Ok(false);
    }
    let file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
    match age::Decryptor::new_buffered(io::BufReader::new(file)) {
        Ok(decryptor) => Ok(decryptor.is_scrypt()),
        // A header age cannot parse is not this function's to report: no passphrase would open
        // it either, and the open that follows says what is wrong in its own wording.
        Err(_) => Ok(false),
    }
}

/// Read a passphrase from the environment, a file, or the person at the terminal.
///
/// `confirm` asks twice, which is right when creating an archive and wrong when opening one:
/// a typo while creating locks the only copy of an identity away forever.
pub fn passphrase(
    variable: &str,
    file: Option<&Path>,
    prompt: &str,
    confirm: bool,
    interactive: bool,
) -> Result<Zeroizing<String>> {
    // `--plaintext` turns off the ARCHIVE's encryption and has nothing to do with the key's
    // own passphrase, so offering it on the key path sent the user after a flag that would not
    // have helped and does not exist for that question.
    let remedy = if variable == KEY_PASSPHRASE_ENV {
        "give a passphrase: it is the only thing protecting this key on disk"
    } else {
        "give a passphrase, or pass --plaintext if you really want no encryption"
    };
    if let Some(path) = file {
        // Zeroizing before the trim, not after: the untrimmed copy holds the passphrase too.
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?);
        let trimmed = Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string());
        return refuse_if_empty(trimmed, &format!("{} is empty", path.display()), remedy);
    }
    if let Ok(value) = std::env::var(variable) {
        // `std::env::var` answers Ok("") for a variable set but empty, which is what an
        // EnvironmentFile line of `RAD_BACKUP_PASSPHRASE=` produces. Unchecked, that
        // encrypted the identity to the empty passphrase and every report called it protected.
        return refuse_if_empty(
            Zeroizing::new(value),
            &format!("{variable} is empty"),
            remedy,
        );
    }
    if !interactive {
        return Err(Error::refused(
            "a passphrase is needed and there is nobody to ask",
            format!("set {variable}, or pass --passphrase-file <path>"),
        ));
    }

    let first = refuse_if_empty(
        Zeroizing::new(rpassword::prompt_password(prompt).map_err(Error::Bare)?),
        "nothing was typed",
        remedy,
    )?;
    if confirm {
        let again =
            Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ").map_err(Error::Bare)?);
        if *first != *again {
            return Err(Error::refused(
                "the two passphrases do not match",
                "run again",
            ));
        }
    }
    Ok(first)
}

/// Refuse an empty passphrase whichever of the three sources it came from.
///
/// age accepts one and encrypts to it, so an empty passphrase produces a file that says
/// `.age`, reports as encrypted everywhere, and opens for anyone who presses Enter.
fn refuse_if_empty(
    passphrase: Zeroizing<String>,
    because: &str,
    remedy: &str,
) -> Result<Zeroizing<String>> {
    if passphrase.is_empty() {
        return Err(Error::refused(
            format!("an empty passphrase protects nothing: {because}"),
            remedy,
        ));
    }
    Ok(passphrase)
}

fn parse_recipients(specs: &[String]) -> Result<Vec<Box<dyn age::Recipient>>> {
    let mut recipients: Vec<Box<dyn age::Recipient>> = Vec::with_capacity(specs.len());
    for spec in specs {
        let spec = spec.trim();
        if let Ok(recipient) = age::x25519::Recipient::from_str(spec) {
            recipients.push(Box::new(recipient));
            continue;
        }
        if let Ok(recipient) = age::ssh::Recipient::from_str(spec) {
            recipients.push(Box::new(recipient));
            continue;
        }
        return Err(Error::refused(
            format!("{spec} is not a recipient this tool understands"),
            "pass an age public key (age1...) or an ssh public key (ssh-ed25519 AAAA...)",
        ));
    }
    Ok(recipients)
}

fn read_identity_files(paths: &[std::path::PathBuf]) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
    for path in paths {
        // A private key, so the buffer it is read into is wiped when this loop ends rather
        // than left in whatever heap page it happened to land on.
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?);
        if let Ok(identity) = age::x25519::Identity::from_str(text.trim()) {
            identities.push(Box::new(identity));
            continue;
        }
        let key = age::ssh::Identity::from_buffer(text.as_bytes(), None)
            .map_err(|e| Error::Age(format!("{}: {e}", path.display())))?;
        identities.push(Box::new(key));
    }
    Ok(identities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_round_trips_through_a_passphrase() {
        let passphrase = Zeroizing::new("a passphrase with spaces".to_string());
        let plaintext = b"the 32 bytes that matter, pretend";

        let mut buffer = Vec::new();
        let mut sink = Sink::new(
            Box::new(io::Cursor::new(&mut buffer)),
            &Encryption::Passphrase(passphrase.clone()),
        )
        .expect("sink is buildable");
        sink.write_all(plaintext).expect("plaintext is writable");
        sink.finish().expect("sink finishes");

        assert!(buffer.starts_with(b"age-encryption.org/"));

        let mut reader = decrypting_reader(io::Cursor::new(&buffer), Some(&passphrase), &[])
            .expect("reader opens");
        let mut round_tripped = Vec::new();
        reader
            .read_to_end(&mut round_tripped)
            .expect("ciphertext is readable");
        assert_eq!(round_tripped, plaintext);
    }

    #[test]
    fn the_wrong_passphrase_is_reported_as_a_wrong_passphrase() {
        let mut buffer = Vec::new();
        let mut sink = Sink::new(
            Box::new(io::Cursor::new(&mut buffer)),
            &Encryption::Passphrase(Zeroizing::new("right".to_string())),
        )
        .expect("sink is buildable");
        sink.write_all(b"secret").expect("plaintext is writable");
        sink.finish().expect("sink finishes");

        let wrong = Zeroizing::new("wrong".to_string());
        let opened = decrypting_reader(io::Cursor::new(&buffer), Some(&wrong), &[]);
        assert!(matches!(opened, Err(Error::WrongPassphrase)));
    }

    #[test]
    fn a_damaged_payload_is_reported_as_damage_and_not_as_a_wrong_passphrase() {
        let passphrase = Zeroizing::new("right".to_string());
        let mut buffer = Vec::new();
        let mut sink = Sink::new(
            Box::new(io::Cursor::new(&mut buffer)),
            &Encryption::Passphrase(passphrase.clone()),
        )
        .expect("sink is buildable");
        sink.write_all(&[7u8; 4096]).expect("plaintext is writable");
        sink.finish().expect("sink finishes");

        // The last byte is inside the payload, well past the header the passphrase unwraps.
        let last = buffer.len() - 1;
        buffer[last] ^= 0xff;

        let mut reader = decrypting_reader(io::Cursor::new(&buffer), Some(&passphrase), &[])
            .expect("the header still opens, because the passphrase is right");
        let mut out = Vec::new();
        let failure = reader
            .read_to_end(&mut out)
            .expect_err("a flipped byte cannot authenticate");
        assert!(failure.to_string().contains("damaged"), "{failure}");
    }

    fn written(name: &str, encryption: &Encryption) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rad-backup-crypt-{name}-{}.age",
            std::process::id()
        ));
        let file = std::fs::File::create(&path).expect("scratch file is creatable");
        let mut sink = Sink::new(Box::new(file), encryption).expect("sink is buildable");
        sink.write_all(b"secret").expect("plaintext is writable");
        sink.finish().expect("sink finishes");
        path
    }

    #[test]
    fn only_a_passphrase_archive_is_the_one_that_asks_for_a_passphrase() {
        let passphrase = written(
            "passphrase",
            &Encryption::Passphrase(Zeroizing::new("open sesame".to_string())),
        );
        // The one case that must ask, and the only one.
        assert!(needs_passphrase(&passphrase).expect("header is readable"));

        // A recipient archive is opened with its private key. Asking for a passphrase here was
        // the bug: an escrow-key restore on a machine with no terminal had nothing to answer.
        let recipient = age::x25519::Identity::generate().to_public().to_string();
        let keyed = written("recipient", &Encryption::Recipients(vec![recipient]));
        assert!(!needs_passphrase(&keyed).expect("header is readable"));

        // A plaintext archive holds its secret in the clear and has nothing to unlock.
        let plain = written("plain", &Encryption::None);
        assert!(!needs_passphrase(&plain).expect("header is readable"));

        for path in [passphrase, keyed, plain] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn a_passphrase_cannot_reach_a_log_through_a_debug_format() {
        let encryption = Encryption::Passphrase(Zeroizing::new("hunter2".to_string()));
        let rendered = format!("{encryption:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("passphrase"), "{rendered}");
    }

    #[test]
    fn a_plaintext_sink_writes_exactly_what_it_was_given() {
        let mut buffer = Vec::new();
        let mut sink = Sink::new(Box::new(io::Cursor::new(&mut buffer)), &Encryption::None)
            .expect("sink is buildable");
        sink.write_all(b"no secrets here").expect("writable");
        sink.finish().expect("sink finishes");
        assert_eq!(buffer, b"no secrets here");
    }
}
