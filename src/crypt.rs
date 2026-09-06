//! Encryption of the archive, and where the passphrase for it comes from.
//!
//! An archive holds the 32 bytes that are the user's identity, so encryption is the default
//! and plaintext is something the caller has to ask for out loud. Revisit never: an
//! unencrypted copy of a private key is the failure this tool exists to prevent.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use age::secrecy::SecretString;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Environment variable holding the archive passphrase, for cron jobs that cannot be asked.
pub const PASSPHRASE_ENV: &str = "RAD_BACKUP_PASSPHRASE";
/// Environment variable `rad` itself uses for the key passphrase, honoured for the same
/// reason: so that a scheduled run needs no interactive terminal.
pub const KEY_PASSPHRASE_ENV: &str = "RAD_PASSPHRASE";
/// Environment variable holding the passphrase that unlocks a `--identity` key file.
///
/// Its own name rather than a share of `PASSPHRASE_ENV`, because the two protect different
/// things and swapping them fails silently: the archive passphrase opens the archive, this one
/// opens the private key an archive was encrypted to. A timer that verifies its own
/// recipient-encrypted archives needs both, and needs to say which is which.
pub const IDENTITY_PASSPHRASE_ENV: &str = "RAD_BACKUP_IDENTITY_PASSPHRASE";

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
        // Pathless on purpose: `output` is whatever sink the caller opened, and the failure
        // here is age setting up its own stream rather than anything about a file.
        Ok(Self::Encrypted(Box::new(
            encryptor.wrap_output(output).map_err(Error::Bare)?,
        )))
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

/// The private keys offered for an archive encrypted to a recipient, and what unlocks one that
/// is itself passphrase-protected.
///
/// An ssh key with a passphrase on it is the normal and recommended state of an ssh key, so the
/// second half is not an extra: without it the common case of `--recipient <ssh pubkey>` writes
/// an archive that the holder of the right key cannot open.
#[derive(Clone, Default)]
pub struct Identities {
    /// The key files named by `--identity`, in the order they were given.
    pub files: Vec<PathBuf>,
    /// A file holding the passphrase for those keys, for a run with nobody at the terminal.
    pub passphrase_file: Option<PathBuf>,
    /// Whether there is anybody to prompt. False means a locked key fails at once rather than
    /// blocking a timer on a question that will never be answered.
    pub interactive: bool,
}

/// Wrap a reader so that it yields plaintext, whatever the archive was encrypted with.
pub fn decrypting_reader<'a, R: Read + 'a>(
    input: R,
    archive_passphrase: Option<&Zeroizing<String>>,
    identities: &Identities,
) -> Result<Box<dyn Read + 'a>> {
    let buffered = io::BufReader::new(input);
    let decryptor = match age::Decryptor::new_buffered(buffered) {
        Ok(decryptor) => decryptor,
        // Reached only once `looks_encrypted` has seen the age magic, so a header age
        // cannot parse is damage rather than a plaintext archive. age's own parse error names
        // internals nobody can act on, so this names the stream instead.
        Err(_) => return Err(Error::Age("not an age-encrypted stream".to_string())),
    };

    if decryptor.is_scrypt() {
        let passphrase = archive_passphrase.ok_or_else(|| {
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

    if identities.files.is_empty() {
        return Err(Error::refused(
            "this archive is encrypted to a key, not a passphrase",
            "pass --identity <file> with the age or ssh private key it was encrypted to",
        ));
    }
    let offered = OfferedKeys::read(identities)?;
    let borrowed: Vec<&dyn age::Identity> = offered
        .identities
        .iter()
        .map(std::convert::AsRef::as_ref)
        .collect();
    // Not through the blanket conversion: it reads `NoMatchingKeys` as a wrong passphrase,
    // which is right for the scrypt path above and nonsense here, where no archive passphrase
    // was asked for. It sent people to retype something that does not exist instead of to the
    // key file the archive was actually encrypted to.
    let reader = decryptor
        .decrypt(borrowed.into_iter())
        .map_err(|failure| offered.explain(failure))?;
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

/// What a passphrase is being read for, which is what decides whether it is asked for twice.
///
/// Taken as this rather than as a `bool`, because the call sites passed a bare `true` or
/// `false` that said nothing about which way round it went, and getting it round the wrong way
/// is not a bug that shows up until somebody needs the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Locking something new. Asked for twice, because a typo here locks the only copy of an
    /// identity away forever and nothing on earth reopens it.
    Sealing,
    /// Opening something that already exists. Asked for once, because a typo just fails.
    Opening,
}

/// Which of the three secrets a passphrase protects.
///
/// They lock different things, and confusing two of them fails quietly: a scheduled run reaches
/// for the wrong environment variable, finds nothing, and asks a person who is not there.
/// Taken as an enum so that the variable, the flag a failure sends the reader to, and the
/// sentence about what an empty one costs all come from one place instead of from each caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protects {
    /// The archive, when it is locked with a passphrase rather than to a recipient.
    Archive,
    /// A private key given with `--identity`, which is what opens an archive encrypted to a
    /// recipient.
    IdentityKey,
    /// The Radicle secret key in the home, which is `rad`'s own secret under `rad`'s own
    /// variable.
    RadicleKey,
}

impl Protects {
    /// Every secret this tool may hold, so the one place child processes are spawned scrubs
    /// all of them by walking rather than by listing names it has to remember to extend.
    ///
    /// Walked through `after` rather than read out of an array, because an array is not
    /// something the compiler can check for completeness: a fourth variant would leave a
    /// three-element `ALL`, the scrubbing loop, and every test that iterates it all green
    /// while a fourth secret leaked into every child process. `after` is a `match` with no
    /// wildcard, so the same variant stops the build until somebody says where it goes.
    pub fn all() -> impl Iterator<Item = Self> {
        std::iter::successors(Some(Self::Archive), |current| current.after())
    }

    /// The next secret in the walk, or `None` at the end of it. The chain has to reach every
    /// variant: adding one is a compile error here, and the arm that fixes it is the decision
    /// about whether the new secret is scrubbed from child processes.
    fn after(self) -> Option<Self> {
        match self {
            Self::Archive => Some(Self::IdentityKey),
            Self::IdentityKey => Some(Self::RadicleKey),
            Self::RadicleKey => None,
        }
    }

    /// The environment variable a run with nobody at the terminal sets instead.
    pub fn env(self) -> &'static str {
        match self {
            Self::Archive => PASSPHRASE_ENV,
            Self::IdentityKey => IDENTITY_PASSPHRASE_ENV,
            Self::RadicleKey => KEY_PASSPHRASE_ENV,
        }
    }

    /// The flag naming a file that holds this passphrase, where there is one. There is none
    /// for the Radicle key: the only place this tool asks for that one is `words`, which is
    /// choosing a NEW passphrase, and pointing that at a file of an existing secret would hand
    /// the restored key someone else's.
    fn passphrase_file_flag(self) -> Option<&'static str> {
        match self {
            Self::Archive => Some("--passphrase-file"),
            Self::IdentityKey => Some("--identity-passphrase-file"),
            Self::RadicleKey => None,
        }
    }

    /// What to do about an empty passphrase. `--plaintext` turns off the ARCHIVE's encryption
    /// and has nothing to do with a key's own passphrase, so offering it on a key path sent
    /// the reader after a flag that would not have helped.
    fn remedy_for_empty(self) -> &'static str {
        match self {
            Self::Archive => {
                "give a passphrase, or pass --plaintext if you really want no encryption"
            }
            Self::IdentityKey => "give the passphrase that unlocks that key",
            Self::RadicleKey => {
                "give a passphrase: it is the only thing protecting this key on disk"
            }
        }
    }
}

/// Read a passphrase from the environment, a file, or the person at the terminal.
pub fn read_passphrase(
    protects: Protects,
    file: Option<&Path>,
    prompt: &str,
    purpose: Purpose,
    interactive: bool,
) -> Result<Zeroizing<String>> {
    let variable = protects.env();
    let remedy = protects.remedy_for_empty();
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
        let file_instead = match protects.passphrase_file_flag() {
            Some(flag) => format!(", or pass {flag} <path>"),
            None => String::new(),
        };
        return Err(Error::refused(
            "a passphrase is needed and there is nobody to ask",
            format!("set {variable}{file_instead}"),
        ));
    }

    let first = refuse_if_empty(
        Zeroizing::new(rpassword::prompt_password(prompt).map_err(Error::Bare)?),
        "nothing was typed",
        remedy,
    )?;
    if purpose == Purpose::Sealing {
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

/// The `--identity` key files as age wants them, alongside the record of what unlocking each
/// one produced.
///
/// The record is what lets a failure name its cause. age answers `NoMatchingKeys` both for a
/// key that is not a recipient of the archive and for one it could not unlock, which is the
/// difference between "wrong key" and "right key, still locked": told the first when the second
/// is true, someone holding the correct key gives up on it in the middle of a recovery.
struct OfferedKeys {
    identities: Vec<Box<dyn age::Identity>>,
    /// The key file behind each entry of `identities`, in the same order age tries them.
    offered: Vec<PathBuf>,
    passphrases: KeyPassphrases,
    /// Key files age was handed nothing for, each with why. Recorded rather than refused:
    /// `--identity` takes several, `for k in ~/.ssh/id_*` is how people pass them, and one
    /// ecdsa key next to the right ed25519 one must not end a recovery.
    skipped: Vec<String>,
}

impl OfferedKeys {
    fn read(identities: &Identities) -> Result<Self> {
        let passphrases = KeyPassphrases::default();
        let mut parsed: Vec<Box<dyn age::Identity>> = Vec::with_capacity(identities.files.len());
        let mut offered = Vec::with_capacity(identities.files.len());
        let mut skipped = Vec::new();
        for path in &identities.files {
            // A private key, so the buffer it is read into is wiped when this loop ends rather
            // than left in whatever heap page it happened to land on.
            let text =
                Zeroizing::new(std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?);
            if let Ok(identity) = age::x25519::Identity::from_str(text.trim()) {
                parsed.push(Box::new(identity));
                offered.push(path.clone());
                continue;
            }
            // The file name goes in so that age's own prompt, which this replaces, and the
            // messages below name the key a person has to go and find.
            let key =
                age::ssh::Identity::from_buffer(text.as_bytes(), Some(path.display().to_string()))
                    .map_err(|e| Error::Age(format!("{}: {e}", path.display())))?;
            if let age::ssh::Identity::Unsupported(kind) = &key {
                skipped.push(format!("{} is {}", path.display(), WhyUnsupported(kind)));
                continue;
            }
            parsed.push(Box::new(key.with_callbacks(KeyPassphraseSource {
                key_file: path.clone(),
                passphrase_file: identities.passphrase_file.clone(),
                interactive: identities.interactive,
                asked: passphrases.clone(),
            })));
            offered.push(path.clone());
        }
        // Refused only when there is nothing left to try, because then the run has no chance
        // of succeeding and the reason is worth stopping on rather than burying under "no key
        // matched". With one usable key left, the skipped ones are a footnote, not a wall.
        if parsed.is_empty() && !skipped.is_empty() {
            return Err(Error::refused(
                format!("no key age can use was given: {}", skipped.join("; ")),
                "pass --identity with an ssh-ed25519, ssh-rsa or age key",
            ));
        }
        Ok(Self {
            identities: parsed,
            offered,
            passphrases,
            skipped,
        })
    }

    /// Say why the archive did not open, in terms of what the key files did rather than what
    /// age could tell from the header alone.
    fn explain(&self, failure: age::DecryptError) -> Error {
        let footnote = match self.skipped.is_empty() {
            true => String::new(),
            false => format!(" ({} was skipped)", self.skipped.join("; ")),
        };
        match failure {
            // Not "the passphrase was wrong", however much it looks like it. age returns this
            // both for a passphrase that did not decrypt the key and for one that DID, over a
            // key whose inner type age cannot use: an encrypted ecdsa or `sk-ssh-*` key parses
            // as merely encrypted, because the envelope carries only the cipher, so the check
            // above cannot see it. age also stops at the first key that fails, so the keys
            // after it were never tried. Blaming the passphrase alone had someone retyping a
            // correct secret while the key that opens the archive sat unread beside it.
            age::DecryptError::KeyDecryptionFailed => {
                let culprit = self.passphrases.last_answered();
                let named = culprit
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "a key given here".to_string());
                let untried = self.after(culprit.as_deref());
                let rest = match untried.is_empty() {
                    true => String::new(),
                    false => format!(
                        "; age stops at the first key it cannot use, so {untried} went untried"
                    ),
                };
                Error::refused(
                    format!(
                        "{named} could not be used with the passphrase given: either that \
                         passphrase is wrong, or age cannot use a key of that type{rest}{footnote}"
                    ),
                    "check the passphrase, or pass --identity with only the key this archive \
                     was encrypted to",
                )
            }
            age::DecryptError::NoMatchingKeys if !self.passphrases.locked().is_empty() => {
                Error::refused(
                    format!(
                        "this archive was never tried against {}, which stayed locked{footnote}",
                        self.passphrases.locked()
                    ),
                    format!(
                        "pass --identity-passphrase-file PATH, or set \
                         {IDENTITY_PASSPHRASE_ENV}, or re-run with stdin and stderr both on a \
                         terminal"
                    ),
                )
            }
            age::DecryptError::NoMatchingKeys => Error::refused(
                format!("none of the identities given open this archive{footnote}"),
                "pass --identity with the age or ssh private key it was encrypted to",
            ),
            // Every remaining variant means the ciphertext did not authenticate. Said flatly,
            // not through the blanket conversion, which hedges on "if the passphrase was
            // right": on this path no archive passphrase was ever asked for, so that sentence
            // sends the reader after a secret that does not exist.
            other => Error::Age(format!(
                "{other}: this archive did not authenticate, so the \
                 bytes changed after it was written"
            )),
        }
    }

    /// The key files that come after `culprit` in the order age was given them, which are the
    /// ones it never reached. Named so that a failure cannot imply every key was tried.
    fn after(&self, culprit: Option<&Path>) -> String {
        let Some(culprit) = culprit else {
            return String::new();
        };
        self.offered
            .iter()
            .skip_while(|path| path.as_path() != culprit)
            .skip(1)
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Why age will not read a key file, in this tool's own words.
///
/// age explains each kind itself, down to the `ssh-keygen` line that migrates off it, but it
/// writes a multi-line block with an ASCII rule through it, and it names `rage`, which is a
/// tool the reader did not run. One clause is what belongs in a one-line refusal.
struct WhyUnsupported<'a>(&'a age::ssh::UnsupportedKey);

impl std::fmt::Display for WhyUnsupported<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            age::ssh::UnsupportedKey::EncryptedPem => write!(
                f,
                "an encrypted PEM key, which age cannot read; `ssh-keygen -p -m RFC4716` \
                 rewrites it in a format it can"
            ),
            age::ssh::UnsupportedKey::EncryptedSsh(cipher) => write!(
                f,
                "encrypted with {cipher}, which age cannot read; `ssh-keygen -p` re-encrypts \
                 it with one it can"
            ),
            age::ssh::UnsupportedKey::Hardware(kind) => write!(
                f,
                "a {kind} key, which lives on a hardware token age has no way to drive"
            ),
            age::ssh::UnsupportedKey::Type(kind) => {
                write!(f, "a {kind} key; age reads ssh-ed25519 and ssh-rsa")
            }
        }
    }
}

/// What asking for each key file's passphrase produced, shared by every key's callbacks.
///
/// Two jobs, one map. An answer is remembered so that an archive whose header holds several
/// stanzas asks a person once rather than once per stanza, and a refusal is remembered so that
/// `OfferedKeys::explain` can name the key that stayed locked.
#[derive(Clone, Default)]
struct KeyPassphrases(Arc<Mutex<Answers>>);

/// What has been asked so far, and of whom last.
#[derive(Default)]
struct Answers {
    by_key: BTreeMap<PathBuf, Asked>,
    /// The key file most recently given a passphrase, which is the one age was working on
    /// when it stopped: it tries keys in order and gives up at the first that fails.
    last_answered: Option<PathBuf>,
}

/// What came back when one key file's passphrase was asked for.
enum Asked {
    Given(Zeroizing<String>),
    /// Nothing to ask, nobody to ask, or nothing typed. Carries the reason, so the run says
    /// which of those it was.
    Refused(String),
}

impl KeyPassphrases {
    /// A poisoned lock means a panic while a passphrase was being read. What is behind it is a
    /// cache and a diary, so taking it back is right: refusing would turn one panic into a
    /// second failure carrying less information than the first.
    fn entries(&self) -> std::sync::MutexGuard<'_, Answers> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// The key files that were asked for a passphrase and did not get one, each with why.
    /// Empty when every key that was asked was answered.
    fn locked(&self) -> String {
        self.named(|asked| match asked {
            Asked::Refused(why) => Some(format!(" ({why})")),
            Asked::Given(_) => None,
        })
    }

    /// The key file a passphrase was most recently supplied for.
    ///
    /// Which is the one that failed: age tries keys in the order they were given and stops at
    /// the first that errors, so the last key it asked about is the one it was asking about
    /// when it gave up. Listing every key a passphrase was supplied for, which is what this
    /// used to do, named keys that had unlocked perfectly well as if they were the fault.
    fn last_answered(&self) -> Option<PathBuf> {
        self.entries().last_answered.clone()
    }

    fn named(&self, describe: impl Fn(&Asked) -> Option<String>) -> String {
        self.entries()
            .by_key
            .iter()
            .filter_map(|(path, asked)| {
                describe(asked).map(|suffix| format!("{}{suffix}", path.display()))
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Supplies the passphrase that unlocks one `--identity` key file, when age asks for it.
///
/// age asks lazily, once it holds an encrypted key and a stanza that key might open, which is
/// why this is a callback rather than something read up front: an unencrypted key never asks,
/// and neither does a run that was handed a plaintext archive.
#[derive(Clone)]
struct KeyPassphraseSource {
    key_file: PathBuf,
    passphrase_file: Option<PathBuf>,
    interactive: bool,
    asked: KeyPassphrases,
}

impl age::Callbacks for KeyPassphraseSource {
    /// Only plugin identities reach this, and this tool has no plugin feature enabled, so it
    /// is here to be correct rather than to be seen. Straight to stderr rather than through
    /// `Term`: age says this when it wants a person to go and touch a hardware key, which is
    /// not narration `--quiet` may drop.
    fn display_message(&self, message: &str) {
        eprintln!("{message}");
    }

    /// No confirmation UI, which age documents as `None` rather than as a default answer. A
    /// silent "yes" here would be this tool guessing on a question it never showed anybody.
    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    /// Only plugins ask for non-private input, and nothing this tool does needs one.
    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, _description: &str) -> Option<SecretString> {
        let mut asked = self.asked.entries();
        if let Some(previous) = asked.by_key.get(&self.key_file) {
            return match previous {
                Asked::Given(passphrase) => Some(SecretString::from(passphrase.to_string())),
                Asked::Refused(_) => None,
            };
        }
        // age's own description is localised and names only the file. This asks in the tool's
        // own voice and says which of the two passphrases it wants, because a person who has
        // just been asked for the archive's is owed the difference.
        let answer = read_passphrase(
            Protects::IdentityKey,
            self.passphrase_file.as_deref(),
            &format!("Passphrase for the key {}: ", self.key_file.display()),
            Purpose::Opening,
            self.interactive,
        );
        let (remembered, given) = match answer {
            Ok(passphrase) => {
                let secret = SecretString::from(passphrase.to_string());
                (Asked::Given(passphrase), Some(secret))
            }
            Err(why) => (Asked::Refused(why.one_line()), None),
        };
        // The order matters as much as the answer: age stops at the first key that fails, so
        // the last key it asked about is the one to name when it does.
        if matches!(remembered, Asked::Given(_)) {
            asked.last_answered = Some(self.key_file.clone());
        }
        asked.by_key.insert(self.key_file.clone(), remembered);
        given
    }
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

        let mut reader = decrypting_reader(
            io::Cursor::new(&buffer),
            Some(&passphrase),
            &Identities::default(),
        )
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
        let opened = decrypting_reader(
            io::Cursor::new(&buffer),
            Some(&wrong),
            &Identities::default(),
        );
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

        let mut reader = decrypting_reader(
            io::Cursor::new(&buffer),
            Some(&passphrase),
            &Identities::default(),
        )
        .expect("the header still opens, because the passphrase is right");
        let mut out = Vec::new();
        let failure = reader
            .read_to_end(&mut out)
            .expect_err("a flipped byte cannot authenticate");
        assert!(failure.to_string().contains("damaged"), "{failure}");
    }

    fn scratch_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rad-backup-crypt-{name}-{}.age",
            std::process::id()
        ))
    }

    fn written(name: &str, encryption: &Encryption) -> PathBuf {
        let path = scratch_path(name);
        let file = std::fs::File::create(&path).expect("scratch file is creatable");
        let mut sink = Sink::new(Box::new(file), encryption).expect("sink is buildable");
        sink.write_all(b"secret").expect("plaintext is writable");
        sink.finish().expect("sink finishes");
        path
    }

    /// A throwaway ed25519 key file and the `ssh-ed25519 AAAA...` line naming its public half.
    ///
    /// Built through `key::openssh_from_seed`, which is the path a Radicle key restored from
    /// words takes, so the fixture cannot drift from the keys this tool actually meets. `seed`
    /// picks which key: two different values are two unrelated identities.
    fn ssh_key_file(name: &str, seed: u8, passphrase: Option<&str>) -> (PathBuf, String) {
        let seed = Zeroizing::new([seed; 32]);
        let openssh = crate::key::openssh_from_seed(
            &seed,
            passphrase.map(|p| Zeroizing::new(p.to_string())).as_ref(),
        )
        .expect("a key is buildable from a seed");
        let recipient = crate::key::identity_from_seed(&seed)
            .and_then(|identity| identity.to_openssh())
            .expect("the public half is renderable");
        let path = scratch_path(name);
        let mut file = crate::perms::create_private(&path).expect("scratch key is creatable");
        file.write_all(openssh.as_bytes())
            .expect("scratch key is writable");
        (path, recipient)
    }

    /// Owner-only, like every other passphrase this tool writes. `/tmp` is shared, and a
    /// fixture that drops a secret there at the umask default would be the one place in the
    /// crate that does not follow what SECURITY.md says about passphrase files.
    fn passphrase_file(name: &str, passphrase: &str) -> PathBuf {
        let path = scratch_path(name);
        let mut file = crate::perms::create_private(&path).expect("scratch file is creatable");
        file.write_all(passphrase.as_bytes())
            .expect("scratch passphrase file is writable");
        path
    }

    /// Deletes what a test wrote, however the test ends.
    ///
    /// A trailing `for path in [..] { remove_file(path) }` runs only when every assertion
    /// above it held, so the runs that leave private keys and passphrases in `/tmp` are
    /// exactly the failing ones somebody then re-runs.
    struct Scratch(Vec<PathBuf>);

    impl Scratch {
        fn keeping(paths: impl IntoIterator<Item = PathBuf>) -> Self {
            Self(paths.into_iter().collect())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// Open a recipient-encrypted archive the way `--identity` does, with no terminal to
    /// prompt on: every case below is one a timer has to survive without a person.
    fn opened_with(
        archive: &Path,
        key_files: &[PathBuf],
        passphrase_file: Option<&Path>,
    ) -> Result<Vec<u8>> {
        let file = std::fs::File::open(archive).map_err(|e| Error::io(archive, e))?;
        let mut reader = decrypting_reader(
            file,
            None,
            &Identities {
                files: key_files.to_vec(),
                passphrase_file: passphrase_file.map(Path::to_path_buf),
                interactive: false,
            },
        )?;
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).map_err(Error::Bare)?;
        Ok(plaintext)
    }

    #[test]
    fn a_passphrase_protected_key_opens_the_archive_it_is_a_recipient_of() {
        let (key, recipient) = ssh_key_file("locked-key", 7, Some("hunter2"));
        let archive = written("locked", &Encryption::Recipients(vec![recipient]));
        let unlocks = passphrase_file("locked-pass", "hunter2\n");

        let _scratch = Scratch::keeping([key.clone(), archive.clone(), unlocks.clone()]);

        let plaintext = opened_with(&archive, std::slice::from_ref(&key), Some(&unlocks))
            .expect("the right key with the right passphrase opens the archive");

        assert_eq!(plaintext, b"secret");
    }

    /// An empty passphrase file is a mistake, not an answer: `touch pass` and a scheduled
    /// restore would otherwise hand age an empty string and report the key as the wrong one.
    #[test]
    fn an_empty_identity_passphrase_file_is_refused_rather_than_offered_to_age() {
        let (key, recipient) = ssh_key_file("empty-pass-key", 13, Some("hunter2"));
        let archive = written("empty-pass", &Encryption::Recipients(vec![recipient]));
        let empty = passphrase_file("empty-pass-file", "");
        let _scratch = Scratch::keeping([key.clone(), archive.clone(), empty.clone()]);

        let failure = opened_with(&archive, std::slice::from_ref(&key), Some(&empty))
            .expect_err("an empty passphrase unlocks nothing");

        let said = failure.one_line();
        assert!(said.contains("stayed locked"), "{said}");
        assert!(said.contains("is empty"), "{said}");
    }

    #[test]
    fn a_wrong_passphrase_for_the_key_is_reported_as_that_and_not_as_a_key_that_does_not_match() {
        let (key, recipient) = ssh_key_file("wrong-pass-key", 8, Some("hunter2"));
        let archive = written("wrong-pass", &Encryption::Recipients(vec![recipient]));
        let unlocks = passphrase_file("wrong-pass-file", "not hunter2");

        let _scratch = Scratch::keeping([key.clone(), archive.clone(), unlocks.clone()]);

        let failure = opened_with(&archive, std::slice::from_ref(&key), Some(&unlocks))
            .expect_err("a wrong key passphrase cannot open the archive");

        let said = failure.one_line();
        assert!(said.contains(&key.display().to_string()), "{said}");
        assert!(said.contains("that passphrase is wrong"), "{said}");
        // Never as a key that is not a recipient, which is what age itself reports and what
        // sends someone holding the right key off to look for another one.
        assert!(!said.contains("none of the identities"), "{said}");
    }

    /// The bug in the first version of this message: it named every key a passphrase had been
    /// supplied for, so a key that unlocked perfectly well was listed as the failure beside
    /// the one that did not. age stops at the first key it cannot use, so exactly one is.
    #[test]
    fn a_key_that_unlocked_is_not_named_beside_the_one_that_did_not() {
        // One passphrase for both, right for the first and wrong for the second: the shape a
        // single --identity-passphrase-file has whenever two locked keys are offered.
        let (first, _) = ssh_key_file("two-first", 14, Some("hunter2"));
        let (second, recipient) = ssh_key_file("two-second", 15, Some("different"));
        let archive = written("two", &Encryption::Recipients(vec![recipient]));
        let unlocks = passphrase_file("two-pass", "hunter2");
        let _scratch = Scratch::keeping([
            first.clone(),
            second.clone(),
            archive.clone(),
            unlocks.clone(),
        ]);

        let failure = opened_with(&archive, &[first.clone(), second.clone()], Some(&unlocks))
            .expect_err("the recipient key's passphrase was not the one given");

        let said = failure.one_line();
        assert!(said.contains(&second.display().to_string()), "{said}");
        assert!(!said.contains(&first.display().to_string()), "{said}");
    }

    #[test]
    fn a_key_that_stayed_locked_is_named_instead_of_being_called_the_wrong_key() {
        let (key, recipient) = ssh_key_file("no-pass-key", 9, Some("hunter2"));
        let archive = written("no-pass", &Encryption::Recipients(vec![recipient]));

        // No passphrase file, no variable, nobody to prompt: the case a timer runs in, and the
        // one that used to report a correct key as the wrong one.
        let failure = opened_with(&archive, std::slice::from_ref(&key), None)
            .expect_err("a key nothing can unlock opens nothing");

        let said = failure.one_line();
        assert!(said.contains("stayed locked"), "{said}");
        assert!(said.contains(&key.display().to_string()), "{said}");
        assert!(said.contains(IDENTITY_PASSPHRASE_ENV), "{said}");
        assert!(!said.contains("none of the identities"), "{said}");
        for path in [key, archive] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn an_unrelated_key_is_still_reported_as_a_key_the_archive_was_not_encrypted_to() {
        let (recipient_key, recipient) = ssh_key_file("unrelated-recipient", 10, None);
        let (other, _) = ssh_key_file("unrelated-key", 11, None);
        let archive = written("unrelated", &Encryption::Recipients(vec![recipient]));
        let _scratch = Scratch::keeping([recipient_key, other.clone(), archive.clone()]);

        let failure = opened_with(&archive, std::slice::from_ref(&other), None)
            .expect_err("a key that is not a recipient opens nothing");

        let said = failure.one_line();
        assert!(said.contains("none of the identities"), "{said}");
        assert!(!said.contains("stayed locked"), "{said}");
    }

    /// An encrypted key in the PEM format `ssh-keygen` wrote before OpenSSH 7.8. age can tell
    /// what it is and cannot use it, which is a third thing from "wrong key" and "still
    /// locked"; the body is filler because nothing gets as far as decoding it.
    const LEGACY_PEM_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
         Proc-Type: 4,ENCRYPTED\n\
         DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\
         \n\
         QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2\n\
         -----END RSA PRIVATE KEY-----\n";

    #[test]
    fn a_key_age_cannot_use_is_named_as_that_rather_than_as_the_wrong_key() {
        let (recipient_key, recipient) = ssh_key_file("unsupported-recipient", 12, None);
        let archive = written("unsupported", &Encryption::Recipients(vec![recipient]));
        let key = scratch_path("unsupported-key");
        std::fs::write(&key, LEGACY_PEM_KEY).expect("scratch key is writable");
        let _scratch = Scratch::keeping([recipient_key, key.clone(), archive.clone()]);

        let failure = opened_with(&archive, std::slice::from_ref(&key), None)
            .expect_err("a key age cannot use opens nothing");

        let said = failure.one_line();
        assert!(said.contains(&key.display().to_string()), "{said}");
        assert!(!said.contains("none of the identities"), "{said}");
        // In this tool's words, not age's: age writes a four-line block with a rule through it
        // that recommends `rage`, which is not the program the reader just ran.
        assert!(!said.contains("rage"), "{said}");
    }

    /// The bug: a key age cannot read ended the whole run, refusing before it had tried
    /// anything. `--identity` takes several, `for k in ~/.ssh/id_*` is how people pass them,
    /// and `id_ecdsa` sitting next to `id_ed25519` is the ordinary shape of an ssh directory.
    /// Turning "one of your keys is unusable" into "you cannot restore", mid-recovery, is
    /// worse than the vague message it was meant to improve.
    #[test]
    fn a_key_age_cannot_use_does_not_stop_the_key_beside_it_from_opening_the_archive() {
        let (good, recipient) = ssh_key_file("mixed-good", 16, None);
        let archive = written("mixed", &Encryption::Recipients(vec![recipient]));
        let legacy = scratch_path("mixed-legacy");
        std::fs::write(&legacy, LEGACY_PEM_KEY).expect("scratch key is writable");
        let _scratch = Scratch::keeping([good.clone(), legacy.clone(), archive.clone()]);

        // Unusable key first, so it is not merely being reached after the archive is open.
        let plaintext = opened_with(&archive, &[legacy.clone(), good.clone()], None)
            .expect("a key age cannot read is not a reason to abandon the one that works");
        assert_eq!(plaintext, b"secret");
    }

    /// The other side of it: when nothing usable was given, the run stops with the reason
    /// rather than reporting that no key matched, which would send someone to look for a key
    /// they are already holding.
    #[test]
    fn a_run_with_no_usable_key_at_all_says_so_instead_of_reporting_no_match() {
        let (recipient_key, recipient) = ssh_key_file("none-usable-recipient", 17, None);
        let archive = written("none-usable", &Encryption::Recipients(vec![recipient]));
        let legacy = scratch_path("none-usable-legacy");
        std::fs::write(&legacy, LEGACY_PEM_KEY).expect("scratch key is writable");
        let _scratch = Scratch::keeping([recipient_key, legacy.clone(), archive.clone()]);

        let failure = opened_with(&archive, std::slice::from_ref(&legacy), None)
            .expect_err("nothing usable was offered");

        let said = failure.one_line();
        assert!(said.contains("no key age can use"), "{said}");
        assert!(said.contains(&legacy.display().to_string()), "{said}");
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
