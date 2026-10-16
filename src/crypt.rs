//! Encryption of the archive, and where the passphrase for it comes from.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use age::secrecy::SecretString;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Environment variable holding the archive passphrase, for cron jobs that cannot be asked.
pub const ARCHIVE_PASSPHRASE_ENV: &str = "RAD_BACKUP_PASSPHRASE";
/// Environment variable `rad` itself reads for the key passphrase, honoured so that a
/// scheduled run needs no terminal.
pub const KEY_PASSPHRASE_ENV: &str = "RAD_PASSPHRASE";
/// Environment variable holding the passphrase that unlocks a `--identity` key file.
///
/// This variable stays apart from `ARCHIVE_PASSPHRASE_ENV`, because swapping the two fails
/// silently. A timer that verifies its own recipient-encrypted archives needs both.
pub const IDENTITY_PASSPHRASE_ENV: &str = "RAD_BACKUP_IDENTITY_PASSPHRASE";

/// How an archive is protected.
#[derive(Clone)]
pub enum Encryption {
    /// A passphrase only a person holds. The default.
    Passphrase(Zeroizing<String>),
    /// age recipients: `age1...` keys, or `ssh-ed25519 AAAA...` public keys, so an archive can
    /// be encrypted to another machine or to a friend holding escrow.
    Recipients(Vec<String>),
    /// No encryption. Only ever chosen explicitly, because an archive holds the identity's
    /// private key.
    Plaintext,
}

impl Encryption {
    pub fn is_encrypted(&self) -> bool {
        !matches!(self, Self::Plaintext)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Passphrase(_) => "passphrase",
            Self::Recipients(_) => "recipients",
            Self::Plaintext => "none",
        }
    }
}

/// Prints only the mode label. A derived `Debug` would print the passphrase `Zeroizing` wraps
/// into any log, panic message or `dbg!` that formats an `Encryption`.
impl std::fmt::Debug for Encryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Encryption::{}", self.label())
    }
}

/// The writing half of the container, owning the layer on the output so that finishing is
/// one call whatever the encryption mode.
pub enum Sink<'a> {
    Plaintext(Box<dyn Write + 'a>),
    Encrypted(Box<age::stream::StreamWriter<Box<dyn Write + 'a>>>),
}

impl<'a> Sink<'a> {
    pub fn new(output: Box<dyn Write + 'a>, encryption: &Encryption) -> Result<Self> {
        let encryptor = match encryption {
            Encryption::Plaintext => return Ok(Self::Plaintext(output)),
            Encryption::Passphrase(passphrase) => {
                age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_string()))
            }
            Encryption::Recipients(specs) => {
                let recipients = parse_recipients(specs)?;
                let recipient_refs: Vec<&dyn age::Recipient> =
                    recipients.iter().map(std::convert::AsRef::as_ref).collect();
                age::Encryptor::with_recipients(recipient_refs.into_iter())?
            }
        };
        // This error is pathless, because `output` may be any sink and the failure is age
        // setting up its own stream
        Ok(Self::Encrypted(Box::new(
            encryptor.wrap_output(output).map_err(Error::PathlessIo)?,
        )))
    }

    /// Closes the encryption layer. Every writing path must end here, because a sink dropped
    /// without it leaves a truncated archive that does not decrypt.
    pub fn finish(self) -> Result<()> {
        match self {
            Self::Plaintext(mut output) => output.flush().map_err(Error::PathlessIo),
            Self::Encrypted(writer) => {
                let mut output = writer.finish().map_err(Error::PathlessIo)?;
                output.flush().map_err(Error::PathlessIo)
            }
        }
    }
}

impl Write for Sink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plaintext(w) => w.write(buf),
            Self::Encrypted(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plaintext(w) => w.flush(),
            Self::Encrypted(w) => w.flush(),
        }
    }
}

/// The private keys offered for an archive encrypted to a recipient, and what unlocks one that
/// is itself passphrase-protected.
///
/// A passphrase-protected ssh key is the common case. Without the unlocking half, an archive
/// written with `--recipient <ssh pubkey>` cannot be opened by the holder of the right key.
#[derive(Clone, Default)]
pub struct Identities {
    /// The key files named by `--identity`, in the order they were given.
    pub files: Vec<PathBuf>,
    /// A file holding the passphrase for those keys, for a run with nobody at the terminal.
    pub passphrase_file: Option<PathBuf>,
    /// Whether there is anybody to prompt. When false, a locked key fails at once, so a timer
    /// never blocks on a question nobody answers.
    pub is_interactive: bool,
}

/// Wraps a reader so that it yields plaintext, whatever the archive was encrypted with.
pub fn decrypting_reader<'a, R: Read + 'a>(
    input: R,
    archive_passphrase: Option<&Zeroizing<String>>,
    identities: &Identities,
) -> Result<Box<dyn Read + 'a>> {
    let buffered = io::BufReader::new(input);
    let decryptor = match age::Decryptor::new_buffered(buffered) {
        Ok(decryptor) => decryptor,
        // `looks_encrypted` has already seen the age magic, so an unparseable header is
        // damage. age's own parse error names internals nobody can act on.
        Err(_) => {
            return Err(Error::Age(
                "the archive's encryption header is damaged".to_string(),
            ));
        }
    };

    if decryptor.is_scrypt() {
        let passphrase = archive_passphrase.ok_or_else(|| {
            Error::refused(
                "this archive is protected by a passphrase, and none was given",
                format!(
                    "run again and type the passphrase, pass --passphrase-file <path>, or set \
                     {ARCHIVE_PASSPHRASE_ENV}"
                ),
            )
        })?;
        let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));
        let reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            // Unwrapping the file key is the step a passphrase can be wrong at, so every
            // failure here is a wrong passphrase. Payload errors arrive later, as io errors.
            .map_err(|_| Error::WrongPassphrase)?;
        return Ok(Box::new(AuthenticatingReader(reader)));
    }

    if identities.files.is_empty() {
        return Err(Error::refused(
            "this archive is encrypted to a public key, not to a passphrase",
            "pass --identity <file> with the matching age or ssh private key",
        ));
    }
    let offered = OfferedKeys::read(identities)?;
    let identity_refs: Vec<&dyn age::Identity> = offered
        .identities
        .iter()
        .map(std::convert::AsRef::as_ref)
        .collect();
    // The blanket conversion reads `NoMatchingKeys` as a wrong passphrase, which is false on
    // this path, because no archive passphrase was asked for
    let reader = decryptor
        .decrypt(identity_refs.into_iter())
        .map_err(|failure| offered.explain(failure))?;
    Ok(Box::new(AuthenticatingReader(reader)))
}

/// A reader that says what a failure in the encrypted payload means.
///
/// age reports a chunk that fails authentication as a bare "decryption error", which reads as
/// a wrong secret. The secret is already proven right once the payload is read, so the bytes
/// changed after they were written.
struct AuthenticatingReader<R>(R);

impl<R: Read> Read for AuthenticatingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{e}. The archive is damaged or was changed after it was written"),
            )
        })
    }
}

/// Whether a file begins with an age header. A reader decides to decrypt by this, never by
/// the file name.
pub fn looks_encrypted(path: &Path) -> Result<bool> {
    use std::io::Read as _;

    const AGE_MAGIC: &[u8] = b"age-encryption.org/";
    let mut file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
    let mut head = [0u8; AGE_MAGIC.len()];
    match file.read_exact(&mut head) {
        Ok(()) => Ok(head == AGE_MAGIC),
        // A file shorter than the magic is not encrypted. Any other failure is a file this
        // function could not read, and calling it unencrypted makes `doctor` claim anyone can
        // read it.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Whether opening this archive asks for a passphrase, read from the archive's own header.
///
/// Every age file starts with the same magic, so `looks_encrypted` cannot tell a passphrase
/// archive from a recipient one, and whether `--identity` was passed cannot either. A prompt
/// for a recipient archive blocks an unattended restore that has nobody to answer it.
pub fn needs_passphrase(path: &Path) -> Result<bool> {
    if !looks_encrypted(path)? {
        return Ok(false);
    }
    let file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
    match age::Decryptor::new_buffered(io::BufReader::new(file)) {
        Ok(decryptor) => Ok(decryptor.is_scrypt()),
        // No passphrase opens an unparseable header, and the open that follows reports it
        Err(_) => Ok(false),
    }
}

/// What a passphrase is being read for, which decides whether it is asked for twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Locking something new. Asked for twice, because a typo here locks the identity away for
    /// good.
    Sealing,
    /// Opening something that already exists. Asked for once, because a typo just fails.
    Opening,
}

/// Which secret a passphrase protects.
///
/// Confusing two secrets fails quietly, because a scheduled run reads the wrong environment
/// variable, finds nothing, and asks a person who is not there. Each variant owns its
/// variable, its file flag and its remedy for an empty passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protects {
    /// The archive, when it is locked with a passphrase.
    Archive,
    /// A private key given with `--identity`, which is what opens an archive encrypted to a
    /// recipient.
    IdentityKey,
    /// The Radicle secret key in the home, under `rad`'s own variable.
    RadicleKey,
}

impl Protects {
    /// Every secret this tool may hold, for scrubbing from child-process environments.
    ///
    /// Never replace this walk with an array. A short array keeps every test green while a new
    /// secret leaks into every child process. `after` is a `match` with no wildcard, so a new
    /// variant stops the build until its arm is written.
    pub fn all() -> impl Iterator<Item = Self> {
        std::iter::successors(Some(Self::Archive), |current| current.after())
    }

    /// The next secret in the walk, or `None` at the end of it.
    ///
    /// A new variant is a compile error here, and its arm decides whether child processes get
    /// the new secret scrubbed.
    fn after(self) -> Option<Self> {
        match self {
            Self::Archive => Some(Self::IdentityKey),
            Self::IdentityKey => Some(Self::RadicleKey),
            Self::RadicleKey => None,
        }
    }

    /// The environment variable a run with nobody at the terminal sets.
    pub fn env(self) -> &'static str {
        match self {
            Self::Archive => ARCHIVE_PASSPHRASE_ENV,
            Self::IdentityKey => IDENTITY_PASSPHRASE_ENV,
            Self::RadicleKey => KEY_PASSPHRASE_ENV,
        }
    }

    /// The flag naming a file that holds this passphrase, if any.
    ///
    /// The Radicle key has none, because `words` asks for that passphrase to choose a new one,
    /// and a file holding an existing secret would give the restored key someone else's.
    fn passphrase_file_flag(self) -> Option<&'static str> {
        match self {
            Self::Archive => Some("--passphrase-file"),
            Self::IdentityKey => Some("--identity-passphrase-file"),
            Self::RadicleKey => None,
        }
    }

    /// Which passphrase this is, in the words a refusal uses.
    fn named(self) -> &'static str {
        match self {
            Self::Archive => "the archive passphrase",
            Self::IdentityKey => "the passphrase for the --identity key",
            Self::RadicleKey => "the passphrase for your Radicle key",
        }
    }

    /// What to do about an empty passphrase. `--plaintext` is offered only when an archive is
    /// being sealed, because the flag turns off the archive's encryption and nothing else.
    fn remedy_for_empty(self, purpose: Purpose) -> &'static str {
        match (self, purpose) {
            (Self::Archive, Purpose::Sealing) => {
                "use a passphrase that is not empty, or pass --plaintext to create an archive \
                 without encryption"
            }
            (Self::Archive, Purpose::Opening) => "give the passphrase the archive was created with",
            (Self::IdentityKey, _) => "give the passphrase that unlocks the --identity key",
            (Self::RadicleKey, Purpose::Sealing) => {
                "choose a passphrase that is not empty. It protects your key on disk"
            }
            (Self::RadicleKey, Purpose::Opening) => "give the passphrase for your Radicle key",
        }
    }
}

/// Reads a passphrase from the environment, a file, or the person at the terminal.
pub fn read_passphrase(
    protects: Protects,
    file: Option<&Path>,
    prompt: &str,
    purpose: Purpose,
    is_interactive: bool,
) -> Result<Zeroizing<String>> {
    let variable = protects.env();
    let remedy = protects.remedy_for_empty(purpose);
    if let Some(path) = file {
        // The read is zeroized before the trim, because the untrimmed copy holds it too
        let untrimmed =
            Zeroizing::new(std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?);
        let trimmed = Zeroizing::new(untrimmed.trim_end_matches(['\n', '\r']).to_string());
        return refuse_if_empty(trimmed, &format!("{} is empty", path.display()), remedy);
    }
    if let Ok(value) = std::env::var(variable) {
        // `std::env::var` answers Ok("") for a set but empty variable, as the EnvironmentFile
        // line `RAD_BACKUP_PASSPHRASE=` gives. Unchecked, age encrypts to the empty string.
        return refuse_if_empty(
            Zeroizing::new(value),
            &format!("{variable} is empty"),
            remedy,
        );
    }
    if !is_interactive {
        let file_instead = match protects.passphrase_file_flag() {
            Some(flag) => format!(", or pass {flag} <path>"),
            None => String::new(),
        };
        return Err(Error::refused(
            format!(
                "{} is needed, but there is no terminal to ask for it",
                protects.named()
            ),
            format!("set {variable}{file_instead}"),
        ));
    }

    let first = refuse_if_empty(
        Zeroizing::new(rpassword::prompt_password(prompt).map_err(Error::PathlessIo)?),
        "nothing was typed",
        remedy,
    )?;
    if purpose == Purpose::Sealing {
        let again = Zeroizing::new(
            rpassword::prompt_password("Repeat passphrase: ").map_err(Error::PathlessIo)?,
        );
        if *first != *again {
            return Err(Error::refused(
                "the two passphrases do not match",
                "run the command again and type the same passphrase twice",
            ));
        }
    }
    Ok(first)
}

/// Refuses an empty passphrase whichever source it came from.
///
/// age accepts an empty passphrase, and the file it writes reports as encrypted everywhere
/// and opens for anyone who presses Enter.
fn refuse_if_empty(
    passphrase: Zeroizing<String>,
    because: &str,
    remedy: &str,
) -> Result<Zeroizing<String>> {
    if passphrase.is_empty() {
        return Err(Error::refused(
            format!("{because}. The passphrase cannot be empty"),
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
            format!("`{spec}` is not a public key rad-backup can encrypt to"),
            "pass an age public key (age1...) or an ssh public key (ssh-ed25519 AAAA...)",
        ));
    }
    Ok(recipients)
}

/// The `--identity` key files as age wants them, with a record of what unlocking each did.
///
/// age answers `NoMatchingKeys` both for a key that is not a recipient and for one that stayed
/// locked. The record tells the two apart, so the holder of the right key is not told it is
/// the wrong one in the middle of a recovery.
struct OfferedKeys {
    identities: Vec<Box<dyn age::Identity>>,
    /// The key file behind each entry of `identities`, in the same order age tries them.
    offered: Vec<PathBuf>,
    passphrases: KeyPassphrases,
    /// Key files age was handed nothing for, each with why. One unusable key must not end a
    /// recovery, because `for k in ~/.ssh/id_*` passes an ecdsa key beside the ed25519 one.
    skipped: Vec<String>,
}

impl OfferedKeys {
    fn read(identities: &Identities) -> Result<Self> {
        let passphrases = KeyPassphrases::default();
        let mut parsed: Vec<Box<dyn age::Identity>> = Vec::with_capacity(identities.files.len());
        let mut offered = Vec::with_capacity(identities.files.len());
        let mut skipped = Vec::new();
        for path in &identities.files {
            // The buffer holds a private key, so it is wiped at the end of this iteration
            let text =
                Zeroizing::new(std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?);
            if let Ok(identity) = age::x25519::Identity::from_str(text.trim()) {
                parsed.push(Box::new(identity));
                offered.push(path.clone());
                continue;
            }
            // The file name lets every message about this key say which file to go and find
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
                is_interactive: identities.is_interactive,
                asked: passphrases.clone(),
            })));
            offered.push(path.clone());
        }
        // The run stops here only when no key is left to try, because then it cannot succeed.
        // With one usable key left, the skipped ones become a footnote.
        if parsed.is_empty() && !skipped.is_empty() {
            return Err(Error::refused(
                format!(
                    "none of the --identity keys can be used. {}",
                    skipped.join(". ")
                ),
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

    /// Says why the archive did not open, in terms of what each key file did.
    fn explain(&self, failure: age::DecryptError) -> Error {
        let footnote = match self.skipped.is_empty() {
            true => String::new(),
            false => format!(". Skipped: {}", self.skipped.join(". ")),
        };
        match failure {
            // age returns this for a wrong passphrase and also for a right one over a key type
            // it cannot use (an encrypted ecdsa or `sk-ssh-*` key passes `read` as merely
            // encrypted). age stops at the first failing key, so later keys were never tried.
            age::DecryptError::KeyDecryptionFailed => {
                let culprit = self.passphrases.last_answered();
                let named = culprit
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "one of the --identity keys".to_string());
                let untried = self.after(culprit.as_deref());
                let rest = match untried.is_empty() {
                    true => String::new(),
                    false => format!(
                        ". age stops at the first key it cannot use, so these keys were not \
                         tried: {untried}"
                    ),
                };
                Error::KeyNotUsable {
                    what: format!(
                        "could not unlock {named} with the passphrase given. Either the \
                         passphrase is wrong, or age cannot use this type of key{rest}{footnote}"
                    ),
                    remedy: "check the passphrase. Or pass --identity with only the key the \
                             archive was encrypted to"
                        .to_string(),
                }
            }
            age::DecryptError::NoMatchingKeys if !self.passphrases.locked().is_empty() => {
                Error::KeysStayedLocked {
                    what: format!(
                        "the archive could not be tried with a key that stayed locked: \
                         {}{footnote}",
                        self.passphrases.locked()
                    ),
                    remedy: format!(
                        "pass --identity-passphrase-file <path> or set \
                         {IDENTITY_PASSPHRASE_ENV}. Or run the command in a terminal to type \
                         the passphrase"
                    ),
                }
            }
            age::DecryptError::NoMatchingKeys => Error::refused(
                format!("none of the --identity keys opens this archive{footnote}"),
                "pass --identity with the private key the archive was encrypted to",
            ),
            // Every remaining variant means the ciphertext did not authenticate. The blanket
            // conversion hedges on an archive passphrase, which this path never asked for.
            other => Error::Age(format!(
                "{other}. The archive is damaged or was changed after it was written"
            )),
        }
    }

    /// The key files after `culprit` in the order age was given them, which age never reached.
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
            .join(", ")
    }
}

/// Why age will not read a key file, as one clause for a one-line refusal.
///
/// age's own explanation is a multi-line block that names `rage`, a tool the reader did not
/// run.
struct WhyUnsupported<'a>(&'a age::ssh::UnsupportedKey);

impl std::fmt::Display for WhyUnsupported<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            age::ssh::UnsupportedKey::EncryptedPem => write!(
                f,
                "an encrypted PEM key, which age cannot read. Run `ssh-keygen -p -m RFC4716` \
                 on it to convert it"
            ),
            age::ssh::UnsupportedKey::EncryptedSsh(cipher) => write!(
                f,
                "encrypted with {cipher}, which age cannot read. Run `ssh-keygen -p` on it to \
                 re-encrypt it"
            ),
            age::ssh::UnsupportedKey::Hardware(kind) => {
                write!(f, "a {kind} key on a hardware token, which age cannot use")
            }
            age::ssh::UnsupportedKey::Type(kind) => {
                write!(
                    f,
                    "a {kind} key. age can only use ssh-ed25519 and ssh-rsa keys"
                )
            }
        }
    }
}

/// What asking for each key file's passphrase produced, shared by every key's callbacks.
///
/// A remembered answer means an archive with several stanzas asks a person once. A remembered
/// refusal lets `OfferedKeys::explain` name the key that stayed locked.
#[derive(Clone, Default)]
struct KeyPassphrases(Arc<Mutex<Answers>>);

/// What has been asked so far, and of whom last.
#[derive(Default)]
struct Answers {
    by_key: BTreeMap<PathBuf, Asked>,
    /// The key file most recently given a passphrase. age tries keys in order and gives up at
    /// the first that fails, so this is the key age was working on when it stopped.
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
    /// Locks the answers, taking them back from a poisoned lock.
    ///
    /// A poisoned lock means a panic while a passphrase was read. The data behind it is a
    /// cache and a log, so a refusal would only add a second failure with less information.
    fn entries(&self) -> std::sync::MutexGuard<'_, Answers> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// The key files that were asked for a passphrase and did not get one, each with why.
    /// Empty when every key asked was answered.
    fn locked(&self) -> String {
        self.named(|asked| match asked {
            Asked::Refused(why) => Some(format!(" ({why})")),
            Asked::Given(_) => None,
        })
    }

    /// The key file a passphrase was most recently supplied for, which is the one that failed.
    ///
    /// age tries keys in order and stops at the first that errors, so every earlier key
    /// unlocked fine and must not be named as the fault.
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
            .join(", ")
    }
}

/// Supplies the passphrase that unlocks one `--identity` key file, when age asks for it.
///
/// age asks lazily, once it holds an encrypted key and a stanza that key might open, so an
/// unencrypted key or a plaintext archive never prompts.
#[derive(Clone)]
struct KeyPassphraseSource {
    key_file: PathBuf,
    passphrase_file: Option<PathBuf>,
    is_interactive: bool,
    asked: KeyPassphrases,
}

impl age::Callbacks for KeyPassphraseSource {
    /// Prints age's message to stderr. The message bypasses `Term`, because age sends it to
    /// ask a person to touch a hardware key, and `--quiet` must not drop that.
    fn display_message(&self, message: &str) {
        eprintln!("{message}");
    }

    /// Answers `None`, which age documents as "no confirmation UI". A default "yes" would
    /// answer a question nobody was shown.
    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    /// Answers `None`. Only plugins ask for non-private input, and this tool needs none.
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
        // The prompt says it wants the key's passphrase, because the person may have just been
        // asked for the archive's. age's own description names only the file.
        let answer = read_passphrase(
            Protects::IdentityKey,
            self.passphrase_file.as_deref(),
            &format!("Passphrase for the key {}: ", self.key_file.display()),
            Purpose::Opening,
            self.is_interactive,
        );
        let (remembered, given) = match answer {
            Ok(passphrase) => {
                let secret = SecretString::from(passphrase.to_string());
                (Asked::Given(passphrase), Some(secret))
            }
            Err(why) => (Asked::Refused(why.one_line()), None),
        };
        // age stops at the first key that fails, so the last key answered is the one to name
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

    /// `doctor` renders "not encrypted" as readable by anyone, so that claim must never come
    /// from a failed read.
    #[test]
    fn a_file_that_could_not_be_read_is_not_reported_as_unencrypted() {
        let dir = std::env::temp_dir().join(format!("rad-backup-looks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");

        let short = dir.join("short");
        std::fs::write(&short, b"age").expect("scratch file is writable");
        assert!(
            !looks_encrypted(&short).expect("a file shorter than the magic is an answer"),
            "a three-byte file is not an age file"
        );

        // Linux opens a directory and fails on the read, which is the shape this guards
        let refused = looks_encrypted(&dir);
        assert!(refused.is_err(), "{refused:?}");

        let _ = std::fs::remove_dir_all(dir);
    }

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

        // The last byte is inside the payload, well past the header the passphrase unwraps
        let last = buffer.len() - 1;
        buffer[last] ^= 0xff;

        let mut reader = decrypting_reader(
            io::Cursor::new(&buffer),
            Some(&passphrase),
            &Identities::default(),
        )
        .expect("the header still opens, because the passphrase is right");
        let mut read_back = Vec::new();
        let failure = reader
            .read_to_end(&mut read_back)
            .expect_err("a flipped byte cannot authenticate");
        assert!(failure.to_string().contains("damaged"), "{failure}");
    }

    use crate::key::tests::TestScratch;

    /// The refusal for a key that is not a recipient, which the other failures must not say.
    const NO_KEY_OPENS_IT: &str = "none of the --identity keys opens this archive";

    fn scratch_path(scratch: &TestScratch, name: &str) -> PathBuf {
        scratch.path_of(&format!("{name}.age"))
    }

    /// Owner-only, because an archive holds the secret its key unlocks, and `File::create`
    /// follows a symlink planted under the name.
    fn written_archive(scratch: &TestScratch, name: &str, encryption: &Encryption) -> PathBuf {
        let path = scratch_path(scratch, name);
        let file = crate::perms::create_private_file(&path).expect("scratch file is creatable");
        let mut sink = Sink::new(Box::new(file), encryption).expect("sink is buildable");
        sink.write_all(b"secret").expect("plaintext is writable");
        sink.finish().expect("sink finishes");
        path
    }

    /// A throwaway ed25519 key file and the `ssh-ed25519 AAAA...` line naming its public half.
    ///
    /// The key goes through `key::openssh_from_seed`, the path a key restored from words
    /// takes, so the fixture matches real keys. Two `seed` values give unrelated identities.
    fn ssh_key_file(
        scratch: &TestScratch,
        name: &str,
        seed: u8,
        passphrase: Option<&str>,
    ) -> (PathBuf, String) {
        let seed = Zeroizing::new([seed; 32]);
        let openssh = crate::key::openssh_from_seed(
            &seed,
            passphrase.map(|p| Zeroizing::new(p.to_string())).as_ref(),
        )
        .expect("a key is buildable from a seed");
        let recipient = crate::key::identity_from_seed(&seed)
            .and_then(|identity| identity.to_openssh())
            .expect("the public half is renderable");
        let path = scratch_path(scratch, name);
        let mut file = crate::perms::create_private_file(&path).expect("scratch key is creatable");
        file.write_all(openssh.as_bytes())
            .expect("scratch key is writable");
        (path, recipient)
    }

    /// Owner-only, because `/tmp` is shared and SECURITY.md requires passphrase files to be
    /// private.
    fn passphrase_file(scratch: &TestScratch, name: &str, passphrase: &str) -> PathBuf {
        let path = scratch_path(scratch, name);
        let mut file = crate::perms::create_private_file(&path).expect("scratch file is creatable");
        file.write_all(passphrase.as_bytes())
            .expect("scratch passphrase file is writable");
        path
    }

    /// Opens a recipient-encrypted archive the way `--identity` does, with no terminal, which
    /// is how a timer meets every case below.
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
                is_interactive: false,
            },
        )?;
        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(Error::PathlessIo)?;
        Ok(plaintext)
    }

    #[test]
    fn a_passphrase_protected_key_opens_the_archive_it_is_a_recipient_of() {
        let scratch = TestScratch::create("crypt-locked");
        let (key, recipient) = ssh_key_file(&scratch, "locked-key", 7, Some("hunter2"));
        let archive = written_archive(&scratch, "locked", &Encryption::Recipients(vec![recipient]));
        let unlocks = passphrase_file(&scratch, "locked-pass", "hunter2\n");

        let plaintext = opened_with(&archive, std::slice::from_ref(&key), Some(&unlocks))
            .expect("the right key with the right passphrase opens the archive");

        assert_eq!(plaintext, b"secret");
    }

    /// An empty passphrase file is a mistake. After `touch pass`, a scheduled restore would
    /// otherwise hand age an empty string and report the key as the wrong one.
    #[test]
    fn an_empty_identity_passphrase_file_is_refused_rather_than_offered_to_age() {
        let scratch = TestScratch::create("crypt-empty-pass");
        let (key, recipient) = ssh_key_file(&scratch, "empty-pass-key", 13, Some("hunter2"));
        let archive = written_archive(
            &scratch,
            "empty-pass",
            &Encryption::Recipients(vec![recipient]),
        );
        let empty = passphrase_file(&scratch, "empty-pass-file", "");

        let failure = opened_with(&archive, std::slice::from_ref(&key), Some(&empty))
            .expect_err("an empty passphrase unlocks nothing");

        let said = failure.one_line();
        assert!(said.contains("stayed locked"), "{said}");
        assert!(said.contains("is empty"), "{said}");
    }

    #[test]
    fn a_wrong_passphrase_for_the_key_is_reported_as_that_and_not_as_a_key_that_does_not_match() {
        let scratch = TestScratch::create("crypt-wrong-pass");
        let (key, recipient) = ssh_key_file(&scratch, "wrong-pass-key", 8, Some("hunter2"));
        let archive = written_archive(
            &scratch,
            "wrong-pass",
            &Encryption::Recipients(vec![recipient]),
        );
        let unlocks = passphrase_file(&scratch, "wrong-pass-file", "not hunter2");

        let failure = opened_with(&archive, std::slice::from_ref(&key), Some(&unlocks))
            .expect_err("a wrong key passphrase cannot open the archive");

        let said = failure.one_line();
        assert!(said.contains(&key.display().to_string()), "{said}");
        assert!(matches!(failure, Error::KeyNotUsable { .. }), "{said}");
        // age itself reports a non-recipient here, which sends the holder of the right key
        // looking for another
        assert!(!said.contains(NO_KEY_OPENS_IT), "{said}");
    }

    /// age stops at the first key it cannot use, so exactly one key is the failure, and a key
    /// that unlocked must not be named beside it.
    #[test]
    fn a_key_that_unlocked_is_not_named_beside_the_one_that_did_not() {
        let scratch = TestScratch::create("crypt-two");
        // One passphrase file, right for the first key and wrong for the second, as when two
        // locked keys share one --identity-passphrase-file
        let (first, _) = ssh_key_file(&scratch, "two-first", 14, Some("hunter2"));
        let (second, recipient) = ssh_key_file(&scratch, "two-second", 15, Some("different"));
        let archive = written_archive(&scratch, "two", &Encryption::Recipients(vec![recipient]));
        let unlocks = passphrase_file(&scratch, "two-pass", "hunter2");

        let failure = opened_with(&archive, &[first.clone(), second.clone()], Some(&unlocks))
            .expect_err("the recipient key's passphrase was not the one given");

        let said = failure.one_line();
        assert!(said.contains(&second.display().to_string()), "{said}");
        assert!(!said.contains(&first.display().to_string()), "{said}");
    }

    #[test]
    fn a_key_that_stayed_locked_is_named_instead_of_being_called_the_wrong_key() {
        let scratch = TestScratch::create("crypt-no-pass");
        let (key, recipient) = ssh_key_file(&scratch, "no-pass-key", 9, Some("hunter2"));
        let archive = written_archive(
            &scratch,
            "no-pass",
            &Encryption::Recipients(vec![recipient]),
        );

        // No passphrase file, no variable and nobody to prompt, which is how a timer runs
        let failure = opened_with(&archive, std::slice::from_ref(&key), None)
            .expect_err("a key nothing can unlock opens nothing");

        let said = failure.one_line();
        assert!(said.contains("stayed locked"), "{said}");
        assert!(said.contains(&key.display().to_string()), "{said}");
        assert!(said.contains(IDENTITY_PASSPHRASE_ENV), "{said}");
        assert!(!said.contains(NO_KEY_OPENS_IT), "{said}");
    }

    #[test]
    fn an_unrelated_key_is_still_reported_as_a_key_the_archive_was_not_encrypted_to() {
        let scratch = TestScratch::create("crypt-unrelated");
        let (_, recipient) = ssh_key_file(&scratch, "unrelated-recipient", 10, None);
        let (other, _) = ssh_key_file(&scratch, "unrelated-key", 11, None);
        let archive = written_archive(
            &scratch,
            "unrelated",
            &Encryption::Recipients(vec![recipient]),
        );

        let failure = opened_with(&archive, std::slice::from_ref(&other), None)
            .expect_err("a key that is not a recipient opens nothing");

        let said = failure.one_line();
        assert!(said.contains(NO_KEY_OPENS_IT), "{said}");
        assert!(!said.contains("stayed locked"), "{said}");
    }

    /// An encrypted key in the PEM format `ssh-keygen` wrote before OpenSSH 7.8, which age
    /// recognises and cannot use. The body is filler, because nothing decodes that far.
    const LEGACY_PEM_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
         Proc-Type: 4,ENCRYPTED\n\
         DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\
         \n\
         QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2\n\
         -----END RSA PRIVATE KEY-----\n";

    /// Owner-only although the body is filler, because a key-shaped test file at the umask
    /// default is the pattern a real key gets copied from.
    fn legacy_key_file(scratch: &TestScratch, name: &str) -> PathBuf {
        let path = scratch_path(scratch, name);
        let mut file = crate::perms::create_private_file(&path).expect("scratch key is creatable");
        file.write_all(LEGACY_PEM_KEY.as_bytes())
            .expect("scratch key is writable");
        path
    }

    #[test]
    fn a_key_age_cannot_use_is_named_as_that_rather_than_as_the_wrong_key() {
        let scratch = TestScratch::create("crypt-unsupported");
        let (_, recipient) = ssh_key_file(&scratch, "unsupported-recipient", 12, None);
        let archive = written_archive(
            &scratch,
            "unsupported",
            &Encryption::Recipients(vec![recipient]),
        );
        let key = legacy_key_file(&scratch, "unsupported-key");

        let failure = opened_with(&archive, std::slice::from_ref(&key), None)
            .expect_err("a key age cannot use opens nothing");

        let said = failure.one_line();
        assert!(said.contains(&key.display().to_string()), "{said}");
        assert!(!said.contains(NO_KEY_OPENS_IT), "{said}");
        // age's own message is a multi-line block recommending `rage`, a program the reader
        // did not run
        assert!(!said.contains("rage"), "{said}");
    }

    /// `for k in ~/.ssh/id_*` passes `id_ecdsa` beside `id_ed25519`, so one unusable key must
    /// not stop a recovery that the key beside it can finish.
    #[test]
    fn a_key_age_cannot_use_does_not_stop_the_key_beside_it_from_opening_the_archive() {
        let scratch = TestScratch::create("crypt-mixed");
        let (good, recipient) = ssh_key_file(&scratch, "mixed-good", 16, None);
        let archive = written_archive(&scratch, "mixed", &Encryption::Recipients(vec![recipient]));
        let legacy = legacy_key_file(&scratch, "mixed-legacy");

        // Unusable key first, so it is not merely being reached after the archive is open
        let plaintext = opened_with(&archive, &[legacy.clone(), good.clone()], None)
            .expect("a key age cannot read is not a reason to abandon the one that works");
        assert_eq!(plaintext, b"secret");
    }

    /// With no usable key at all, the run stops with the reason. "No key matched" would send
    /// someone to look for a key they already hold.
    #[test]
    fn a_run_with_no_usable_key_at_all_says_so_instead_of_reporting_no_match() {
        let scratch = TestScratch::create("crypt-none-usable");
        let (_, recipient) = ssh_key_file(&scratch, "none-usable-recipient", 17, None);
        let archive = written_archive(
            &scratch,
            "none-usable",
            &Encryption::Recipients(vec![recipient]),
        );
        let legacy = legacy_key_file(&scratch, "none-usable-legacy");

        let failure = opened_with(&archive, std::slice::from_ref(&legacy), None)
            .expect_err("nothing usable was offered");

        let said = failure.one_line();
        assert!(said.contains("can be used"), "{said}");
        assert!(!said.contains(NO_KEY_OPENS_IT), "{said}");
        assert!(said.contains(&legacy.display().to_string()), "{said}");
    }

    #[test]
    fn only_a_passphrase_archive_is_the_one_that_asks_for_a_passphrase() {
        let scratch = TestScratch::create("crypt-needs-passphrase");
        let passphrase = written_archive(
            &scratch,
            "passphrase",
            &Encryption::Passphrase(Zeroizing::new("open sesame".to_string())),
        );
        assert!(needs_passphrase(&passphrase).expect("header is readable"));

        // A recipient archive opens with its private key, so an escrow-key restore with no
        // terminal has no passphrase prompt to answer
        let recipient = age::x25519::Identity::generate().to_public().to_string();
        let keyed = written_archive(
            &scratch,
            "recipient",
            &Encryption::Recipients(vec![recipient]),
        );
        assert!(!needs_passphrase(&keyed).expect("header is readable"));

        // A plaintext archive holds its secret in the clear and has nothing to unlock
        let plain = written_archive(&scratch, "plain", &Encryption::Plaintext);
        assert!(!needs_passphrase(&plain).expect("header is readable"));
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
        let mut sink = Sink::new(
            Box::new(io::Cursor::new(&mut buffer)),
            &Encryption::Plaintext,
        )
        .expect("sink is buildable");
        sink.write_all(b"no secrets here").expect("writable");
        sink.finish().expect("sink finishes");
        assert_eq!(buffer, b"no secrets here");
    }
}
