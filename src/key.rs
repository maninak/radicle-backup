//! Reading, inspecting and rebuilding the ed25519 keypair that is a Radicle identity.
//!
//! Secret material never leaves this module as a plain `Vec`: seeds and passphrases are
//! wrapped in `Zeroizing` so that a copy cannot outlive the operation that needed it.

use std::path::Path;

use ssh_key::rand_core::OsRng;
use ssh_key::{LineEnding, PrivateKey, PublicKey, private::Ed25519Keypair};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Multicodec prefix for an ed25519 public key, as the varint pair `did:key` expects.
const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];
/// The comment `rad auth` writes into the key file. Kept so a rebuilt key is byte-comparable
/// with one `rad` would have written.
const RADICLE_KEY_COMMENT: &str = "radicle";

/// A public key, and the two names Radicle shows it under.
pub struct Identity {
    key: PublicKey,
}

impl Identity {
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        Self::parse(&text).map_err(|e| Error::BadKey {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
    }

    /// Pure counterpart of [`Identity::read`], so the parsing can be tested without a file.
    pub fn parse(openssh: &str) -> Result<Self> {
        let key = PublicKey::from_openssh(openssh.trim())?;
        if key.key_data().ed25519().is_none() {
            return Err(Error::NotEd25519 {
                algorithm: key.algorithm().to_string(),
            });
        }
        Ok(Self { key })
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key
            .key_data()
            .ed25519()
            .map(|k| k.0)
            .expect("an Identity is only built from an ed25519 key")
    }

    /// The `did:key:z6Mk...` form: multicodec-tagged public key in base58btc, per the did:key
    /// method spec. This is the name that appears in every identity document.
    pub fn did(&self) -> String {
        let mut tagged = Vec::with_capacity(MULTICODEC_ED25519_PUB.len() + 32);
        tagged.extend_from_slice(&MULTICODEC_ED25519_PUB);
        tagged.extend_from_slice(&self.public_key_bytes());
        format!("did:key:z{}", bs58::encode(tagged).into_string())
    }

    /// The `z6Mk...` node identifier, which is the DID without its method prefix.
    pub fn node_id(&self) -> String {
        self.did()
            .strip_prefix("did:key:")
            .unwrap_or_default()
            .to_string()
    }

    /// The `SHA256:...` fingerprint `rad self` and `ssh-add -l` print.
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint(ssh_key::HashAlg::Sha256).to_string()
    }

    pub fn to_openssh(&self) -> Result<String> {
        Ok(self.key.to_openssh()?)
    }
}

/// How the secret key file protects itself. `Plaintext` is a finding, not a state: a key with
/// no passphrase is one stolen laptop away from a stolen identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protection {
    Plaintext,
    Encrypted { cipher: String, kdf: String },
}

impl Protection {
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted { .. })
    }
}

/// The secret key file, inspected without being decrypted.
pub struct SecretKey {
    key: PrivateKey,
}

impl SecretKey {
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| Error::io(path, e))?);
        let key = PrivateKey::from_openssh(&*bytes).map_err(|e| Error::BadKey {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        Ok(Self { key })
    }

    pub fn protection(&self) -> Protection {
        if self.key.is_encrypted() {
            Protection::Encrypted {
                cipher: self.key.cipher().to_string(),
                kdf: kdf_name(self.key.kdf()).to_string(),
            }
        } else {
            Protection::Plaintext
        }
    }

    /// The 32-byte seed, which is the whole of the identity. Everything else about a Radicle
    /// account is derived from it or refetchable.
    pub fn seed(&self, passphrase: Option<&Zeroizing<String>>) -> Result<Zeroizing<[u8; 32]>> {
        let decrypted;
        let key = if self.key.is_encrypted() {
            let passphrase = passphrase.ok_or_else(|| {
                Error::refused(
                    "this key is passphrase-protected",
                    "re-run and enter the passphrase, or set RAD_PASSPHRASE",
                )
            })?;
            decrypted = self
                .key
                .decrypt(passphrase.as_bytes())
                .map_err(|_| Error::WrongPassphrase)?;
            &decrypted
        } else {
            &self.key
        };
        let keypair = key.key_data().ed25519().ok_or_else(|| Error::NotEd25519 {
            algorithm: key.algorithm().to_string(),
        })?;
        Ok(Zeroizing::new(keypair.private.to_bytes()))
    }

    pub fn identity(&self) -> Result<Identity> {
        Identity::parse(&self.key.public_key().to_openssh()?)
    }
}

/// The name `ssh-keygen` prints for a key derivation function, which `ssh-key` models as an
/// enum without a `Display`.
fn kdf_name(kdf: &ssh_key::Kdf) -> &'static str {
    match kdf {
        ssh_key::Kdf::None => "none",
        ssh_key::Kdf::Bcrypt { .. } => "bcrypt",
        _ => "unknown",
    }
}

/// Rebuild a key file from a seed, which is how a paper or mnemonic backup comes home.
///
/// Passing `None` writes an unprotected key, which the caller must have said out loud.
pub fn openssh_from_seed(
    seed: &Zeroizing<[u8; 32]>,
    passphrase: Option<&Zeroizing<String>>,
) -> Result<Zeroizing<String>> {
    let keypair = Ed25519Keypair::from_seed(seed);
    let mut key = PrivateKey::new(keypair.into(), RADICLE_KEY_COMMENT)?;
    key.set_comment(RADICLE_KEY_COMMENT);
    let key = match passphrase {
        Some(passphrase) => key.encrypt(&mut OsRng, passphrase.as_bytes())?,
        None => key,
    };
    Ok(key.to_openssh(LineEnding::LF)?)
}

/// The public half of a seed, so a restore can prove it rebuilt the right identity before it
/// writes anything.
pub fn identity_from_seed(seed: &Zeroizing<[u8; 32]>) -> Result<Identity> {
    let keypair = Ed25519Keypair::from_seed(seed);
    let key = PrivateKey::new(keypair.into(), RADICLE_KEY_COMMENT)?;
    Identity::parse(&key.public_key().to_openssh()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kostis' own public key, and the DID and fingerprint `rad self` prints for it on rad
    /// 1.10.1. A real vector, so a wrong multicodec prefix or a wrong base58 alphabet cannot
    /// pass.
    const PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfJT4YlvXMI9h98D4SSswNV5S0voNrQaUZMCq0s0zK";
    const DID: &str = "did:key:z6MkvAFBkdph6yXSZDkkVqf9FfCcvkG29JD4KbwwnGphDRLV";
    const FINGERPRINT: &str = "SHA256:+ggv51RTNH8KlryICcYCnb67MXDyMjOpxQrIwP68xYU";

    #[test]
    fn a_public_key_yields_the_did_that_rad_self_shows_for_it() {
        let identity = Identity::parse(PUBLIC_KEY).expect("the vector is a valid ssh key");
        assert_eq!(identity.did(), DID);
        assert_eq!(identity.node_id(), DID.trim_start_matches("did:key:"));
        assert_eq!(identity.fingerprint(), FINGERPRINT);
    }

    #[test]
    fn public_key_bytes_are_the_last_thirty_two_bytes_of_the_ssh_blob() {
        let identity = Identity::parse(PUBLIC_KEY).expect("the vector is a valid ssh key");
        let expected =
            hex::decode("e95f253e1896f5cc23d87df03e124acc0d5794b4be836b41a519302ab4b34cca")
                .expect("the vector is valid hex");
        assert_eq!(identity.public_key_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn a_seed_round_trips_through_an_encrypted_key_file() {
        let seed = Zeroizing::new([7u8; 32]);
        let passphrase = Zeroizing::new("correct horse battery staple".to_string());
        let openssh = openssh_from_seed(&seed, Some(&passphrase)).expect("key is buildable");

        let path = scratch_file("encrypted-key", &openssh);
        let key = SecretKey::read(&path).expect("key is readable");
        assert!(key.protection().is_encrypted());
        assert_eq!(*key.seed(Some(&passphrase)).expect("decrypts"), *seed);

        let wrong = Zeroizing::new("hunter2".to_string());
        assert!(matches!(
            key.seed(Some(&wrong)),
            Err(Error::WrongPassphrase)
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_key_written_without_a_passphrase_reports_itself_as_plaintext() {
        let seed = Zeroizing::new([9u8; 32]);
        let openssh = openssh_from_seed(&seed, None).expect("key is buildable");

        let path = scratch_file("plaintext-key", &openssh);
        let key = SecretKey::read(&path).expect("key is readable");
        assert_eq!(key.protection(), Protection::Plaintext);
        assert_eq!(*key.seed(None).expect("needs no passphrase"), *seed);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_identity_rebuilt_from_a_seed_matches_the_one_stored_beside_it() {
        let seed = Zeroizing::new([3u8; 32]);
        let openssh = openssh_from_seed(&seed, None).expect("key is buildable");
        let path = scratch_file("identity-key", &openssh);
        let stored = SecretKey::read(&path).expect("key is readable");

        let from_seed = identity_from_seed(&seed).expect("seed yields an identity");
        assert_eq!(
            from_seed.did(),
            stored.identity().expect("key has a public half").did()
        );
        let _ = std::fs::remove_file(path);
    }

    fn scratch_file(name: &str, contents: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("rad-backup-test-{name}-{}", std::process::id()));
        std::fs::write(&path, contents).expect("scratch file is writable");
        path
    }
}
