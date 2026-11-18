//! What the conformance archives in `tests/fixtures` hold. `tests/conformance.rs` checks them
//! and `examples/write_fixtures.rs` writes them, so both build them here.

use std::io::Write as _;

use radicle_backup::container::{COMPRESSION_LEVEL, MODE_DOC, MODE_SECRET, Writer};
use radicle_backup::crypt::Encryption;
use radicle_backup::error::Result;
use radicle_backup::instructions;
use radicle_backup::key;
use radicle_backup::manifest::{
    IdentityInfo, Manifest, NodeInfo, PolicySummary, RepoSelection, SourceInfo, Tier, ToolInfo,
};
use zeroize::Zeroizing;

/// The passphrase of every encrypted fixture.
pub const PASSPHRASE: &str = "the fixture passphrase";
/// The passphrase on the private key inside the Grove-shaped fixture.
pub const KEY_PASSPHRASE: &str = "the fixture key passphrase";
/// The scrypt work factor the encrypted fixtures are pinned to, about 1 MiB and a few
/// milliseconds, so a test opens them cheaply. Grove writes 18.
pub const WORK_FACTOR: u8 = 10;
/// The zstd level Grove writes.
pub const GROVE_LEVEL: i32 = 3;

/// (a) A plaintext archive whose bytes the writer reproduces exactly.
pub const PLAINTEXT: &str = "plaintext.tar.zst";
/// (b) A passphrase archive holding what (a) holds.
pub const PASSPHRASE_ARCHIVE: &str = "passphrase.tar.zst.age";
/// (c) An archive written the way Grove writes one.
pub const GROVE: &str = "grove-level-3.tar.zst.age";

const RID: &str = "z3gqcJUoA1n9HaHKufZs5FCSGazv5";

/// (a), which holds no key and no salt, so its bytes depend on the writer alone.
pub fn plaintext() -> Result<Vec<u8>> {
    small_archive(&Encryption::Plaintext, None)
}

/// (b), whose bytes differ on every write because age draws a fresh salt and file key.
pub fn passphrase() -> Result<Vec<u8>> {
    small_archive(
        &Encryption::Passphrase(Zeroizing::new(PASSPHRASE.to_string())),
        Some(WORK_FACTOR),
    )
}

fn small_archive(encryption: &Encryption, work_factor: Option<u8>) -> Result<Vec<u8>> {
    let mut archive = Vec::new();
    let mut writer = Writer::create(
        Box::new(&mut archive),
        encryption,
        COMPRESSION_LEVEL,
        work_factor,
    )?;
    writer.add_bytes(
        "config.json",
        b"{\"node\":{\"alias\":\"fixture\"}}\n",
        MODE_DOC,
    )?;
    let bundle: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    writer.add_stream(
        &format!("repos/{RID}.bundle"),
        bundle.len() as u64,
        &mut bundle.as_slice(),
        MODE_SECRET,
    )?;
    let mut manifest = manifest(IdentityInfo {
        did: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_string(),
        node_id: "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_string(),
        alias: Some("fixture".to_string()),
        public_key: "ssh-ed25519 AAAA".to_string(),
        fingerprint: "SHA256:fixture".to_string(),
        key_is_encrypted: true,
    });
    writer.finish(&mut manifest)?;
    Ok(archive)
}

/// (c), an identity archive with a real key, written entry by entry through the push form at
/// Grove's level, so `rad-backup verify --deep` has a whole identity to check.
pub fn grove() -> Result<Vec<u8>> {
    // The identity the all-zero seed gives, which `tests/end_to_end.rs` also restores
    let seed = Zeroizing::new([0u8; 32]);
    let secret = key::openssh_from_seed(&seed, Some(&Zeroizing::new(KEY_PASSPHRASE.to_string())))?;
    let identity = key::identity_from_seed(&seed)?;
    let public = identity.to_openssh()?;
    let manifest_identity = IdentityInfo {
        did: identity.did(),
        node_id: identity.node_id(),
        alias: Some("fixture".to_string()),
        public_key: public.clone(),
        fingerprint: identity.fingerprint(),
        key_is_encrypted: true,
    };
    let mut manifest = manifest(manifest_identity);

    let mut archive = Vec::new();
    let mut writer = Writer::create(
        Box::new(&mut archive),
        &Encryption::Passphrase(Zeroizing::new(PASSPHRASE.to_string())),
        GROVE_LEVEL,
        Some(WORK_FACTOR),
    )?;
    let restore_doc = instructions::restore_doc(&manifest);
    let entries: [(&str, &[u8], u32); 5] = [
        ("keys/radicle", secret.as_bytes(), MODE_SECRET),
        ("keys/radicle.pub", public.as_bytes(), MODE_DOC),
        (
            "config.json",
            b"{\"node\":{\"alias\":\"fixture\"}}\n",
            MODE_DOC,
        ),
        ("RESTORE.md", restore_doc.as_bytes(), MODE_DOC),
        (
            "restore.sh",
            instructions::RESTORE_SCRIPT.as_bytes(),
            instructions::SCRIPT_MODE,
        ),
    ];
    for (path, bytes, mode) in entries {
        writer.begin_entry(path, bytes.len() as u64, mode)?;
        // Small, uneven chunks, the way a browser stream hands them over
        for chunk in bytes.chunks(97) {
            writer.write_entry(chunk)?;
        }
        writer.end_entry()?;
    }
    writer.finish(&mut manifest)?;
    Ok(archive)
}

/// A manifest whose every field is fixed, so a release does not change the fixtures.
fn manifest(identity: IdentityInfo) -> Manifest {
    Manifest {
        format: 1,
        tool: ToolInfo {
            name: "rad-backup".to_string(),
            version: "0.0.0-fixture".to_string(),
        },
        created: "2026-11-18T00:00:00Z".to_string(),
        tier: Tier::Identity,
        repo_selection: RepoSelection::None,
        identity,
        source: SourceInfo {
            host: None,
            rad_home: "/home/fixture/.radicle".to_string(),
            rad_version: None,
            git_version: None,
            os: "linux".to_string(),
            retires_key: None,
        },
        node: NodeInfo::default(),
        entries: Vec::new(),
        repos: Vec::new(),
        policies: PolicySummary::default(),
        warnings: Vec::new(),
    }
}

/// Writes every fixture into `dir`.
pub fn write_all(dir: &std::path::Path) -> std::io::Result<()> {
    let built = [
        (PLAINTEXT, plaintext()),
        (PASSPHRASE_ARCHIVE, passphrase()),
        (GROVE, grove()),
    ];
    for (name, bytes) in built {
        let bytes = bytes.map_err(std::io::Error::other)?;
        std::fs::File::create(dir.join(name))?.write_all(&bytes)?;
    }
    Ok(())
}
