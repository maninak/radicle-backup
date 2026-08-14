//! A printable recovery sheet.
//!
//! Paper outlives disks, formats and this program. The sheet carries the key twice, as a QR
//! code for a scanner and as text a human can retype, plus enough plain English that whoever
//! finds it in a drawer in ten years knows what they are holding.

use qrcode::QrCode;
use qrcode::render::svg;
use zeroize::Zeroizing;

use crate::cli::Paper;
use crate::cmd::{Ctx, fill, iso_stamp};
use crate::crypt;
use crate::error::{Error, Result};
use crate::key::{Identity, Protection, SecretKey};

const SHEET: &str = include_str!("../../assets/paper.html");

pub fn run(ctx: &Ctx, args: &Paper) -> Result<()> {
    ctx.home.require()?;
    let identity = Identity::read(ctx.home.public_key())?;
    let secret = SecretKey::read(ctx.home.secret_key())?;

    let (heading, caution, secret_text) = if args.words {
        let passphrase = match secret.protection() {
            Protection::Plaintext => None,
            Protection::Encrypted { .. } => Some(crypt::passphrase(
                crypt::KEY_PASSPHRASE_ENV,
                None,
                "Passphrase for the key: ",
                false,
                ctx.term.is_interactive(),
            )?),
        };
        let seed = secret.seed(passphrase.as_ref())?;
        let mnemonic = mnemonic(&seed)?;
        (
            "24 words",
            "These words ARE the key. Anyone holding this sheet is you. Keep it where you \
             would keep cash.",
            mnemonic,
        )
    } else {
        let key = Zeroizing::new(
            std::fs::read_to_string(ctx.home.secret_key())
                .map_err(|e| Error::io(ctx.home.secret_key(), e))?,
        );
        let caution = match secret.protection() {
            Protection::Encrypted { .. } => {
                "This key is still protected by its passphrase. Without that passphrase this \
                 sheet is useless, so store the passphrase somewhere else, and store it."
            }
            Protection::Plaintext => {
                "This key has NO passphrase, so this sheet is the key itself. Anyone holding \
                 it is you. Keep it where you would keep cash."
            }
        };
        ("the key file", caution, key)
    };

    let qr = qr_svg(&secret_text)?;
    let words_html = if args.words {
        word_grid(&secret_text)
    } else {
        format!("<pre class=\"key\">{}</pre>", escape(&secret_text))
    };

    let sheet = fill(
        SHEET,
        &[
            ("ALIAS", ctx.home.alias()?.as_deref().unwrap_or("unnamed")),
            ("DID", &identity.did()),
            ("FINGERPRINT", &identity.fingerprint()),
            ("CREATED", &iso_stamp(jiff::Timestamp::now())),
            ("HEADING", heading),
            ("CAUTION", caution),
            ("SECRET", &words_html),
            ("QR", &qr),
            ("TOOL", env!("CARGO_PKG_VERSION")),
        ],
    );

    match &args.output {
        Some(path) => {
            crate::cmd::write_owner_only(path, sheet.as_bytes())?;
            ctx.term.ok(&format!("wrote {}", path.display()));
            ctx.term
                .hint("open it in a browser and print it; then delete the file");
        }
        None => ctx.term.print(&sheet),
    }
    Ok(())
}

/// The 32-byte seed as a BIP-39 mnemonic: 24 words, checksummed, and readable after a bad
/// photocopy in a way a QR code is not.
fn mnemonic(seed: &Zeroizing<[u8; 32]>) -> Result<Zeroizing<String>> {
    let mnemonic = bip39::Mnemonic::from_entropy(seed.as_slice()).map_err(|e| {
        Error::refused(
            format!("could not turn this key into words: {e}"),
            "report this: a 32-byte seed should always convert",
        )
    })?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

fn qr_svg(text: &str) -> Result<String> {
    let code = QrCode::new(text.as_bytes()).map_err(|e| {
        Error::refused(
            format!("this key does not fit in a QR code: {e}"),
            "use --words, which is smaller",
        )
    })?;
    // The renderer emits an XML prolog, which is fine in a .svg file and wrong inside an HTML
    // document, where it renders as visible text. The sheet is HTML, so it goes.
    let rendered = code
        .render::<svg::Color>()
        .min_dimensions(320, 320)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(match rendered.find("<svg") {
        Some(start) => rendered[start..].to_string(),
        None => rendered,
    })
}

/// Numbered words, so a person reading them aloud and a person writing them down stay in step.
fn word_grid(mnemonic: &str) -> String {
    let mut html = String::from("<ol class=\"words\">");
    for word in mnemonic.split_whitespace() {
        html.push_str(&format!("<li>{}</li>", escape(word)));
    }
    html.push_str("</ol>");
    html
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_becomes_twenty_four_words_and_comes_back_as_the_same_seed() {
        let seed = Zeroizing::new([42u8; 32]);
        let words = mnemonic(&seed).expect("a seed converts");
        assert_eq!(words.split_whitespace().count(), 24);

        let parsed = bip39::Mnemonic::parse_normalized(&words).expect("the words parse");
        assert_eq!(parsed.to_entropy(), seed.as_slice());
    }

    #[test]
    fn the_word_grid_numbers_every_word_it_was_given() {
        let html = word_grid("alpha bravo charlie");
        assert_eq!(html.matches("<li>").count(), 3);
        assert!(html.contains("<li>bravo</li>"));
    }

    #[test]
    fn markup_in_an_alias_or_a_key_cannot_break_out_of_the_sheet() {
        assert_eq!(escape("<script>&"), "&lt;script&gt;&amp;");
    }

    #[test]
    fn a_key_file_fits_in_a_qr_code() {
        let seed = Zeroizing::new([7u8; 32]);
        let key = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let svg = qr_svg(&key).expect("a key file fits");
        // The sheet embeds this inline in HTML, where an XML prolog would render as text.
        assert!(svg.starts_with("<svg"), "{}", &svg[..svg.len().min(120)]);
        assert!(!svg.contains("<?xml"));
    }
}
