//! A printable recovery sheet.

use std::io::IsTerminal;

use qrcode::QrCode;
use qrcode::render::svg;
use zeroize::Zeroizing;

use crate::cli::Paper;
use crate::cmd::{Ctx, fill, rfc3339_stamp};
use crate::crypt;
use crate::error::{Error, Result};
use crate::key::{Identity, Protection, SecretKey};

const SHEET_TEMPLATE: &str = include_str!("../../assets/paper.html");

pub fn run(ctx: &Ctx, args: &Paper) -> Result<()> {
    ctx.home.require_identity()?;
    let identity = Identity::read(ctx.home.public_key())?;
    let secret = SecretKey::read(ctx.home.secret_key())?;

    let (heading, caution, secret_text) = if args.words {
        let passphrase = match secret.protection() {
            Protection::Plaintext => None,
            Protection::Encrypted { .. } => Some(crypt::read_passphrase(
                crypt::Protects::RadicleKey,
                None,
                "Passphrase for your Radicle key: ",
                crypt::Purpose::Opening,
                ctx.term.is_interactive(),
            )?),
        };
        let seed = secret.seed(passphrase.as_ref())?;
        let mnemonic = mnemonic(&seed)?;
        (
            "24 words",
            "These words ARE the key. Anyone holding this sheet can act as you. Keep it where \
             you would keep cash.",
            mnemonic,
        )
    } else {
        let key = Zeroizing::new(
            std::fs::read_to_string(ctx.home.secret_key())
                .map_err(|e| Error::io(ctx.home.secret_key(), e))?,
        );
        let caution = match secret.protection() {
            Protection::Encrypted { .. } => {
                "This key is protected by its passphrase. The sheet is useless without it. Keep \
                 the passphrase somewhere safe, apart from this sheet."
            }
            Protection::Plaintext => {
                "This key has NO passphrase. This sheet is the key itself. Anyone holding it \
                 can act as you. Keep it where you would keep cash."
            }
        };
        ("the key file", caution, key)
    };

    // The QR encodes the key, so its SVG is key material too
    let qr = qr_svg(&secret_text)?;
    let secret_html = if args.words {
        word_grid(&secret_text)
    } else {
        key_block(&secret_text)
    };

    // `render` returns its buffer by move, so this wrapper wipes the buffer holding the sheet
    let sheet = Zeroizing::new(render(Sheet {
        alias: ctx.home.read_alias()?.as_deref().unwrap_or("unnamed"),
        did: &identity.did(),
        fingerprint: &identity.fingerprint(),
        created: &rfc3339_stamp(jiff::Timestamp::now()),
        heading,
        caution,
        secret_html: &secret_html,
        qr: &qr,
    }));

    match &args.output {
        Some(path) => {
            crate::perms::write_owner_only(path, sheet.as_bytes())?;
            ctx.term.ok(&format!("wrote {}", path.display()));
            ctx.term
                .hint("open it in a browser and print it. Then delete the file");
        }
        // A terminal keeps scrollback in memory and may log a session to disk, so a sheet
        // printed there outlives the zeroizing process. A pipe hands the bytes to one
        // program and ends, so a pipe is allowed.
        None if std::io::stdout().is_terminal() => {
            return Err(Error::refused(
                "the recovery sheet holds your key, so it is not printed to the terminal",
                "write it to a file with --output <path>, or pipe it to another program",
            ));
        }
        None => ctx.term.print(&sheet)?,
    }
    Ok(())
}

/// The values the sheet template is filled with.
struct Sheet<'a> {
    /// The alias as `config.json` holds it, unescaped.
    ///
    /// `render` escapes this field, so escaping it beforehand prints `&amp;lt;` on the sheet.
    alias: &'a str,
    did: &'a str,
    fingerprint: &'a str,
    created: &'a str,
    heading: &'a str,
    caution: &'a str,
    secret_html: &'a str,
    qr: &'a str,
}

/// Fills the sheet template, HTML-escaping the alias.
fn render(sheet: Sheet<'_>) -> String {
    fill(
        SHEET_TEMPLATE,
        &[
            // The alias may come verbatim out of another person's archive, and it lands in a
            // page the user opens in a browser next to their private key
            ("ALIAS", &escape(sheet.alias)),
            ("DID", sheet.did),
            ("FINGERPRINT", sheet.fingerprint),
            ("CREATED", sheet.created),
            ("HEADING", sheet.heading),
            ("CAUTION", sheet.caution),
            ("SECRET", sheet.secret_html),
            ("QR", sheet.qr),
            ("TOOL", env!("CARGO_PKG_VERSION")),
        ],
    )
}

/// Spells the seed as a checksummed 24-word BIP-39 mnemonic.
fn mnemonic(seed: &Zeroizing<[u8; 32]>) -> Result<Zeroizing<String>> {
    let mnemonic = bip39::Mnemonic::from_entropy(seed.as_slice()).map_err(|e| {
        Error::refused(
            format!("could not turn this key into words: {e}"),
            format!(
                "this is a bug in rad-backup. Report it with `rad issue open --repo {}`",
                crate::credits::RID
            ),
        )
    })?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Renders the key as an SVG QR code.
fn qr_svg(text: &str) -> Result<Zeroizing<String>> {
    let code = QrCode::new(text.as_bytes()).map_err(|e| {
        Error::refused(
            format!("could not fit the key into a QR code: {e}"),
            "use --words to put the key on the sheet as 24 words",
        )
    })?;
    // `qrcode` leaves unwiped intermediates and partial copies from each `String` growth,
    // which no safe code here can reach. `build` returns the final buffer by move, so this
    // wrapper wipes the buffer that holds the drawing.
    let mut rendered = Zeroizing::new(
        code.render::<svg::Color>()
            .min_dimensions(320, 320)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    );
    // An XML prolog renders as visible text inside HTML. Draining it in place leaves no
    // unwiped copy of the drawing to drop.
    if let Some(start) = rendered.find("<svg") {
        rendered.drain(..start);
    }
    Ok(rendered)
}

/// Wraps the key file, HTML-escaped, in a `<pre>` block.
fn key_block(key: &str) -> Zeroizing<String> {
    const OPEN: &str = "<pre class=\"key\">";
    const CLOSE: &str = "</pre>";
    let mut html = Zeroizing::new(String::with_capacity(
        OPEN.len() + escaped_len(key) + CLOSE.len(),
    ));
    html.push_str(OPEN);
    escape_into(&mut html, key);
    html.push_str(CLOSE);
    html
}

/// Lays out the words as a numbered HTML list.
fn word_grid(mnemonic: &str) -> Zeroizing<String> {
    // The words are the key, so they go into one buffer sized up front. A `format!` per word
    // would drop 24 plaintext pieces of the key.
    const OPEN: &str = "<ol class=\"words\">";
    const CLOSE: &str = "</ol>";
    const ITEM_OPEN: &str = "<li>";
    const ITEM_CLOSE: &str = "</li>";
    let len = OPEN.len()
        + mnemonic
            .split_whitespace()
            .map(|word| ITEM_OPEN.len() + escaped_len(word) + ITEM_CLOSE.len())
            .sum::<usize>()
        + CLOSE.len();
    let mut html = Zeroizing::new(String::with_capacity(len));
    html.push_str(OPEN);
    for word in mnemonic.split_whitespace() {
        html.push_str(ITEM_OPEN);
        escape_into(&mut html, word);
        html.push_str(ITEM_CLOSE);
    }
    html.push_str(CLOSE);
    html
}

/// HTML-escapes `text`.
fn escape(text: &str) -> Zeroizing<String> {
    // The buffer is sized once and filled in one pass, because each `replace` call would drop
    // a whole unwiped copy of the key
    let mut escaped = Zeroizing::new(String::with_capacity(escaped_len(text)));
    escape_into(&mut escaped, text);
    escaped
}

/// Appends `text` to `out`, HTML-escaped.
///
/// `out` must already have room for `escaped_len(text)` more bytes, because a `String` that
/// grows drops its old buffer unwiped whatever wraps it.
fn escape_into(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
}

/// The byte length of `text` once HTML-escaped.
fn escaped_len(text: &str) -> usize {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".len(),
            '<' => "&lt;".len(),
            '>' => "&gt;".len(),
            c => c.len_utf8(),
        })
        .sum()
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
        assert_eq!(escape("<script>&").as_str(), "&lt;script&gt;&amp;");
        let text = "<&>&&<<>> plain & <x> \"q\" 'a' é\n";
        let reference = text
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        assert_eq!(escape(text).as_str(), reference);
    }

    #[test]
    fn an_alias_out_of_a_stranger_s_config_cannot_put_script_on_the_sheet() {
        let sheet = render(Sheet {
            alias: "<img src=x onerror=alert(1)>",
            did: "did:key:z6Mk",
            fingerprint: "SHA256:x",
            created: "2026-01-01T00:00:00Z",
            heading: "24 words",
            caution: "caution",
            secret_html: "<ol></ol>",
            qr: "<svg></svg>",
        });
        assert!(
            !sheet.contains("<img src=x"),
            "the alias reached the page as markup"
        );
        assert!(sheet.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn every_buffer_that_carries_the_key_wipes_itself() {
        // The bindings check each return type, so a builder returning `String` fails to build
        let seed = Zeroizing::new([7u8; 32]);
        let key = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let _: Zeroizing<String> = escape(&key);
        let _: Zeroizing<String> = key_block(&key);
        let _: Zeroizing<String> = word_grid("alpha bravo <charlie>");
        let _: Zeroizing<String> = qr_svg(&key).expect("a key file fits");
    }

    #[test]
    fn the_key_is_escaped_in_one_exactly_sized_allocation() {
        // A `String` that outgrows its capacity frees its old buffer unwiped. Capacity equal
        // to length shows the buffer never grew.
        let seed = Zeroizing::new([7u8; 32]);
        let key = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let words = mnemonic(&seed).expect("a seed converts");
        for html in [
            escape("<&>&&<<>> plain & <x> é"),
            key_block(&key),
            word_grid(&words),
            word_grid("a<b>&c d&&e"),
        ] {
            assert_eq!(html.capacity(), html.len(), "{}", html.as_str());
        }
    }

    #[test]
    fn a_key_file_fits_in_a_qr_code() {
        let seed = Zeroizing::new([7u8; 32]);
        let key = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let svg = qr_svg(&key).expect("a key file fits");
        // The sheet embeds this inline in HTML, where an XML prolog would render as text
        assert!(svg.starts_with("<svg"), "{}", &svg[..svg.len().min(120)]);
        assert!(!svg.contains("<?xml"));
    }
}
