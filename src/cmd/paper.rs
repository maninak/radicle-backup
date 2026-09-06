//! A printable recovery sheet.
//!
//! Paper outlives disks, formats and this program. The sheet carries the key twice, as a QR
//! code for a scanner and as text a human can retype, plus enough plain English that whoever
//! finds it in a drawer in ten years knows what they are holding.

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
                "Passphrase for the key: ",
                crypt::Purpose::Opening,
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

    // The QR encodes the key, so the SVG carrying it is key material as much as the text is.
    let qr = qr_svg(&secret_text)?;
    // Holds the key or its 24 words in the clear, as the QR does.
    let secret_html = if args.words {
        word_grid(&secret_text)
    } else {
        key_block(&secret_text)
    };

    // `render` returns its buffer by move, so wrapping the result wipes the sheet itself
    // rather than a copy of it.
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
                .hint("open it in a browser and print it; then delete the file");
        }
        // A terminal keeps thousands of lines of scrollback in its own memory, and some
        // emulators log a session to disk, so a sheet printed to a TTY outlives the process
        // that was careful to zeroize it. A pipe is different: `paper | wkhtmltopdf -` hands
        // the bytes to one program and ends, so the refusal is about the terminal, not about
        // the absence of `--output`.
        None if std::io::stdout().is_terminal() => {
            return Err(Error::refused(
                "this sheet is the key in the clear, and stdout is a terminal",
                "write it with --output <path>, or pipe it into something that keeps no history",
            ));
        }
        None => ctx.term.print(&sheet)?,
    }
    Ok(())
}

/// Everything the sheet says, already computed. Split from `run` so that the escaping can be
/// tested against the real template without a home to read it from.
struct Sheet<'a> {
    /// Raw, straight out of `config.json`. `render` escapes it and nothing else may, because
    /// escaping twice prints `&amp;lt;` on the sheet where the alias should be.
    alias: &'a str,
    did: &'a str,
    fingerprint: &'a str,
    created: &'a str,
    heading: &'a str,
    caution: &'a str,
    secret_html: &'a str,
    qr: &'a str,
}

/// Fill the template in.
///
/// The alias is escaped here because it is the one field that is neither derived from the key
/// nor written by this program: it arrives in a `config.json`, which a restore copies verbatim
/// out of somebody else's archive, and it lands in the `<title>` and a `<td>` of a page the
/// user is told to open in a browser next to their private key.
fn render(sheet: Sheet<'_>) -> String {
    fill(
        SHEET_TEMPLATE,
        &[
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

/// The key as an SVG QR code. Returned `Zeroizing` because the SVG decodes back to the key.
///
/// Not everything on the way there is wiped. `QrCode::new` encodes the key into a `Vec<Color>`
/// module matrix through its own intermediates (the data bits, the codewords, the canvas), and
/// the SVG renderer grows its `String` with `write!`, so every reallocation on the way leaves
/// a partial copy of the drawing behind. All of that is private to `qrcode`, `Color` is a
/// foreign type that implements no `Zeroize`, and `unsafe` is forbidden here, so none of it
/// can be wiped from this side. What this function owns, it wipes: the finished SVG is taken
/// over by move and trimmed in place, so no copy of the whole drawing is dropped intact.
fn qr_svg(text: &str) -> Result<Zeroizing<String>> {
    let code = QrCode::new(text.as_bytes()).map_err(|e| {
        Error::refused(
            format!("this key does not fit in a QR code: {e}"),
            "use --words, which is smaller",
        )
    })?;
    // `build` returns the renderer's buffer by move, so wrapping it wipes the buffer that
    // actually holds the bytes rather than a copy taken out of it.
    let mut rendered = Zeroizing::new(
        code.render::<svg::Color>()
            .min_dimensions(320, 320)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    );
    // The renderer emits an XML prolog, which is fine in a .svg file and wrong inside an HTML
    // document, where it renders as visible text. The sheet is HTML, so it goes. Drained
    // rather than sliced and copied, because the copy would leave the original to drop
    // unwiped.
    if let Some(start) = rendered.find("<svg") {
        rendered.drain(..start);
    }
    Ok(rendered)
}

/// The key file as preformatted text, escaped, in a buffer that wipes itself.
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

/// Numbered words, so a person reading them aloud and a person writing them down stay in step.
///
/// Built in one buffer that wipes itself, because those words are the key: a `format!` per
/// word would drop 24 small plaintext copies of it on the way.
fn word_grid(mnemonic: &str) -> Zeroizing<String> {
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

/// HTML-escape `text` into a buffer that wipes itself.
///
/// Sized exactly and filled in one pass rather than chained through `replace`, because each
/// `replace` allocates a whole fresh copy that is then dropped intact, and this function is
/// called on the key.
fn escape(text: &str) -> Zeroizing<String> {
    let mut escaped = Zeroizing::new(String::with_capacity(escaped_len(text)));
    escape_into(&mut escaped, text);
    escaped
}

/// Append `text` to `out`, HTML-escaped. `out` must already have room for `escaped_len(text)`
/// more bytes, because a `String` that grows drops its old buffer unwiped whatever wraps it.
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

/// How long `escape_into(_, text)` will be, so that its buffer can be allocated once.
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
        // The same answer the `replace` chain it replaced gave, on every awkward shape at
        // once.
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
        // Type-level: each of these hands back `Zeroizing`, so none can drop a plain copy of
        // its own result. A return type of `String` fails to compile here.
        let seed = Zeroizing::new([7u8; 32]);
        let key = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let _: Zeroizing<String> = escape(&key);
        let _: Zeroizing<String> = key_block(&key);
        let _: Zeroizing<String> = word_grid("alpha bravo <charlie>");
        let _: Zeroizing<String> = qr_svg(&key).expect("a key file fits");
    }

    #[test]
    fn the_key_is_escaped_in_one_exactly_sized_allocation() {
        // A `String` that outgrows its capacity frees its old buffer unwiped, whatever wraps
        // it, so the buffer must be sized right before the first byte lands. Capacity equal
        // to length is the trace of that: a buffer that grew would carry the slack.
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
        // The sheet embeds this inline in HTML, where an XML prolog would render as text.
        assert!(svg.starts_with("<svg"), "{}", &svg[..svg.len().min(120)]);
        assert!(!svg.contains("<?xml"));
    }
}
