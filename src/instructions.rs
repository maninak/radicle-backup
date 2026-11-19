//! The restore instructions every archive carries, filled in from its manifest.
//!
//! They are rendered from the manifest alone, so a writer with no Radicle home on disk, such
//! as a browser, writes the same documents `rad-backup` does.

use crate::manifest::Manifest;

/// The template of `RESTORE.md`, whose `{{KEY}}` markers [`restore_doc`] fills.
pub const RESTORE_DOC: &str = include_str!("../assets/RESTORE.md");
/// `restore.sh`, carried as written.
pub const RESTORE_SCRIPT: &str = include_str!("../assets/restore.sh");

/// The mode of the restore script, executable so it runs straight out of the archive.
pub const SCRIPT_MODE: u32 = 0o755;

/// `RESTORE.md` for the archive `manifest` describes.
pub fn restore_doc(manifest: &Manifest) -> String {
    fill(
        RESTORE_DOC,
        &[
            ("CREATED", &manifest.created),
            ("RAD_HOME", &manifest.source.rad_home),
            (
                "HOST",
                manifest.source.host.as_deref().unwrap_or("a machine"),
            ),
            (
                "ALIAS",
                manifest.identity.alias.as_deref().unwrap_or("unnamed"),
            ),
            ("DID", &manifest.identity.did),
            ("FINGERPRINT", &manifest.identity.fingerprint),
        ],
    )
}

/// Substitutes `{{KEY}}` markers in `template` in one pass, leaving unknown ones as written.
///
/// An inserted value is never scanned again, so a value such as an alias of `{{SECRET}}`
/// cannot expand to another key.
pub fn fill(template: &str, values: &[(&str, &str)]) -> String {
    // The buffer is sized up front, because growing it frees the old one with a partial copy
    // of the key in it, out of reach of the `Zeroizing` around the result. The estimate runs
    // high, which is harmless.
    let mut filled = String::with_capacity(room_for(template, values));
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            break;
        };
        let key = &after[..end];
        match values.iter().find(|(name, _)| *name == key) {
            Some((_, value)) => {
                filled.push_str(&rest[..start]);
                filled.push_str(value);
            }
            None => filled.push_str(&rest[..start + 2 + end + 2]),
        }
        rest = &after[end + 2..];
    }
    filled.push_str(rest);
    filled
}

/// How much room [`fill`] needs before it writes anything.
///
/// Each value counts once per marker that asks for it, because `{{ALIAS}}` appears more than once in
/// the recovery sheet, and a buffer that grows midway frees a block holding the key.
fn room_for(template: &str, values: &[(&str, &str)]) -> usize {
    template.len()
        + values
            .iter()
            .map(|(name, value)| {
                let marker = format!("{{{{{name}}}}}");
                template.matches(marker.as_str()).count() * value.len()
            })
            .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_replaced_and_unknown_ones_are_left_alone() {
        let filled = fill("hello {{NAME}}, {{MISSING}}", &[("NAME", "world")]);
        assert_eq!(filled, "hello world, {{MISSING}}");
    }

    #[test]
    fn a_value_cannot_name_another_key() {
        // The alias arrives in a `config.json` that a restore copies verbatim out of somebody
        // else's archive, and `paper` puts it in the title of a sheet printed next to the key
        let filled = fill(
            "{{ALIAS}} holds {{SECRET}}",
            &[("ALIAS", "{{SECRET}}"), ("SECRET", "the 24 words")],
        );
        assert_eq!(filled, "{{SECRET}} holds the 24 words");
    }

    #[test]
    fn a_document_is_sized_for_every_marker_that_asks_for_the_same_value() {
        let template = "{{ALIAS}} .. {{ALIAS}}";
        let values = [("ALIAS", "a name long enough to matter")];
        assert!(room_for(template, &values) >= fill(template, &values).len());
    }
}
