//! Who makes this, where its issues go, and how to support it: said once here for `--help`
//! and the man page both.

/// The Radicle repository, which is where issues live: GitHub's are turned off.
pub const RID: &str = "rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J";

pub const AUTHOR: &str = "Konstantinos Maninakis (maninak)";

/// The family of Radicle tools this is one of, rather than a page about this tool alone.
pub const RADICLE_TOOLS: &str = "https://radicle.tools";

pub const DONATE: &str = "https://liberapay.com/maninak/donate";

/// Where a vulnerability goes instead of an issue, which is public, and which a node that has
/// fetched it keeps. The address `SECURITY.md` gives.
pub const SECURITY: &str = "security@radicle.tools";

/// The lines `--help` ends with. Not `-h`, which is for somebody looking up a flag.
///
/// No full stop after a URL or a repository id, because a terminal that makes links of them
/// can take the full stop into the link.
pub fn help_footer() -> String {
    format!(
        "A project by {AUTHOR} for {RADICLE_TOOLS}\n\
         Source and issues: {RID}\n\
         Vulnerabilities: {SECURITY}, never an issue\n\
         Donate: {DONATE}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each of these is a fact a document owns, and the binary carries a copy of it to every
    /// machine it is installed on. A security address that moved in `SECURITY.md` alone would
    /// go on sending vulnerabilities to the old one.
    #[test]
    fn the_credits_say_what_the_documents_that_own_them_say() {
        for (document, text, value) in [
            ("SECURITY.md", include_str!("../SECURITY.md"), SECURITY),
            ("CONTRIBUTING.md", include_str!("../CONTRIBUTING.md"), RID),
            ("README.md", include_str!("../README.md"), DONATE),
        ] {
            assert!(text.contains(value), "{document} no longer says {value}");
        }
    }

    /// The footer names where issues go, so it has to name where a vulnerability goes instead,
    /// or somebody who has found a way to read a key reports it in public.
    #[test]
    fn the_help_footer_sends_a_vulnerability_away_from_the_issues() {
        let footer = help_footer();
        assert!(footer.contains(RID), "{footer}");
        assert!(footer.contains(SECURITY), "{footer}");
    }

    #[test]
    fn no_help_footer_line_ends_in_a_full_stop() {
        for line in help_footer().lines() {
            assert!(!line.ends_with('.'), "{line}");
        }
    }
}
