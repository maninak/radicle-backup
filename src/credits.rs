//! Who makes this, where its issues go and how to support it, for `--help` and the man page.

/// The Radicle repository, where issues live, since GitHub issues are turned off.
pub const RID: &str = "rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J";

pub const AUTHOR: &str = "Konstantinos Maninakis (maninak)";

/// The site for the family of Radicle tools this belongs to.
pub const RADICLE_TOOLS: &str = "https://radicle.tools";

pub const DONATE: &str = "https://liberapay.com/maninak/donate";

/// Where a vulnerability goes, because an issue is public and every node that fetched it
/// keeps a copy. The address `SECURITY.md` gives.
pub const SECURITY: &str = "security@radicle.tools";

/// The lines `--help` ends with, and `-h` leaves out.
///
/// No line ends in a full stop, because a terminal that links a URL or an id can take the full
/// stop into the link.
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

    /// The binary carries copies of facts its documents own, so a security address moved in
    /// `SECURITY.md` alone would keep sending vulnerabilities to the old one.
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

    /// A footer naming where issues go must also name where a vulnerability goes, or a finder
    /// reports it in public.
    #[test]
    fn the_help_footer_sends_a_vulnerability_away_from_the_issues() {
        let footer = help_footer();
        assert!(footer.contains(RID), "{footer}");
        assert!(footer.contains(SECURITY), "{footer}");
    }
}
