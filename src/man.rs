//! The manual page.
//!
//! One page carries every command and its options, because one page is what a package
//! installs, and what the `rad-restore.1` that `just generated` writes includes. clap_mangen's
//! own layout lists each command as a `rad-backup-<command>(1)` page of its own, which no
//! package ships, and puts none of their options on the page it renders. Revisit if a package
//! ever ships a page per command.

use std::io::{IsTerminal as _, Write};
use std::process::ExitCode;

use clap::CommandFactory as _;
use clap_mangen::Man;

use crate::cli::Cli;
use crate::error::{Error, Result};

/// Where stdout leads, which decides whether the page is written at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stdout {
    /// Somebody reading, to whom roff is noise.
    Terminal,
    /// A pipe or a file, which is how a package build asks for the page.
    Elsewhere,
}

impl Stdout {
    pub fn detect() -> Self {
        if std::io::stdout().is_terminal() {
            Self::Terminal
        } else {
            Self::Elsewhere
        }
    }
}

/// Write the page as roff to a pipe or a file, and refuse a terminal with the ways to read it.
///
/// Not the page shown through `man` and a pager, for two reasons. `rad` runs this binary as a
/// child and dies on Ctrl-C, which gives the terminal back to the shell while the pager is
/// still reading from it. And `man -l -`, the way to hand `man` a page on stdin, is man-db's
/// alone: macOS has no `-l`. Revisit only when both have changed.
pub fn run(leads_to: Stdout, stdout: &mut dyn Write) -> Result<ExitCode> {
    match leads_to {
        Stdout::Terminal => Err(Error::ManAtATerminal),
        Stdout::Elsewhere => crate::emit(stdout, &render()?),
    }
}

/// The manual page, as roff.
pub fn render() -> Result<Vec<u8>> {
    let mut command = Cli::command().subcommand_value_name("command");
    // Built here rather than inside `Man::new`, so that the commands read below carry their
    // full names (`rad-backup restore`) and the global options they inherit are marked.
    command.build();
    let top = Man::new(command.clone());

    let mut page = Vec::new();
    top.render_title(&mut page).map_err(Error::PathlessIo)?;
    // No hyphenation: a line that breaks `--plaintext` as `--plain-` and `text` hands a reader
    // who copies it a flag that does not exist.
    page.extend_from_slice(b".nh\n");
    let mut sections = Vec::new();
    top.render_name_section(&mut sections)
        .map_err(Error::PathlessIo)?;
    top.render_synopsis_section(&mut sections)
        .map_err(Error::PathlessIo)?;
    top.render_description_section(&mut sections)
        .map_err(Error::PathlessIo)?;
    top.render_options_section(&mut sections)
        .map_err(Error::PathlessIo)?;
    page.extend_from_slice(without_preamble(&sections).as_bytes());

    // An index first, so a reader sees every command on one screen before the sections.
    page.extend_from_slice(b".SH COMMANDS\n");
    let verbs: Vec<&clap::Command> = command
        .get_subcommands()
        .filter(|verb| !verb.is_hide_set())
        .collect();
    for verb in &verbs {
        let about = verb
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default();
        page.extend_from_slice(
            format!(
                ".TP\n\\fB{}\\fR\n\\&{}\n",
                roff_text(verb.get_name()),
                roff_text(&about)
            )
            .as_bytes(),
        );
    }
    for verb in verbs {
        render_verb(&mut page, verb)?;
    }
    page.extend_from_slice(closing_sections().as_bytes());
    Ok(page)
}

/// Who makes this, where to report a bug, and the pages that go with it, in the order
/// man-pages(7) gives. SEE ALSO names `rad`, and the tools that open an archive and put it
/// back without this one.
///
/// `rad clone` rather than `rad seed`: with the node stopped, `rad seed` only records the
/// policy and says it succeeded, and `rad issue open` then fails on a path in storage, where
/// `rad clone` says the node has to be running.
fn closing_sections() -> String {
    use crate::credits::{AUTHOR, DONATE, RADICLE_TOOLS, RID, SECURITY};

    let rid = roff_text(RID);
    format!(
        ".SH AUTHORS\n\
         A project by {author} for {tools}\n\
         .PP\n\
         Donate: {donate}\n\
         .SH \"REPORTING BUGS\"\n\
         Issues live on Radicle:\n\
         .PP\n.RS\n.nf\n\
         rad clone {rid}\n\
         rad issue open \\-\\-repo {rid}\n\
         .fi\n.RE\n\
         .PP\n\
         A vulnerability goes to {security} instead, because an issue is public, and a copy \
         another node has fetched cannot be taken back.\n\
         .SH \"SEE ALSO\"\n\
         \\fBage\\fR(1), \\fBgit\\fR(1), \\fBjq\\fR(1), \\fBrad\\fR(1), \\fBtar\\fR(1), \
         \\fBzstd\\fR(1)\n",
        author = roff_text(AUTHOR),
        tools = roff_text(RADICLE_TOOLS),
        donate = roff_text(DONATE),
        security = roff_text(SECURITY),
    )
}

/// One command's section: its name and aliases, how it is called, what it does, and the
/// options that are its own.
fn render_verb(page: &mut Vec<u8>, verb: &clap::Command) -> Result<()> {
    let names: Vec<&str> = std::iter::once(verb.get_name())
        .chain(verb.get_visible_aliases())
        .collect();
    page.extend_from_slice(format!(".SS \"{}\"\n", roff_text(&names.join(", "))).as_bytes());

    let verb = verb.clone().mut_args(|arg| {
        if arg.is_global_set() || arg.get_id() == "help" {
            arg.hide(true)
        } else {
            arg
        }
    });
    let man = Man::new(verb.clone());
    let mut synopsis = Vec::new();
    man.render_synopsis_section(&mut synopsis)
        .map_err(Error::PathlessIo)?;
    // The global options are hidden above so that each section does not list them again, and
    // a synopsis without them reads as complete: `restore` would show no way to pass the
    // `--identity` an encrypted archive needs.
    let mut section = format!(
        "{} [\\fIglobal\\ options\\fR]\n",
        String::from_utf8_lossy(&synopsis).trim_end()
    )
    .into_bytes();
    man.render_description_section(&mut section)
        .map_err(Error::PathlessIo)?;
    // `create` is what running with no command does, so its options are the page's own
    // OPTIONS, and listing them twice would make the page longer and no clearer.
    let is_create = verb.get_name() == "create";
    if !is_create && verb.get_arguments().any(|arg| !arg.is_hide_set()) {
        man.render_options_section(&mut section)
            .map_err(Error::PathlessIo)?;
    }
    page.extend_from_slice(demoted(&without_preamble(&section)).as_bytes());
    if is_create {
        page.extend_from_slice(
            b".PP\nIt takes the options under OPTIONS, other than \\-\\-version.\n",
        );
    }
    Ok(())
}

/// Roff without the string definition clap_mangen opens every render with, which the page's
/// title already made once.
fn without_preamble(roff: &[u8]) -> String {
    String::from_utf8_lossy(roff)
        .lines()
        .filter(|line| !line.starts_with(".ie \\n(.g .ds Aq") && !line.starts_with(".el .ds Aq"))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// Sections clap_mangen rendered for a page of their own, made into paragraphs of one
/// command's section. The headings every command has become paragraph breaks; any other, such
/// as an option group's, stays as a bold line so the grouping is not lost.
fn demoted(roff: &str) -> String {
    roff.lines()
        .map(|line| match line.strip_prefix(".SH ") {
            Some("SYNOPSIS" | "DESCRIPTION" | "OPTIONS") => ".PP\n".to_string(),
            Some(heading) => format!(".PP\n.B {heading}\n"),
            None => format!("{line}\n"),
        })
        .collect()
}

/// Text as roff spells it: a backslash escaped, and a hyphen made a minus so that what a
/// reader copies from the page is what the shell expects.
fn roff_text(text: &str) -> String {
    text.replace('\\', "\\\\").replace('-', "\\-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> String {
        String::from_utf8(render().expect("the page renders")).expect("roff is text")
    }

    /// The start of the entry that documents an option, as against the mention of it every
    /// synopsis makes. Roff escapes a hyphen, so `--force` is spelled `\-\-force`.
    fn entry(short: Option<char>, long: &str) -> String {
        let long = format!("\\fB\\-\\-{}\\fR", long.replace('-', "\\-"));
        match short {
            Some(short) => format!(".TP\n\\fB\\-{short}\\fR, {long}"),
            None => format!(".TP\n{long}"),
        }
    }

    /// What each `.TP` entry in a stretch of the page documents: a flag by its long name, and
    /// a positional by its value name, `ARCHIVE` for `[ARCHIVE]`.
    fn entries(roff: &str) -> Vec<String> {
        let mut documented: Vec<String> = roff
            .split(".TP\n")
            .skip(1)
            .filter_map(|entry| {
                let head = entry.lines().next()?;
                let head = head
                    .replace("\\fB", "")
                    .replace("\\fR", "")
                    .replace("\\fI", "")
                    .replace("\\-", "-");
                let word = head
                    .split_whitespace()
                    .find(|word| word.starts_with("--"))
                    .or_else(|| head.split_whitespace().next())?;
                Some(
                    word.trim_start_matches('-')
                        .trim_matches(['[', ']', '<', '>', ','])
                        .to_string(),
                )
            })
            .collect();
        documented.sort();
        documented
    }

    /// How `entries` names an argument.
    fn documented_as(arg: &clap::Arg) -> String {
        match arg.get_long() {
            Some(long) => long.to_string(),
            None => arg
                .get_value_names()
                .and_then(|names| names.first())
                .map(ToString::to_string)
                .unwrap_or_else(|| arg.get_id().to_string().to_uppercase()),
        }
    }

    /// The options a command documents in its own section: not the global ones, which the
    /// page lists once, nor `--help`, which every command has.
    fn own_options(verb: &clap::Command) -> impl Iterator<Item = &clap::Arg> {
        verb.get_arguments()
            .filter(|arg| !arg.is_hide_set() && !arg.is_global_set() && arg.get_id() != "help")
    }

    #[test]
    fn every_command_is_on_the_page_with_the_options_that_are_its_own() {
        let page = page();
        let command = Cli::command();
        let mut checked = 0;
        for verb in command.get_subcommands() {
            // Its own section only, since `schedule --output` is not documented by the
            // `--output` under OPTIONS.
            let section = page
                .split(".SS \"")
                .find(|section| {
                    section
                        .split(['"', ','])
                        .next()
                        .is_some_and(|name| name == verb.get_name())
                })
                .unwrap_or_else(|| panic!("`{}` has no section on the page", verb.get_name()));
            if verb.get_name() == "create" {
                continue;
            }
            // Exactly its own: an entry missing is an option nobody can read about, and one
            // too many is a global or `--help` repeated in every section.
            let mut expected: Vec<String> = own_options(verb).map(documented_as).collect();
            expected.sort();
            let documented = entries(section);
            assert_eq!(
                documented,
                expected,
                "the section for `{}`",
                verb.get_name()
            );
            checked += expected.len();
        }
        assert!(
            checked > 10,
            "only {checked} command options were looked for, so this test guards little"
        );
    }

    /// The page tells a reader that `create` takes the options under OPTIONS, other than
    /// `--version`. That holds only while OPTIONS is exactly `create`'s options plus `--help`
    /// and `--version`, in both directions.
    #[test]
    fn the_options_under_options_are_exactly_those_create_takes() {
        let page = page();
        let options = page
            .split(".SH OPTIONS\n")
            .nth(1)
            .and_then(|rest| rest.split(".SH ").next())
            .expect("the page has an OPTIONS section");
        let documented = entries(options);

        let command = Cli::command();
        let create = command
            .find_subcommand("create")
            .expect("`create` is a command");
        let mut expected: Vec<String> = own_options(create)
            .map(documented_as)
            .chain(["help".to_string(), "version".to_string()])
            .collect();
        expected.sort();
        assert!(expected.len() > 5, "{expected:?}");
        assert_eq!(documented, expected);

        // And documented there alone, not again in `create`'s own section.
        let section = page
            .split(".SS \"create\"\n")
            .nth(1)
            .and_then(|rest| rest.split(".SS ").next())
            .expect("`create` has a section");
        assert!(!section.contains(".TP\n"), "{section}");
        assert!(
            section.contains("It takes the options under OPTIONS, other than \\-\\-version."),
            "`create` no longer points at its options: {section}"
        );
    }

    #[test]
    fn the_page_names_no_page_of_ours_that_nothing_ships() {
        // The pages `just generated` writes for a package to install.
        let shipped = ["rad-backup", "rad-restore"];
        let plain = page()
            .replace("\\fB", "")
            .replace("\\fR", "")
            .replace("\\-", "-");
        for (at, _) in plain.match_indices("(1)") {
            let name: String = plain[..at]
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if name.starts_with("rad-") {
                assert!(
                    shipped.contains(&name.as_str()),
                    "the page sends a reader to {name}(1), which no package installs"
                );
            }
        }
    }

    #[test]
    fn the_page_ends_with_who_makes_it_where_to_report_a_bug_and_what_to_read_next() {
        let closing = closing_sections();
        assert!(page().ends_with(&closing), "the page ends elsewhere");
        let headings: Vec<&str> = closing
            .lines()
            .filter_map(|line| line.strip_prefix(".SH "))
            .collect();
        assert_eq!(headings, ["AUTHORS", "\"REPORTING BUGS\"", "\"SEE ALSO\""]);
        for credit in [
            crate::credits::RID,
            crate::credits::AUTHOR,
            crate::credits::DONATE,
            crate::credits::RADICLE_TOOLS,
            crate::credits::SECURITY,
        ] {
            assert!(closing.contains(&roff_text(credit)), "{credit}");
        }
    }

    #[test]
    fn the_page_turns_hyphenation_off_before_its_first_section() {
        let page = page();
        let before_first_section = page
            .split(".SH ")
            .next()
            .expect("split yields at least one piece");
        assert!(
            before_first_section.lines().any(|line| line == ".nh"),
            "{before_first_section}"
        );
        assert!(!page.contains("\n.hy"), "hyphenation is turned back on");
    }

    #[test]
    fn every_command_synopsis_says_it_takes_the_global_options() {
        let page = page();
        let command = Cli::command();
        let mut checked = 0;
        for verb in command.get_subcommands() {
            let start = format!("\\fBrad\\-backup {}\\fR", roff_text(verb.get_name()));
            let synopsis = page
                .lines()
                .find(|line| line.starts_with(&start))
                .unwrap_or_else(|| panic!("`{}` has no synopsis", verb.get_name()));
            assert!(
                synopsis.ends_with(" [\\fIglobal\\ options\\fR]"),
                "{synopsis}"
            );
            checked += 1;
        }
        assert!(checked > 10, "only {checked} commands were looked at");
    }

    #[test]
    fn the_global_options_are_listed_once_and_not_under_every_command() {
        let page = page();
        assert_eq!(page.matches(&entry(None, "passphrase-file")).count(), 1);
        assert!(page.contains(".SH \"GLOBAL OPTIONS\""), "{page}");
    }

    #[test]
    fn a_command_section_holds_no_heading_of_a_page_of_its_own() {
        let page = page();
        let commands = page
            .split(".SH COMMANDS")
            .nth(1)
            .and_then(|rest| rest.strip_suffix(&closing_sections()))
            .expect("the page has a COMMANDS section, and the closing sections after it");
        assert!(!commands.contains(".SH "), "{commands}");
        assert_eq!(page.matches(".ds Aq").count(), 2, "one `.ie`/`.el` pair");
    }

    #[test]
    fn an_option_group_heading_survives_inside_a_command_section() {
        let demoted = demoted(".SH OPTIONS\n.TP\nx\n.SH \"NETWORK OPTIONS\"\n.TP\ny\n");
        assert_eq!(
            demoted,
            ".PP\n.TP\nx\n.PP\n.B \"NETWORK OPTIONS\"\n.TP\ny\n"
        );
    }

    #[test]
    fn a_terminal_is_refused_the_roff_and_told_how_to_read_the_page() {
        let mut written = Vec::new();
        let refusal = run(Stdout::Terminal, &mut written).expect_err("a terminal is refused");
        assert!(matches!(refusal, Error::ManAtATerminal), "{refusal}");
        assert_eq!(refusal.exit_status(), crate::error::EXIT_FAILURE);
        assert_eq!(written, b"");
        let said = refusal.to_string();
        for way in [
            "`man rad-backup`",
            "rad-backup man > ",
            "`rad-backup --help`",
        ] {
            assert!(said.contains(way), "the refusal leaves out {way}: {said}");
        }
        // Every line fits an 80-column terminal once `main` prefixes the first with `✗ `.
        for line in refusal.to_string().lines() {
            assert!(line.chars().count() + 2 <= 80, "{line}");
        }
    }

    #[test]
    fn away_from_a_terminal_the_page_is_the_roff() {
        let mut written = Vec::new();
        run(Stdout::Elsewhere, &mut written).expect("it writes");
        assert_eq!(written, render().expect("the page renders"));
    }

    #[test]
    fn the_command_index_lists_every_command_once_with_what_it_does() {
        let page = page();
        let index = page
            .split(".SH COMMANDS\n")
            .nth(1)
            .and_then(|rest| rest.split(".SS ").next())
            .expect("the page has a COMMANDS section");
        let command = Cli::command();
        for verb in command.get_subcommands() {
            let about = verb
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            let line = format!(
                ".TP\n\\fB{}\\fR\n\\&{}\n",
                roff_text(verb.get_name()),
                roff_text(&about)
            );
            assert_eq!(index.matches(&line).count(), 1, "{line}");
        }
    }
}
