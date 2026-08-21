//! Terminal output.
//!
//! Every line the tool prints goes through here, so that `--quiet`, `--json` and colour
//! detection are decided in one place instead of at each call site.

use std::io::{self, IsTerminal, Write};

use crate::error::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Quiet,
    Normal,
}

pub struct Term {
    colour: bool,
    interactive: bool,
    verbosity: Verbosity,
    assume_yes: bool,
}

impl Term {
    pub fn new(verbosity: Verbosity, assume_yes: bool, force_no_colour: bool) -> Self {
        let interactive = io::stdin().is_terminal() && io::stderr().is_terminal();
        // NO_COLOR is honoured for any non-empty value, per the no-color.org convention.
        let no_colour_env = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Self {
            colour: io::stderr().is_terminal() && !no_colour_env && !force_no_colour,
            interactive,
            verbosity,
            assume_yes,
        }
    }

    /// Progress and status go to stderr, so that `--stdout` archives and `--json` reports can
    /// be piped without the narration mixing in.
    fn say(&self, line: &str) {
        if self.verbosity == Verbosity::Normal {
            self.always(line);
        }
    }

    /// For lines `--quiet` must not swallow. A warning is not narration: the shipped systemd
    /// unit and the crontab in the README both pass `--quiet`, so routing warnings through
    /// `say` meant an unattended run could narrow what it archived and still look clean.
    fn always(&self, line: &str) {
        let mut err = io::stderr();
        let _ = writeln!(err, "{line}");
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.colour {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    pub fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    pub fn headline(&self, text: &str) {
        self.say(&self.bold(text));
    }

    pub fn step(&self, text: &str) {
        self.say(&format!("{} {text}", self.dim("·")));
    }

    pub fn ok(&self, text: &str) {
        self.say(&format!("{} {text}", self.paint("32", "✓")));
    }

    pub fn fail(&self, text: &str) {
        self.always(&format!("{} {text}", self.paint("31", "✗")));
    }

    pub fn warn(&self, text: &str) {
        self.always(&format!("{} {text}", self.paint("33", "!")));
    }

    /// For a question that could not be answered. `·` would read as a neutral bullet, and a
    /// reader is owed the difference between "this is fine" and "this could not be looked at".
    /// Never swallowed: an unanswerable check is a diagnostic, not narration.
    pub fn unknown(&self, text: &str) {
        self.always(&format!("{} {text}", self.dim("?")));
    }

    /// A hint attached to a step that went fine. Narration, and `--quiet` drops it.
    pub fn hint(&self, text: &str) {
        self.say(&self.dim(&format!("  {text}")));
    }

    /// The lines under a `warn` or a `fail` that carry the substance: which repositories
    /// diverged, what to run next, where to look. Printed like a hint and never swallowed,
    /// because `--quiet` otherwise reported that something was wrong and withheld what.
    pub fn detail(&self, text: &str) {
        self.always(&self.dim(&format!("  {text}")));
    }

    pub fn blank(&self) {
        self.say("");
    }

    /// Anything a machine consumes goes to stdout: JSON reports, listings, recovery sheets.
    ///
    /// Unlike the narration above, a failure here is the failure of the thing the command was
    /// asked to produce, so it is returned rather than dropped: half a JSON report, written
    /// onto a full disk under an exit code that said success, is output no consumer can tell
    /// from the real thing. A closed pipe is the one exception, because `... | head` closes it
    /// on purpose and the run did nothing wrong.
    pub fn print(&self, line: &str) -> Result<()> {
        let mut out = io::stdout();
        match writeln!(out, "{line}").and_then(|()| out.flush()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(Error::Bare(e)),
        }
    }

    pub fn print_json(&self, value: &serde_json::Value) -> Result<()> {
        self.print(&serde_json::to_string_pretty(value)?)
    }

    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    /// Ask a yes/no question. With nobody to ask (cron, a pipe) the answer is no unless
    /// `--yes` was passed, because a backup tool that guesses "yes" for someone who is not
    /// there can overwrite a home nobody meant to touch.
    pub fn confirm(&self, question: &str) -> Result<bool> {
        if self.assume_yes {
            return Ok(true);
        }
        if !self.interactive {
            return Ok(false);
        }
        let mut err = io::stderr();
        write!(err, "{question} [y/N] ").map_err(Error::Bare)?;
        err.flush().map_err(Error::Bare)?;

        let mut answer = String::new();
        io::stdin().read_line(&mut answer).map_err(Error::Bare)?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
    }
}

/// Render a byte count the way a person reads it, not the way a computer stores it.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// A count with the right noun beside it. One place, so no line ever reads "1 repositories".
pub fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// The verb that agrees with a count, so no line ever reads "1 of 3 are in no archive".
pub fn agree(n: usize) -> &'static str {
    if n == 1 { "is" } else { "are" }
}

/// Render a duration in whole days, for "this backup is 40 days old" style reporting.
pub fn days_ago(days: i64) -> String {
    match days {
        0 => "today".to_string(),
        1 => "yesterday".to_string(),
        // A clock that ran fast on the machine that took it, so the age is not a fact about
        // the archive. "-36 days ago" reads as a typo; this reads as what it is.
        n if n < 0 => "at a time in the future".to_string(),
        n => format!("{n} days ago"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_stamped_ahead_of_this_clock_is_not_reported_as_negative_days_old() {
        assert_eq!(days_ago(-36), "at a time in the future");
        assert_eq!(days_ago(0), "today");
        assert_eq!(days_ago(2), "2 days ago");
    }

    #[test]
    fn a_count_of_one_takes_the_singular_and_everything_else_takes_the_plural() {
        assert_eq!(count(1, "repository", "repositories"), "1 repository");
        assert_eq!(count(0, "repository", "repositories"), "0 repositories");
        assert_eq!(count(2, "repository", "repositories"), "2 repositories");
    }

    #[test]
    fn byte_counts_render_in_the_largest_unit_that_keeps_a_whole_part() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(524), "524 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(20_480), "20.0 KiB");
        assert_eq!(bytes(976 * 1024 * 1024), "976.0 MiB");
        assert_eq!(bytes(2_147_483_648), "2.0 GiB");
    }

    #[test]
    fn recent_days_read_as_words_and_older_ones_as_counts() {
        assert_eq!(days_ago(0), "today");
        assert_eq!(days_ago(1), "yesterday");
        assert_eq!(days_ago(40), "40 days ago");
    }
}
