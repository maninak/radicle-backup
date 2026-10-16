//! Terminal output, where `--quiet`, `--json` and colour detection are decided.

use std::io::{self, IsTerminal, Write};

use crate::error::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Quiet,
    Normal,
}

pub struct Term {
    uses_colour: bool,
    is_interactive: bool,
    verbosity: Verbosity,
    assumes_yes: bool,
}

impl Term {
    pub fn new(assumes_yes: bool, verbosity: Verbosity, force_no_colour: bool) -> Self {
        // Both stdin and stderr, never `/dev/tty`, which stays open through a redirect and
        // would hang an unattended run that keeps a controlling terminal. Revisit if a
        // `--batch` flag ever gives unattended runs their own way to say nobody is there.
        let is_interactive = io::stdin().is_terminal() && io::stderr().is_terminal();
        // NO_COLOR is honoured for any non-empty value, per the no-color.org convention
        let no_colour_env = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Self {
            uses_colour: io::stderr().is_terminal() && !no_colour_env && !force_no_colour,
            is_interactive,
            verbosity,
            assumes_yes,
        }
    }

    /// Prints progress and status to stderr, so `--stdout` archives and `--json` reports pipe
    /// clean. `--quiet` drops it.
    fn narrate(&self, line: &str) {
        if self.verbosity == Verbosity::Normal {
            self.always(line);
        }
    }

    /// Prints a line `--quiet` must not swallow. The shipped systemd unit and the README's
    /// crontab pass `--quiet`, so a swallowed warning would let an unattended run narrow what
    /// it archived and still look clean.
    fn always(&self, line: &str) {
        let mut stderr = io::stderr();
        let _ = writeln!(stderr, "{line}");
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.uses_colour {
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
        self.narrate(&self.bold(text));
    }

    pub fn step(&self, text: &str) {
        self.narrate(&format!("{} {text}", self.dim("·")));
    }

    pub fn ok(&self, text: &str) {
        self.narrate(&format!("{} {text}", self.paint("32", "✓")));
    }

    pub fn fail(&self, text: &str) {
        self.always(&format!("{} {text}", self.paint("31", "✗")));
    }

    pub fn warn(&self, text: &str) {
        self.always(&format!("{} {text}", self.paint("33", "!")));
    }

    /// Marks a question that could not be answered, apart from the neutral `·` of a check that
    /// passed. Never swallowed, because an unanswerable check is a diagnostic.
    pub fn unknown(&self, text: &str) {
        self.always(&format!("{} {text}", self.dim("?")));
    }

    /// A hint attached to a step that went fine, which `--quiet` drops.
    pub fn hint(&self, text: &str) {
        self.narrate(&self.dim(&format!("  {text}")));
    }

    /// The lines under a `warn` or a `fail` that say which repositories are at risk, what to
    /// run next or where to look. Printed like a hint and never swallowed by `--quiet`.
    pub fn detail(&self, text: &str) {
        self.always(&self.dim(&format!("  {text}")));
    }

    pub fn blank(&self) {
        self.narrate("");
    }

    /// Prints machine output (JSON reports, listings, recovery sheets) to stdout.
    ///
    /// # Errors
    ///
    /// Returns a failed write, because half a JSON report under a success exit code is
    /// indistinguishable from a whole one. A closed pipe is not an error, since `| head`
    /// closes it on purpose.
    pub fn print(&self, line: &str) -> Result<()> {
        let mut stdout = io::stdout();
        match writeln!(stdout, "{line}").and_then(|()| stdout.flush()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(Error::PathlessIo(e)),
        }
    }

    pub fn print_json(&self, value: &serde_json::Value) -> Result<()> {
        self.print(&serde_json::to_string_pretty(value)?)
    }

    pub fn is_interactive(&self) -> bool {
        self.is_interactive
    }

    /// Asks a yes/no question. With nobody to ask (cron, a pipe) the answer is no unless
    /// `--yes` was passed, because a guessed yes can overwrite a home nobody meant to touch.
    pub fn confirm(&self, question: &str) -> Result<bool> {
        if self.assumes_yes {
            return Ok(true);
        }
        if !self.is_interactive {
            return Ok(false);
        }
        let mut stderr = io::stderr();
        write!(stderr, "{question} [y/N] ").map_err(Error::PathlessIo)?;
        stderr.flush().map_err(Error::PathlessIo)?;

        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(Error::PathlessIo)?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
    }
}

/// Renders a byte count in the largest binary unit that keeps a whole part.
pub fn human_bytes(n: u64) -> String {
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

/// A count with the noun that agrees with it, so no line reads "1 repositories".
pub fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Names the first five ids and counts the rest, because a long list of identifiers stops
/// being readable while the count still says how much of the home is affected.
pub fn shortlist<S: AsRef<str>>(ids: impl IntoIterator<Item = S>) -> String {
    const NAMED: usize = 5;
    let all: Vec<S> = ids.into_iter().collect();
    let named = all
        .iter()
        .take(NAMED)
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(", ");
    match all.len().saturating_sub(NAMED) {
        0 => named,
        rest => format!("{named}, and {rest} more"),
    }
}

/// The verb that agrees with a count, so no line reads "1 of 3 are in no archive".
pub fn is_or_are(n: usize) -> &'static str {
    if n == 1 { "is" } else { "are" }
}

/// Whole days between two instants, negative when `from` is ahead of `to`.
///
/// An archive's age is read off two stamps (the state file and the file name), and both go
/// through this, so one archive is never stale in one report and fresh in the other.
pub fn days_between(from: jiff::Timestamp, to: jiff::Timestamp) -> i64 {
    to.duration_since(from).as_secs().div_euclid(60 * 60 * 24)
}

/// Renders a day count for "this backup is 40 days old" style reporting.
pub fn days_ago(days: i64) -> String {
    match days {
        0 => "today".to_string(),
        1 => "yesterday".to_string(),
        // A clock that ran fast on the machine that took it, where "-36 days ago" would read
        // as a typo
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
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(524), "524 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(20_480), "20.0 KiB");
        assert_eq!(human_bytes(976 * 1024 * 1024), "976.0 MiB");
        assert_eq!(human_bytes(2_147_483_648), "2.0 GiB");
    }

    #[test]
    fn recent_days_read_as_words_and_older_ones_as_counts() {
        assert_eq!(days_ago(0), "today");
        assert_eq!(days_ago(1), "yesterday");
        assert_eq!(days_ago(40), "40 days ago");
    }
}
