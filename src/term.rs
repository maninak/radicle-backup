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
            let mut err = io::stderr();
            let _ = writeln!(err, "{line}");
        }
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
        self.say(&format!("{} {text}", self.paint("31", "✗")));
    }

    pub fn warn(&self, text: &str) {
        self.say(&format!("{} {text}", self.paint("33", "!")));
    }

    pub fn hint(&self, text: &str) {
        self.say(&self.dim(&format!("  {text}")));
    }

    pub fn blank(&self) {
        self.say("");
    }

    /// Anything a machine consumes goes to stdout: archives, JSON reports, generated sheets.
    pub fn print(&self, line: &str) {
        let mut out = io::stdout();
        let _ = writeln!(out, "{line}");
    }

    pub fn print_json(&self, value: &serde_json::Value) -> Result<()> {
        self.print(&serde_json::to_string_pretty(value)?);
        Ok(())
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

/// Render a duration in whole days, for "this backup is 40 days old" style reporting.
pub fn days_ago(days: i64) -> String {
    match days {
        0 => "today".to_string(),
        1 => "yesterday".to_string(),
        n => format!("{n} days ago"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
