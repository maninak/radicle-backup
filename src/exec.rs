//! Running the programs this tool delegates to: `rad` and `git`, and `systemctl` and `uname`
//! for the two commands that need them.
//!
//! Delegated rather than linked, because the user's own `rad` and `git` are by definition the
//! right versions for the home being backed up: an archive taken by an old build of this tool
//! still reads a new storage format, and a new build still reads an old one. Revisit when
//! heartwood publishes a stable on-disk format guarantee that makes linking `radicle` safe
//! across versions.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use crate::error::{Error, Result};

/// What a child process is allowed to inherit of the passphrases this tool may hold.
///
/// A child inherits the whole environment unless something takes things out of it, and an
/// environment is readable by anything that process goes on to run: a git hook, a credential
/// helper, a pager. So each spawn says out loud which secrets it needs, and everything else
/// is removed rather than left there because nobody thought about it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Secrets {
    /// Nothing. What `git` and every other helper gets.
    None,
    /// One passphrase, and nothing else. `rad node start`, `rad seed` and `rad follow` sign
    /// with the Radicle key, so `rad` is the one program that has a use for one.
    Only(crate::crypt::Protects),
}

/// What a program said, kept apart from whether it succeeded.
pub struct Spoken {
    pub stdout: String,
    pub stderr: String,
}

/// A program we shell out to, with the environment it needs to see.
pub struct Tool {
    program: String,
    home: Option<String>,
    secrets: Secrets,
}

/// What a probe said, when it was in a position to say anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Yes,
    No,
    /// The command failed rather than answered. `said` is whatever it wrote to stderr, so the
    /// report can name the reason instead of inventing one.
    CouldNotAsk {
        said: String,
    },
}

impl Tool {
    /// `rad`, pointed at a specific Radicle home. Honours `RAD` so an operator can name a
    /// specific binary, the same way radicle-seed-prune does.
    pub fn rad(home: &Path) -> Self {
        Self {
            program: std::env::var("RAD").unwrap_or_else(|_| "rad".to_string()),
            home: Some(home.to_string_lossy().into_owned()),
            secrets: Secrets::Only(crate::crypt::Protects::RadicleKey),
        }
    }

    /// Any other program on PATH, with no Radicle home to point it at.
    pub fn on_path(program: &str) -> Self {
        Self {
            program: program.to_string(),
            home: None,
            secrets: Secrets::None,
        }
    }

    /// `git`, which needs no Radicle home of its own.
    pub fn git() -> Self {
        Self {
            program: std::env::var("GIT").unwrap_or_else(|_| "git".to_string()),
            home: None,
            secrets: Secrets::None,
        }
    }

    /// Run and capture stdout, failing when the program does.
    pub fn output<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<String> {
        let finished = self.raw(args)?;
        if !finished.status.success() {
            return Err(self.failure(args, &finished));
        }
        Ok(String::from_utf8_lossy(&finished.stdout).into_owned())
    }

    /// Run and capture stdout, treating a non-zero exit as "no answer" rather than as a
    /// failure. For queries whose absence is a legitimate result, such as a ref that does not
    /// exist.
    ///
    /// Named for what it returns rather than for the capture, because `raw` beside it is the
    /// plumbing every one of these sits on and sharing that word said the wrong thing about
    /// which of them is the low-level one.
    pub fn answer<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Option<String>> {
        let finished = self.raw(args)?;
        if !finished.status.success() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&finished.stdout).into_owned()))
    }

    /// Run a program whose OUTPUT is secret, and answer one question about it without handing
    /// the bytes back.
    ///
    /// `systemctl --user show-environment` prints systemd's whole environment, and when the
    /// archive passphrase is kept there, it prints that too. Every other buffer in this tool
    /// that touches a passphrase is wiped on the way out, and a `String` returned from here
    /// would be dropped intact for the next allocation to read. So the caller gets the answer
    /// and never the text.
    ///
    /// What this cannot reach: the pipe buffer `Command::output` reads the child through is
    /// private to the standard library. What this function owns, it wipes.
    pub fn confided<S: AsRef<OsStr>>(
        &self,
        args: &[S],
        ask: impl Fn(&str) -> bool,
    ) -> Result<bool> {
        let finished = self.raw(args)?;
        let stdout = zeroize::Zeroizing::new(finished.stdout);
        let text = zeroize::Zeroizing::new(String::from_utf8_lossy(&stdout).into_owned());
        Ok(ask(&text))
    }

    /// Run and keep what the program said, whatever it exited with.
    ///
    /// For programs that print their answer and then exit non-zero to express it, such as
    /// `systemctl is-enabled`, which writes "disabled" and exits 1. Reading those through
    /// `answer` threw the word away and left the caller unable to tell a real answer from
    /// a systemd that could not be reached at all.
    pub fn spoken<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Spoken> {
        let finished = self.raw(args)?;
        Ok(Spoken {
            stdout: String::from_utf8_lossy(&finished.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&finished.stderr).trim().to_string(),
        })
    }

    /// Run a command whose failure is not the run's failure, and keep what it said about it.
    ///
    /// `None` when it worked. Otherwise whatever it wrote to stderr, because the caller is
    /// about to tell somebody mid-recovery that one thing did not go, and the program's own
    /// sentence is the difference between that being actionable and being a shrug. A program
    /// that failed silently gets its exit code said for it, so the report is never empty.
    pub fn refused<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Option<String>> {
        let finished = self.raw(args)?;
        if finished.status.success() {
            return Ok(None);
        }
        let said = String::from_utf8_lossy(&finished.stderr).trim().to_string();
        if !said.is_empty() {
            return Ok(Some(said));
        }
        Ok(Some(match finished.status.code() {
            Some(code) => format!("{} exited {code} without saying why", self.program),
            None => format!("{} was killed before it could say why", self.program),
        }))
    }

    /// Run a probe whose non-zero exit is an answer, and keep "it could not answer" apart
    /// from "no".
    ///
    /// `git merge-base --is-ancestor` exits 0 for yes and 1 for no, and 128 when it could not
    /// answer at all: an oid it cannot resolve, an object it cannot read, a repository it
    /// will not open. Folded into a `bool` that third case reads as "no", and "no" in both
    /// directions is what a restore reports as a fork of the user's own peer history, which
    /// is the most alarming thing this tool ever says. A verdict that severe must not rest on
    /// an error nobody looked at.
    pub fn answers<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Answer> {
        let finished = self.raw(args)?;
        Ok(match finished.status.code() {
            Some(0) => Answer::Yes,
            Some(1) => Answer::No,
            // `None` is a signal, which is no more an answer than exit 128 is.
            _ => Answer::CouldNotAsk {
                said: String::from_utf8_lossy(&finished.stderr).trim().to_string(),
            },
        })
    }

    /// Run the child with its output visible, returning whether it exited successfully.
    ///
    /// Its stdout goes to our stderr, not to stdout: with `--stdout` this process's stdout IS
    /// the archive, and a line of `rad node stop` chatter written into it produces a file that
    /// decrypts, fails to decompress, and is discovered at restore time. Everything a child
    /// says here is narration, which is where narration goes anyway.
    pub fn passthrough<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<bool> {
        let status = self
            .command(args)
            .stdout(Stdio::from(io::stderr()))
            .stderr(Stdio::inherit())
            .status()
            .map_err(|source| Error::Spawn {
                program: self.program.clone(),
                source,
            })?;
        Ok(status.success())
    }

    pub fn is_available(&self) -> bool {
        // Through `command`, not `Command::new`, so the probe drops the passphrases like every
        // other spawn. Built by hand it inherited the whole environment, and a shimmed `git`
        // read the archive passphrase out of its own environ.
        self.command(&["--version"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn command<S: AsRef<OsStr>>(&self, args: &[S]) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(args);
        if let Some(home) = &self.home {
            cmd.env("RAD_HOME", home);
        }
        // No pager and no credential prompt, because this tool parses git's output and runs
        // unattended: a `[pager] log = less` in the user's config, or a prompt for a password,
        // would hang the run. The system-wide config is skipped for the same reason; the
        // user's own config, aliases and hooks are still read.
        cmd.env("GIT_PAGER", "cat");
        cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        // Removed here, in the one place every spawn goes through, and by walking `Protects`
        // rather than by naming variables: a secret added to that enum is scrubbed by this
        // loop on the day it appears, where a list here would have to be remembered. The
        // walk is a `match` chain and not an array precisely so the compiler asks.
        for protects in crate::crypt::Protects::all() {
            if self.secrets == Secrets::Only(protects) {
                continue;
            }
            cmd.env_remove(protects.env());
        }
        cmd
    }

    fn raw<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Output> {
        self.command(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|source| Error::Spawn {
                program: self.program.clone(),
                source,
            })
    }

    fn failure<S: AsRef<OsStr>>(&self, args: &[S], finished: &Output) -> Error {
        Error::Command {
            command: self.command_line(args),
            status: match finished.status.code() {
                Some(code) => format!("exit code {code}"),
                None => "a signal".to_string(),
            },
            stderr: String::from_utf8_lossy(&finished.stderr)
                .trim_end()
                .to_string(),
        }
    }

    fn command_line<S: AsRef<OsStr>>(&self, args: &[S]) -> String {
        let mut line = self.program.clone();
        for arg in args {
            line.push(' ');
            line.push_str(&arg.as_ref().to_string_lossy());
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Command::get_envs` reports a removal as a key with no value, which is how the
    /// scrubbing can be checked without a spawn and without touching this process's own
    /// environment.
    fn removed_by(tool: &Tool) -> Vec<String> {
        tool.command(&["--version"])
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn a_helper_that_needs_no_secret_inherits_none_of_them() {
        for tool in [Tool::git(), Tool::on_path("systemctl")] {
            let removed = removed_by(&tool);
            for protects in crate::crypt::Protects::all() {
                assert!(
                    removed.contains(&protects.env().to_string()),
                    "{} would have inherited {}",
                    tool.program,
                    protects.env()
                );
            }
        }
    }

    #[test]
    fn rad_inherits_the_radicle_key_passphrase_and_still_none_of_the_others() {
        let removed = removed_by(&Tool::rad(Path::new("/nowhere")));
        for protects in crate::crypt::Protects::all() {
            let inherited = !removed.contains(&protects.env().to_string());
            assert_eq!(
                inherited,
                protects == crate::crypt::Protects::RadicleKey,
                "rad and {}",
                protects.env()
            );
        }
    }
}
