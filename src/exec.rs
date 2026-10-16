//! Spawning `rad`, `git` and the system helpers with a scrubbed environment.

// Never link the `radicle` crate in place of spawning the user's `rad`, because that ties
// every archive to one `rad` version. Revisit if heartwood publishes a stable archive API.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use crate::error::{Error, Result};

/// The passphrases a child process may inherit.
///
/// A child's environment is readable by anything it runs, such as a git hook, a credential
/// helper or a pager. So every passphrase a spawn does not name is removed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Secrets {
    /// No passphrase.
    None,
    /// One passphrase. `rad` gets the Radicle key's, because `rad node start`, `rad seed` and
    /// `rad follow` sign with that key.
    Only(crate::crypt::Protects),
}

/// The trimmed stdout and stderr of a finished program, whatever its exit status.
pub struct Spoken {
    pub stdout: String,
    pub stderr: String,
}

/// A program to spawn, with the Radicle home and passphrases its environment carries.
pub struct Tool {
    program: OsString,
    home: Option<String>,
    secrets: Secrets,
}

/// The result of a yes-or-no probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Yes,
    No,
    /// The probe failed to answer. `said` holds its stderr, so a report can name the reason.
    CouldNotAsk {
        said: String,
    },
}

/// The binary `RAD` names, to run in place of `rad` from PATH.
///
/// An empty `RAD` counts as unset. The value stays an `OsString`, so a non-UTF-8 path works.
pub fn rad_override_from_env() -> Option<OsString> {
    std::env::var_os("RAD").filter(|rad| !rad.is_empty())
}

/// Explains why `rad` could not be run.
///
/// The message names `RAD` when it is set, because PATH is never searched then.
pub fn rad_missing(rad_override: Option<&OsStr>) -> String {
    match rad_override {
        Some(rad) => format!("RAD is set to {}, but it could not be run", rad.display()),
        None => "rad is not on PATH".to_string(),
    }
}

impl Tool {
    /// `rad` pointed at the Radicle home `home`, honouring a `RAD` override.
    pub fn rad(home: &Path) -> Self {
        Self {
            program: rad_override_from_env().unwrap_or_else(|| OsString::from("rad")),
            home: Some(home.to_string_lossy().into_owned()),
            secrets: Secrets::Only(crate::crypt::Protects::RadicleKey),
        }
    }

    /// A program on PATH, with no Radicle home and no passphrase.
    pub fn on_path(program: &str) -> Self {
        Self {
            program: OsString::from(program),
            home: None,
            secrets: Secrets::None,
        }
    }

    /// `git`, honouring a `GIT` override.
    pub fn git() -> Self {
        Self {
            program: std::env::var_os("GIT").unwrap_or_else(|| OsString::from("git")),
            home: None,
            secrets: Secrets::None,
        }
    }

    /// Runs the program and returns its stdout, failing on a non-zero exit.
    pub fn output<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<String> {
        let finished = self.raw(args)?;
        if !finished.status.success() {
            return Err(self.failure(args, &finished));
        }
        Ok(String::from_utf8_lossy(&finished.stdout).into_owned())
    }

    /// Runs the program and returns its stdout, or `None` on a non-zero exit.
    ///
    /// Suits queries where absence is a legitimate result, such as a ref that does not exist.
    pub fn answer<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Option<String>> {
        let finished = self.raw(args)?;
        if !finished.status.success() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&finished.stdout).into_owned()))
    }

    /// Runs a program whose output is secret and returns `ask`'s verdict on it, never the
    /// text.
    ///
    /// `systemctl --user show-environment` prints the archive passphrase when systemd holds
    /// it. Every buffer this function owns is wiped on drop. The pipe buffer inside
    /// `Command::output` is private to the standard library and stays out of reach.
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

    /// Runs the program and returns what it printed, whatever it exited with.
    ///
    /// Suits programs that answer through a non-zero exit, such as `systemctl is-enabled`,
    /// which prints `disabled` and exits 1.
    pub fn spoken<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Spoken> {
        let finished = self.raw(args)?;
        Ok(Spoken {
            stdout: String::from_utf8_lossy(&finished.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&finished.stderr).trim().to_string(),
        })
    }

    /// Runs a command whose failure is not the run's failure, and returns why it failed.
    ///
    /// Returns `None` on success. Otherwise it returns the program's stderr, or a sentence
    /// naming the exit code when stderr is empty, so the report is never blank.
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
            Some(code) => format!(
                "{} exited {code} without saying why",
                self.program.display()
            ),
            None => format!(
                "{} was killed before it could say why",
                self.program.display()
            ),
        }))
    }

    /// Runs a probe that exits 0 for yes and 1 for no, and keeps any other exit apart as
    /// [`Answer::CouldNotAsk`].
    ///
    /// `git merge-base --is-ancestor` exits 128 when it cannot resolve an oid or open the
    /// repository. Read as `No`, that exit would make a restore report a fork of the user's
    /// own peer history.
    pub fn answers<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Answer> {
        let finished = self.raw(args)?;
        Ok(match finished.status.code() {
            Some(0) => Answer::Yes,
            Some(1) => Answer::No,
            // A signal (`None`) is no answer either
            _ => Answer::CouldNotAsk {
                said: String::from_utf8_lossy(&finished.stderr).trim().to_string(),
            },
        })
    }

    /// Runs the program with its output visible and returns whether it succeeded.
    ///
    /// The child's stdout goes to this process's stderr, because under `--stdout` this
    /// process's stdout is the archive, and a stray line there corrupts it unnoticed.
    pub fn passthrough<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<bool> {
        let status = self
            .command(args)
            .stdout(Stdio::from(io::stderr()))
            .stderr(Stdio::inherit())
            .status()
            .map_err(|source| Error::Spawn {
                program: self.program.to_string_lossy().into_owned(),
                source,
            })?;
        Ok(status.success())
    }

    pub fn is_available(&self) -> bool {
        // The probe goes through `command`, so a shimmed `git` cannot read a passphrase
        // from its environment
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
        // A pager or a password prompt hangs an unattended run, so git gets neither. The
        // system-wide config is skipped for the same reason. The user's config still applies.
        cmd.env("GIT_PAGER", "cat");
        cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        // Walking `Protects` scrubs a secret added to that enum with no second list to update
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
                program: self.program.to_string_lossy().into_owned(),
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
        let mut line = self.program.to_string_lossy().into_owned();
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

    /// The variables `tool`'s command removes from its environment.
    ///
    /// `Command::get_envs` reports a removal as a key with no value, so the check needs no
    /// spawn.
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
                    tool.program.display(),
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
