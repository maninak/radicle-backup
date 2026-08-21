//! Running the two programs this tool delegates to, `rad` and `git`.
//!
//! Delegating instead of linking is deliberate. The user's own `rad` and `git` are by
//! definition the right versions for the home being backed up, so an archive taken by an old
//! build of this tool still reads a new storage format, and a new build still reads an old
//! one. Revisit when heartwood publishes a stable on-disk format guarantee that makes linking
//! `radicle` safe across versions.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use crate::error::{Error, Result};

/// What a child process is allowed to inherit of the two passphrases this tool may hold.
///
/// A child inherits the whole environment unless something takes things out of it, and an
/// environment is readable by anything that process goes on to run: a git hook, a credential
/// helper, a pager. So each spawn says out loud which secrets it needs, and everything else
/// is removed rather than left there because nobody thought about it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Secrets {
    /// Nothing. What `git` and every other helper gets.
    None,
    /// The Radicle key passphrase, and only that. `rad node start`, `rad seed` and `rad
    /// follow` sign with the key, so `rad` is the one program that has a use for it.
    KeyPassphrase,
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

impl Tool {
    /// `rad`, pointed at a specific Radicle home. Honours `RAD` so an operator can name a
    /// specific binary, the same way radicle-seed-prune does.
    pub fn rad(home: &Path) -> Self {
        Self {
            program: std::env::var("RAD").unwrap_or_else(|_| "rad".to_string()),
            home: Some(home.to_string_lossy().into_owned()),
            secrets: Secrets::KeyPassphrase,
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
        let out = self.raw(args)?;
        if !out.status.success() {
            return Err(self.failure(args, &out));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Run and capture stdout, treating a non-zero exit as "no answer" rather than as a
    /// failure. For queries whose absence is a legitimate result, such as a ref that does not
    /// exist.
    ///
    /// Named for what it returns rather than for the capture, because `raw` beside it is the
    /// plumbing every one of these sits on and sharing that word said the wrong thing about
    /// which of them is the low-level one.
    pub fn answer<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Option<String>> {
        let out = self.raw(args)?;
        if !out.status.success() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
    }

    /// Run and keep what the program said, whatever it exited with.
    ///
    /// For programs that print their answer and then exit non-zero to express it, such as
    /// `systemctl is-enabled`, which writes "disabled" and exits 1. Reading those through
    /// `answer` threw the word away and left the caller unable to tell a real answer from
    /// a systemd that could not be reached at all.
    pub fn spoken<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Spoken> {
        let out = self.raw(args)?;
        Ok(Spoken {
            stdout: String::from_utf8_lossy(&out.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        })
    }

    /// Run and report only whether it succeeded. For probes where a non-zero exit is an
    /// answer rather than an error, such as `git merge-base --is-ancestor`.
    pub fn succeeds<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<bool> {
        Ok(self.raw(args)?.status.success())
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
        // Git must not read the invoking user's aliases, hooks or pager: this tool parses
        // git's output, and a `[pager] log = less` in someone's config would hang the run.
        cmd.env("GIT_PAGER", "cat");
        cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        // The archive passphrase is never any child's business, and the key passphrase is
        // only `rad`'s. Removed here, in the one place every spawn goes through, rather than
        // at each call site where the next one added would forget.
        cmd.env_remove(crate::crypt::PASSPHRASE_ENV);
        if self.secrets == Secrets::None {
            cmd.env_remove(crate::crypt::KEY_PASSPHRASE_ENV);
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

    fn failure<S: AsRef<OsStr>>(&self, args: &[S], out: &Output) -> Error {
        Error::Command {
            command: self.display(args),
            status: match out.status.code() {
                Some(code) => format!("exit code {code}"),
                None => "a signal".to_string(),
            },
            stderr: String::from_utf8_lossy(&out.stderr).trim_end().to_string(),
        }
    }

    fn display<S: AsRef<OsStr>>(&self, args: &[S]) -> String {
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
    fn no_child_inherits_the_archive_passphrase() {
        for tool in [
            Tool::git(),
            Tool::on_path("systemctl"),
            Tool::rad(Path::new("/nowhere")),
        ] {
            assert!(
                removed_by(&tool).contains(&crate::crypt::PASSPHRASE_ENV.to_string()),
                "{} would have inherited the archive passphrase",
                tool.program
            );
        }
    }

    #[test]
    fn only_rad_inherits_the_key_passphrase_because_only_rad_signs_with_the_key() {
        let key = crate::crypt::KEY_PASSPHRASE_ENV.to_string();
        assert!(removed_by(&Tool::git()).contains(&key));
        assert!(removed_by(&Tool::on_path("systemctl")).contains(&key));
        assert!(!removed_by(&Tool::rad(Path::new("/nowhere"))).contains(&key));
    }
}
