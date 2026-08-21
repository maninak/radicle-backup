//! Taking a backup without having to remember to.
//!
//! The archive people lose their identity without is the one they meant to take last month.
//! This installs a systemd user timer, checks that the run it schedules can actually work
//! unattended, and turns it on. It writes only files it wrote, and never enables anything the
//! user did not ask for in the same breath.

use std::path::{Path, PathBuf};

use crate::cli::Schedule;
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::exec::Tool;

/// Stamped into every unit this command writes, so it can tell its own file from one somebody
/// hand-wrote and must not be overwritten.
///
/// It used to end "Edit freely; it will not be replaced", which is the opposite of what
/// `write_unit` does: a file carrying the marker is exactly the file the next run overwrites,
/// so an edit made in place was lost without a word. Deleting the line is what keeps a unit.
const MARKER: &str = concat!(
    "# Written by `rad backup schedule`, and replaced by its next run.\n",
    "# Delete both these lines to keep your own edits."
);

/// The header on the environment file. Deliberately not MARKER: that one tells the reader
/// that deleting it keeps their edits, which is true of a unit, because `write_unit` refuses a
/// file without the mark, and false here, because this file is rewritten in full by every run
/// whatever it holds. The same promise the marker rewording set out to stop making.
const ENVIRONMENT_MARK: &str = concat!(
    "# Written by `rad backup schedule`, and rewritten in full by its next run.\n",
    "# A lasting change belongs on the command line, not in this file."
);

/// The half of the marker that decides whether a unit is ours, kept apart from the wording so
/// that rephrasing the advice cannot make every unit written by an older version look like
/// somebody's hand-written file and refuse to be updated.
const MARKER_MARK: &str = "# Written by `rad backup schedule`";

const SERVICE: &str = "rad-backup.service";
const TIMER: &str = "rad-backup.timer";

pub fn run(ctx: &Ctx, args: &Schedule) -> Result<()> {
    ctx.home.require()?;
    // Checked here too: this is the verb that writes the number into a file a timer reads
    // every night, so a bad one is installed rather than typed once.
    if let Some(keep) = args.keep {
        crate::cmd::refuse_keep_zero(keep)?;
    }
    let systemctl = Tool::on_path("systemctl");
    if !systemctl.is_available() {
        return refuse_without_systemd(ctx, args);
    }

    if args.status {
        return status(ctx, &systemctl);
    }
    if args.off {
        // Checked, like `enable` below: told the timer was off while systemd kept running it
        // nightly, a user has been given the opposite of the truth about their own machine.
        if !systemctl.passthrough(&["--user", "disable", "--now", TIMER])? {
            return Err(Error::refused(
                format!("systemd would not disable {TIMER}, so the timer may still be armed"),
                "run `systemctl --user disable --now rad-backup.timer` to see what it objects to",
            ));
        }
        ctx.term
            .ok("the timer is off; the unit files are still there");
        ctx.term.hint("turn it back on with `rad backup schedule`");
        return Ok(());
    }

    // An unattended run cannot be asked for a passphrase, and an encrypted archive needs one.
    // Enabling a timer that is certain to fail every night is worse than not enabling it.
    //
    // What this process can see is not what the timer will see. A `RAD_BACKUP_PASSPHRASE`
    // exported in the shell that runs this command reaches this process and nothing else:
    // systemd starts the service from its own environment, and the environment file this
    // command writes deliberately never carries the passphrase itself. Accepting that passed
    // the check and installed a timer that then failed every night at the prompt.
    // Nothing to unlock, so nothing to ask for: an archive written to a recipient needs
    // only their public key, and a plaintext one needs nothing at all.
    let unattended = !args.recipient.is_empty() || args.plaintext;
    let passphrase_file = ctx.global.passphrase_file.clone();
    if !unattended && passphrase_file.is_none() && !systemd_holds_passphrase(&systemctl)? {
        return Err(Error::refused(
            "a scheduled run has nobody to ask for the archive passphrase",
            "put it in a file only you can read and pass --passphrase-file <path>; an exported \
             RAD_BACKUP_PASSPHRASE reaches this command and not the timer, which systemd starts \
             from its own environment",
        ));
    }

    let dir = unit_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let environment = environment_file()?;
    write_environment(ctx, &environment, args, passphrase_file.as_deref())?;
    let encryption = encryption_arguments(&args.recipient, args.plaintext);
    write_unit(
        ctx,
        &dir.join(SERVICE),
        &service_unit(&environment, &encryption),
    )?;
    write_unit(ctx, &dir.join(TIMER), &timer_unit(&args.every))?;

    // The booleans matter: `enable` is where systemd parses OnCalendar=, so a schedule it
    // rejects fails HERE. Discarding these answers is how a user ends up told a backup will
    // be taken nightly by a timer systemd never loaded.
    if !systemctl.passthrough(&["--user", "daemon-reload"])? {
        return Err(Error::refused(
            "systemd would not reload its unit files, so the timer was not installed",
            "run `systemctl --user daemon-reload` to see what it objects to",
        ));
    }
    if !systemctl.passthrough(&["--user", "enable", "--now", TIMER])? {
        return Err(Error::refused(
            format!(
                "systemd would not enable {TIMER}, so no backup is scheduled; `{}` is the \
                 likeliest thing it rejected",
                args.every
            ),
            "run `systemd-analyze calendar '<expression>'` to check the schedule, then try again",
        ));
    }
    ctx.term
        .ok(&format!("a backup will be taken {}", describe(&args.every)));
    status(ctx, &systemctl)
}

/// Whether systemd's own environment already carries the archive passphrase.
///
/// Asked because refusing on the absence of `--passphrase-file` alone would break a timer that
/// works: a passphrase put where systemd keeps it, with `systemctl --user set-environment` or
/// a file in `~/.config/environment.d/`, does reach the service. What this process inherited
/// from the shell does not, which is why the shell's own environment is not consulted here.
fn systemd_holds_passphrase(systemctl: &Tool) -> Result<bool> {
    let shown = systemctl.spoken(&["--user", "show-environment"])?;
    let prefix = format!("{}=", crate::crypt::PASSPHRASE_ENV);
    Ok(shown.stdout.lines().any(|line| line.starts_with(&prefix)))
}

/// What to report about the timer, from what `is-enabled` said and, when that said nothing,
/// what systemd knows about the unit. `None` is "systemd could not be asked at all".
///
/// `is-enabled` prints its verdict and exits non-zero to express it, so the word on stdout is
/// the answer whatever the status was. Nothing at all has two opposite causes. A unit that was
/// never installed is a definite answer, and it is the commonest one, because checking before
/// scheduling anything is the commonest reason to ask. A systemd that could not be reached, no
/// user bus over a plain ssh session and no lingering, is not an answer at all: reporting it
/// as "disabled" told people on headless machines their backups were off while the timer ran
/// every night.
fn timer_verdict(said: &str, load_state: &str) -> Option<String> {
    if !said.is_empty() {
        return Some(said.to_string());
    }
    load_state
        .trim()
        .strip_prefix("LoadState=")
        .filter(|state| *state == "not-found")
        .map(|_| "disabled".to_string())
}

fn status(ctx: &Ctx, systemctl: &Tool) -> Result<()> {
    let asked = systemctl.spoken(&["--user", "is-enabled", TIMER])?;
    // Only when there is nothing to go on, so the ordinary path still costs one spawn.
    let load = match asked.stdout.is_empty() {
        true => {
            systemctl
                .spoken(&["--user", "show", TIMER, "-p", "LoadState"])?
                .stdout
        }
        false => String::new(),
    };
    let enabled = match timer_verdict(&asked.stdout, &load) {
        Some(word) => word,
        None => {
            ctx.term
                .warn("systemd could not be asked whether the timer is on");
            if !asked.stderr.is_empty() {
                ctx.term.detail(&asked.stderr);
            }
            "unknown".to_string()
        }
    };
    let next = systemctl
        .raw_output(&["--user", "show", TIMER, "-p", "NextElapseUSecRealtime"])?
        .and_then(|out| out.trim().split_once('=').map(|(_, when)| when.to_string()))
        .filter(|when| !when.is_empty());
    let last = systemctl
        .raw_output(&["--user", "show", SERVICE, "-p", "Result"])?
        .and_then(|out| out.trim().split_once('=').map(|(_, what)| what.to_string()))
        .filter(|what| !what.is_empty() && what != "success");

    if ctx.global.json {
        return ctx.term.print_json(&serde_json::json!({
            "enabled": enabled == "enabled",
            // The word systemd used, because "enabled: false" cannot tell a timer that is off
            // from a systemd that could not be reached.
            "state": enabled,
            "next": next,
            "lastFailure": last,
        }));
    }
    if enabled == "unknown" {
        ctx.term
            .detail("run `systemctl --user is-enabled rad-backup.timer` on the machine itself");
    } else if enabled == "enabled" {
        ctx.term.ok(&format!(
            "the timer is on{}",
            next.map(|when| format!(", next run {when}"))
                .unwrap_or_default()
        ));
    } else {
        ctx.term.warn("no backup is scheduled on this machine");
        ctx.term.detail("turn one on with `rad backup schedule`");
    }
    if let Some(failure) = last {
        ctx.term
            .fail(&format!("the last scheduled run ended as: {failure}"));
        ctx.term
            .detail("read it with `journalctl --user -u rad-backup.service`");
    }
    Ok(())
}

/// Always refuses, on a machine with no systemd. Nothing is installed, and the line that would
/// do the same job is printed rather than described, so it can be pasted.
fn refuse_without_systemd(ctx: &Ctx, args: &Schedule) -> Result<()> {
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("/path/to/backups"));
    let keep = args.keep.unwrap_or(7);
    let binary = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "rad-backup".to_string());
    ctx.term
        .warn("there is no systemd here, so nothing was installed");
    ctx.term.detail("this crontab line does the same job:");
    ctx.term.blank();
    let encryption = shell_encryption_arguments(&args.recipient, args.plaintext);
    ctx.term.print(&format!(
        "  0 3 * * *  {} --output {} --keep {keep} --yes --quiet{encryption}",
        shell_quoted(&binary),
        shell_quoted(&output.display().to_string())
    ))?;
    ctx.term.blank();
    if encryption.is_empty() {
        ctx.term.hint(
            "the run needs RAD_BACKUP_PASSPHRASE_FILE set in that crontab, or it will stop \
             to ask for a passphrase nobody is there to type",
        );
    }
    Err(Error::refused(
        "no timer was installed",
        "paste the line above into `crontab -e`",
    ))
}

fn unit_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => home_dir()?.join(".config"),
    };
    Ok(base.join("systemd").join("user"))
}

fn environment_file() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => home_dir()?.join(".config"),
    };
    Ok(base.join("rad-backup").join("env"))
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        Error::refused(
            "cannot tell where your home directory is",
            "set HOME, or XDG_CONFIG_HOME",
        )
    })
}

/// What a scheduled run reads its settings from. Kept apart from the writing so the one
/// promise this file may make can be asserted without a filesystem.
fn environment_text(
    home: &Path,
    output: Option<&Path>,
    keep: Option<usize>,
    passphrase_file: Option<&Path>,
) -> String {
    let mut lines = vec![
        ENVIRONMENT_MARK.to_string(),
        format!("RAD_HOME={}", home.display()),
    ];
    if let Some(output) = output {
        lines.push(format!("RAD_BACKUP_DIR={}", output.display()));
    }
    if let Some(keep) = keep {
        lines.push(format!("RAD_BACKUP_KEEP={keep}"));
    }
    if let Some(file) = passphrase_file {
        lines.push(format!("RAD_BACKUP_PASSPHRASE_FILE={}", file.display()));
    }
    format!("{}\n", lines.join("\n"))
}

/// The environment a scheduled run reads. Written owner-only, because the path to a
/// passphrase file is a map to the passphrase.
fn write_environment(
    ctx: &Ctx,
    path: &Path,
    args: &Schedule,
    passphrase_file: Option<&Path>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let text = environment_text(
        ctx.home.path(),
        args.output.as_deref(),
        args.keep,
        passphrase_file,
    );
    crate::perms::write_owner_only(path, text.as_bytes())?;
    ctx.term.step(&format!("wrote {}", path.display()));
    Ok(())
}

fn write_unit(ctx: &Ctx, path: &Path, contents: &str) -> Result<()> {
    if std::fs::read_to_string(path).is_ok_and(|existing| !existing.contains(MARKER_MARK)) {
        return Err(Error::refused(
            format!("{} was not written by this tool", path.display()),
            "edit it yourself, or move it aside and run this again",
        ));
    }
    std::fs::write(path, contents).map_err(|e| Error::io(path, e))?;
    ctx.term.step(&format!("wrote {}", path.display()));
    Ok(())
}

/// One argument as systemd will read it back: quoted, because systemd word-splits an
/// unquoted `ExecStart=` and an age recipient is a public key with spaces in it.
///
/// `$` and `%` are doubled as well as escaped. Quoting does not stop systemd substituting
/// `$VAR` or expanding a `%h`-style specifier in `ExecStart=`, and an ssh recipient carries
/// a free-text comment, so both can arrive inside a key this tool was handed.
fn quoted(argument: &str) -> String {
    format!(
        "\"{}\"",
        argument
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "$$")
            .replace('%', "%%")
    )
}

/// One argument as `sh` will read it back. Single quotes take every other character
/// literally, and the quote itself is closed, escaped and reopened.
fn shell_quoted(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "'\\''"))
}

/// How the scheduled run should encrypt, spelled on the command line rather than put in the
/// environment file: a recipient is not a secret, and the flag that says "no encryption at
/// all" belongs where somebody reading the unit will see it.
fn encryption_arguments(recipients: &[String], plaintext: bool) -> String {
    if plaintext {
        return " --plaintext".to_string();
    }
    recipients
        .iter()
        .map(|key| format!(" --recipient {}", quoted(key)))
        .collect()
}

/// The same, for the crontab line printed where there is no systemd. Built from the recipients
/// rather than by rewriting the systemd spelling: those are two quoting languages, and the
/// rewrite left systemd's doubled backslashes inside single quotes and could produce a line
/// `sh` would not run at all.
fn shell_encryption_arguments(recipients: &[String], plaintext: bool) -> String {
    if plaintext {
        return " --plaintext".to_string();
    }
    recipients
        .iter()
        .map(|key| format!(" --recipient {}", shell_quoted(key)))
        .collect()
}

fn service_unit(environment: &Path, encryption: &str) -> String {
    let binary = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "rad-backup".to_string());
    format!(
        "{MARKER}
[Unit]
Description=Archive this Radicle identity
Documentation=man:rad-backup(1)

[Service]
Type=oneshot
EnvironmentFile=-{}
ExecStart={} --yes --quiet{encryption}
Nice=10
IOSchedulingClass=idle
",
        environment.display(),
        quoted(&binary)
    )
}

fn timer_unit(calendar: &str) -> String {
    format!(
        "{MARKER}
[Unit]
Description=Archive this Radicle identity {calendar}

[Timer]
OnCalendar={calendar}
# So a laptop that was asleep at the appointed hour still gets its backup.
Persistent=true
RandomizedDelaySec=15min

[Install]
WantedBy=timers.target
"
    )
}

fn describe(every: &str) -> String {
    match every {
        "daily" => "every day".to_string(),
        "weekly" => "every week".to_string(),
        "hourly" => "every hour".to_string(),
        "monthly" => "every month".to_string(),
        other => format!("on the schedule `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_this_tool_wrote_carries_the_mark_that_lets_it_be_replaced() {
        assert!(timer_unit("daily").contains(MARKER));
        assert!(service_unit(Path::new("/tmp/env"), "").contains(MARKER));
    }

    #[test]
    fn a_timer_that_was_never_installed_reads_as_off_rather_than_unknown() {
        // `is-enabled` says nothing for a unit that is not there, and saying nothing was read
        // as "systemd could not be asked". Checking before scheduling anything is the
        // commonest reason to ask at all, and it was the one question left unanswered.
        assert_eq!(
            timer_verdict("", "LoadState=not-found").as_deref(),
            Some("disabled")
        );
    }

    #[test]
    fn a_systemd_that_could_not_be_asked_is_neither_on_nor_off() {
        // No user bus over a plain ssh session: nothing on stdout and nothing to load. Calling
        // that "disabled" told people on headless machines their nightly backups were off.
        assert_eq!(timer_verdict("", ""), None);
        assert_eq!(timer_verdict("", "LoadState=loaded"), None);
    }

    #[test]
    fn the_word_is_enabled_printed_is_the_answer_whatever_its_exit_status_was() {
        assert_eq!(timer_verdict("enabled", "").as_deref(), Some("enabled"));
        assert_eq!(timer_verdict("static", "").as_deref(), Some("static"));
    }

    #[test]
    fn a_recipient_reaches_the_unit_quoted_and_a_passphrase_file_is_not_demanded() {
        // An age recipient is a public key with spaces in it, so an unquoted one would be
        // word-split by systemd into flags it does not recognise.
        let unit = service_unit(
            Path::new("/tmp/env"),
            &encryption_arguments(&["ssh-ed25519 AAAA nobody@example".to_string()], false),
        );
        let exec = unit
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .expect("the service has an ExecStart");
        assert!(
            exec.contains("--recipient \"ssh-ed25519 AAAA nobody@example\""),
            "{exec}"
        );
    }

    #[test]
    fn asking_for_no_encryption_says_so_on_the_command_line_the_timer_runs() {
        // In the unit rather than the environment file, because "this timer writes your
        // private key in the clear every night" is not a thing to keep out of sight.
        let arguments = encryption_arguments(&[], true);
        assert_eq!(arguments, " --plaintext");
        assert!(service_unit(Path::new("/tmp/env"), &arguments).contains("--plaintext"));
    }

    #[test]
    fn a_recipient_that_holds_a_quote_cannot_break_out_of_the_unit() {
        let broken = quoted("ssh-ed25519 \"AAAA\" \\x");
        assert_eq!(broken, "\"ssh-ed25519 \\\"AAAA\\\" \\\\x\"");
    }

    #[test]
    fn a_recipient_systemd_would_expand_reaches_the_run_as_it_was_given() {
        // Quoting does not stop systemd substituting in `ExecStart=`: `$HOME` becomes the
        // value of a variable and `%h` becomes a path. An ssh recipient ends in a free-text
        // comment, so both arrive in keys people really paste.
        let expanded = quoted("ssh-ed25519 AAAA 100% of $HOME");
        assert_eq!(expanded, "\"ssh-ed25519 AAAA 100%% of $$HOME\"");
    }

    #[test]
    fn the_crontab_line_quotes_a_recipient_the_shell_would_otherwise_choke_on() {
        // Built from the recipients, not by rewriting the systemd spelling: that rewrite left
        // systemd's doubled backslashes inside single quotes, and a recipient holding a quote
        // produced a line `sh` refused outright with "unterminated quoted string".
        let arguments =
            shell_encryption_arguments(&["ssh-ed25519 AAAA it's mine".to_string()], false);
        assert_eq!(arguments, " --recipient 'ssh-ed25519 AAAA it'\\''s mine'");

        // And the shell really does read it back as the one word it went in as.
        let out = std::process::Command::new("sh")
            .args(["-c", &format!("printf '%s'{arguments}")])
            .output()
            .expect("sh runs");
        assert!(out.status.success(), "sh refused: {arguments}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "--recipientssh-ed25519 AAAA it's mine"
        );
    }

    #[test]
    fn the_environment_file_does_not_promise_that_an_edit_will_survive() {
        let text = environment_text(Path::new("/home/someone/.radicle"), None, None, None);

        // MARKER says deleting it keeps your edits, which `write_unit` honours and this file
        // cannot: every run rewrites it in full whatever it holds.
        assert!(!text.contains("Delete both these lines"), "{text}");
        assert!(text.contains("rewritten in full"), "{text}");
        for line in text.lines().take(2) {
            assert!(line.starts_with('#'), "not a comment line: {line:?}");
        }
    }

    #[test]
    fn the_marker_says_the_unit_will_be_replaced_rather_than_promising_it_will_not() {
        // It read "Edit freely; it will not be replaced", which is what `write_unit` does to
        // a file WITHOUT the marker. A hand edit that kept the line was silently overwritten
        // by the next run, having been told in writing that it would not be.
        assert!(!MARKER.contains("will not be replaced"));
        assert!(MARKER.contains("replaced by its next run"));

        // The recognition half must survive a rewording of the advice, or every unit written
        // by an older version stops being recognised as ours and refuses to be updated.
        assert!(MARKER.contains(MARKER_MARK));
        for line in MARKER.lines() {
            // systemd reads these as comments, and a comment starts the line.
            assert!(line.starts_with('#'), "not a comment line: {line:?}");
        }
    }

    #[test]
    fn a_binary_whose_path_holds_a_space_still_produces_a_unit_systemd_can_run() {
        // systemd word-splits an unquoted ExecStart=, and this project itself lives under a
        // path with a space in it, so a dev-built binary produced a unit that parsed into a
        // truncated path and failed only when the timer first fired.
        let unit = service_unit(Path::new("/tmp/env"), "");
        let exec = unit
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .expect("the service has an ExecStart");
        assert!(
            exec["ExecStart=".len()..].starts_with('"'),
            "the binary path must be quoted: {exec}"
        );
    }

    #[test]
    fn a_timer_catches_up_after_the_machine_was_asleep() {
        assert!(
            timer_unit("daily").contains("Persistent=true"),
            "a laptop that misses its window must still take the backup"
        );
    }

    #[test]
    fn a_schedule_systemd_understands_is_passed_through_unchanged() {
        // `--every` accepts anything systemd's OnCalendar accepts, so nothing here may
        // reinterpret it: systemd is the only thing that gets to decide what it means.
        assert!(timer_unit("Mon *-*-* 03:30:00").contains("OnCalendar=Mon *-*-* 03:30:00"));
    }
}
