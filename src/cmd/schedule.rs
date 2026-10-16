//! Scheduled backups through a systemd user timer.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::cli::Schedule;
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::exec::Tool;

/// The header stamped into every unit this command writes, which tells a unit it may replace
/// from a hand-written one.
///
/// `write_unit` overwrites a file carrying this header, so the wording tells the reader that
/// deleting it is what keeps an edit.
const MARKER_UNIT: &str = concat!(
    "# Written by `rad backup schedule`, and replaced by its next run.\n",
    "# Delete both these lines to keep your own edits."
);

/// The header on the environment file.
///
/// Every run rewrites this file in full, so its header must not promise that deleting it
/// keeps an edit, as `MARKER_UNIT` does.
const MARKER_ENVIRONMENT: &str = concat!(
    "# Written by `rad backup schedule`, and rewritten in full by its next run.\n",
    "# A lasting change belongs on the command line, not in this file."
);

/// The part of the marker that identifies a unit this command wrote.
///
/// This text stays fixed when the advice is reworded, so units written by an older version
/// are still recognised and updated.
const MARKER_SIGNATURE: &str = "# Written by `rad backup schedule`";

const SERVICE: &str = "rad-backup.service";
const TIMER: &str = "rad-backup.timer";

pub fn run(ctx: &Ctx, args: &Schedule) -> Result<()> {
    ctx.home.require_identity()?;
    // A bad `--keep` here would be installed into a file a timer reads every night
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
        // A failed disable leaves the timer running nightly, so it must not report success
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

    // An unattended run cannot be asked for a passphrase, so a timer without one fails every
    // night. A `RAD_BACKUP_PASSPHRASE` exported in this shell never reaches the timer, which
    // systemd starts from its own environment. Recipient and plaintext archives need none.
    let needs_no_passphrase = !args.recipient.is_empty() || args.plaintext;
    let passphrase_file = ctx.global.passphrase_file.clone();
    let passphrase_env = crate::crypt::ARCHIVE_PASSPHRASE_ENV;
    if !needs_no_passphrase
        && passphrase_file.is_none()
        && !systemd_holds(&systemctl, passphrase_env)?
    {
        return Err(Error::refused(
            "a scheduled run has nobody to ask for the archive passphrase",
            "put it in a file only you can read and pass --passphrase-file <path>; an exported \
             RAD_BACKUP_PASSPHRASE reaches this command and not the timer, which systemd starts \
             from its own environment",
        ));
    }

    // `rad` is resolved before anything is written, so a machine without it gets no timer
    let rad = rad_for_timer()?;

    let dir = unit_dir_from_env()?;
    std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let environment = environment_file_from_env()?;
    write_environment(ctx, &environment, args, passphrase_file.as_deref(), &rad)?;
    let encryption = encryption_arguments(&args.recipient, args.plaintext);
    write_unit(
        ctx,
        &dir.join(SERVICE),
        &service_unit(&environment, &encryption),
    )?;
    write_unit(ctx, &dir.join(TIMER), &timer_unit(&args.every))?;

    // `enable` is where systemd parses OnCalendar=, so a rejected schedule fails here and
    // ignoring these answers would report a backup scheduled on a timer systemd never loaded
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

/// Whether systemd's own environment already sets `name`.
///
/// A passphrase set with `systemctl --user set-environment` or in `~/.config/environment.d/`
/// reaches the service. This process's own environment does not, so it is not consulted.
fn systemd_holds(systemctl: &Tool, name: &str) -> Result<bool> {
    let prefix = format!("{name}=");
    // The output is systemd's whole environment, passphrase included, so it is read through
    // `confided`. An ordinary `String` would leave a copy in freed heap.
    systemctl.confided(&["--user", "show-environment"], |shown| {
        shown.lines().any(|line| line.starts_with(&prefix))
    })
}

/// The timer state to report, from what `is-enabled` `said` and, when that is empty, the
/// unit's `load_state`.
///
/// `is-enabled` exits non-zero to express its verdict, so the word it prints is the answer
/// whatever the exit status.
///
/// Returns `disabled` for a unit systemd has not found, and `None` when systemd could not be
/// asked, as over an ssh session with no user bus.
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

/// Whether what `systemctl is-enabled` said means the timer will fire, `enabled-runtime`
/// (on until the next reboot) included.
///
/// The test is a prefix, because systemd adds new answers over time and none of the others
/// starts with `enabled`.
fn timer_is_on(state: &str) -> bool {
    state.starts_with("enabled")
}

fn status(ctx: &Ctx, systemctl: &Tool) -> Result<()> {
    let is_enabled = systemctl.spoken(&["--user", "is-enabled", TIMER])?;
    // The second spawn runs only when `is-enabled` printed nothing
    let load_state = match is_enabled.stdout.is_empty() {
        true => {
            systemctl
                .spoken(&["--user", "show", TIMER, "-p", "LoadState"])?
                .stdout
        }
        false => String::new(),
    };
    let timer_state = match timer_verdict(&is_enabled.stdout, &load_state) {
        Some(word) => word,
        None => {
            ctx.term
                .warn("systemd could not be asked whether the timer is on");
            if !is_enabled.stderr.is_empty() {
                ctx.term.detail(&is_enabled.stderr);
            }
            "unknown".to_string()
        }
    };
    let next_run = systemctl
        .answer(&["--user", "show", TIMER, "-p", "NextElapseUSecRealtime"])?
        .and_then(|shown| shown.trim().split_once('=').map(|(_, at)| at.to_string()))
        .filter(|when| !when.is_empty());
    let last_failure = systemctl
        .answer(&["--user", "show", SERVICE, "-p", "Result"])?
        .and_then(|shown| {
            shown
                .trim()
                .split_once('=')
                .map(|(_, what)| what.to_string())
        })
        .filter(|what| !what.is_empty() && what != "success");

    let is_on = timer_is_on(&timer_state);
    if ctx.global.json {
        return ctx.term.print_json(&serde_json::json!({
            "enabled": is_on,
            // `state` tells an off timer from a systemd that could not be asked
            "state": timer_state,
            "next": next_run,
            "lastFailure": last_failure,
        }));
    }
    if timer_state == "unknown" {
        ctx.term
            .detail("run `systemctl --user is-enabled rad-backup.timer` on the machine itself");
    } else if is_on {
        ctx.term.ok(&format!(
            "the timer is on{}",
            next_run
                .map(|at| format!(", next run {at}"))
                .unwrap_or_default()
        ));
        if timer_state == "enabled-runtime" {
            ctx.term.detail(
                "only until the next reboot; `systemctl --user enable rad-backup.timer` makes \
                 it permanent",
            );
        }
    } else {
        ctx.term.warn("no backup is scheduled on this machine");
        ctx.term.detail("turn one on with `rad backup schedule`");
    }
    if let Some(failure) = last_failure {
        ctx.term
            .fail(&format!("the last scheduled run ended as: {failure}"));
        ctx.term
            .detail("read it with `journalctl --user -u rad-backup.service`");
    }
    Ok(())
}

/// Prints a crontab line that does the timer's job, then refuses.
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
    // cron's PATH is shorter than a login shell's, so the line names `rad` outright
    let rad = rad_from_env(crate::exec::rad_override_from_env());
    let rad_setting = match &rad {
        Ok(rad) => format!("RAD={} ", shell_systemd_quoted(&rad.display().to_string())),
        Err(_) => String::new(),
    };
    ctx.term.print(&format!(
        "  0 3 * * *  {rad_setting}{} --output {} --keep {keep} --yes --quiet{encryption}",
        shell_systemd_quoted(&binary),
        shell_systemd_quoted(&output.display().to_string())
    ))?;
    ctx.term.blank();
    if let Err(refused) = &rad {
        let said = refused.to_string();
        let mut lines = said.lines();
        if let Some(headline) = lines.next() {
            ctx.term.warn(headline);
        }
        for line in lines {
            ctx.term.hint(line);
        }
    }
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

/// The `rad` a scheduled run is to use, as this shell finds it.
///
/// systemd's PATH may lack `~/.radicle/bin`, which the Radicle installer adds only to shell rc
/// files, so this path is written to the environment file as `RAD`. That file overrides a
/// `RAD` set in systemd's own environment.
fn rad_for_timer() -> Result<PathBuf> {
    rad_from_env(crate::exec::rad_override_from_env())
}

/// `RAD` when it is set, else `rad` from PATH, as an absolute path.
fn rad_from_env(explicit: Option<OsString>) -> Result<PathBuf> {
    let cwd = std::env::current_dir().map_err(|e| Error::io(".", e))?;
    let name = explicit.clone().unwrap_or_else(|| OsString::from("rad"));
    find_program(&name, std::env::var_os("PATH").as_deref(), &cwd).ok_or_else(|| {
        let remedy = match explicit {
            Some(_) => "point RAD at the rad binary, or unset it to use the rad on PATH",
            None => {
                "install Radicle, or run this again with RAD=/path/to/rad. Without rad, a \
                 scheduled backup can miss repositories."
            }
        };
        Error::refused(crate::exec::rad_missing(explicit.as_deref()), remedy)
    })
}

/// Where a shell would find `name` on the `search` path, as an absolute path.
///
/// A relative `name` with a directory part is read against `cwd`. Empty and relative `search`
/// entries are skipped, because a `rad` planted in the current directory would be pinned into
/// a nightly timer that holds the passphrase.
///
/// A symlink is returned unresolved, so a `rad` upgraded by repointing its link stays in use.
fn find_program(name: &OsStr, search: Option<&OsStr>, cwd: &Path) -> Option<PathBuf> {
    let name = Path::new(name);
    if name.components().count() > 1 {
        return Some(cwd.join(name)).filter(|path| is_program(path));
    }
    std::env::split_paths(search?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|path| is_program(path))
}

fn is_program(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| is_executable(&metadata))
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file()
}

fn unit_dir_from_env() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => home_dir_from_env()?.join(".config"),
    };
    Ok(base.join("systemd").join("user"))
}

fn environment_file_from_env() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => home_dir_from_env()?.join(".config"),
    };
    Ok(base.join("rad-backup").join("env"))
}

fn home_dir_from_env() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        Error::refused(
            "cannot tell where your home directory is",
            "set HOME, or XDG_CONFIG_HOME",
        )
    })
}

/// The text of the environment file a scheduled run reads its settings from.
///
/// Rejects any path systemd would read back differently. A newline in a path would write a
/// second setting, and systemd's EnvironmentFile has no escape for one.
fn environment_text(
    home: &Path,
    output: Option<&Path>,
    keep: Option<usize>,
    passphrase_file: Option<&Path>,
    rad: Option<&Path>,
) -> Result<String> {
    let mut lines = vec![MARKER_ENVIRONMENT.to_string(), setting("RAD_HOME", home)?];
    if let Some(rad) = rad {
        lines.push(setting("RAD", rad)?);
    }
    if let Some(output) = output {
        lines.push(setting("RAD_BACKUP_DIR", output)?);
    }
    if let Some(keep) = keep {
        lines.push(format!("RAD_BACKUP_KEEP={keep}"));
    }
    if let Some(file) = passphrase_file {
        lines.push(setting("RAD_BACKUP_PASSPHRASE_FILE", file)?);
    }
    Ok(format!("{}\n", lines.join("\n")))
}

/// One `NAME=path` line for the environment file.
///
/// Rejects a path holding a line break or backslash, with whitespace at either end, or that
/// is not UTF-8, because systemd would read each of these back as a different path.
fn setting(name: &str, path: &Path) -> Result<String> {
    let Some(value) = path
        .to_str()
        .filter(|value| !value.contains(['\n', '\r', '\\']) && value.trim() == *value)
    else {
        return Err(Error::refused(
            format!("systemd cannot read {} back as written", path.display()),
            "use a path without line breaks, backslashes, spaces at either end or bytes that \
             are not UTF-8. Or schedule the backup with cron instead.",
        ));
    };
    Ok(format!("{name}={value}"))
}

/// Writes the environment file owner-only, because it holds the passphrase file's path.
fn write_environment(
    ctx: &Ctx,
    path: &Path,
    args: &Schedule,
    passphrase_file: Option<&Path>,
    rad: &Path,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let text = environment_text(
        ctx.home.path(),
        args.output.as_deref(),
        args.keep,
        passphrase_file,
        Some(rad),
    )?;
    crate::perms::write_owner_only(path, text.as_bytes())?;
    ctx.term.step(&format!("wrote {}", path.display()));
    ctx.term.detail(&format!(
        "scheduled backups will use rad at {}",
        rad.display()
    ));
    Ok(())
}

/// Writes one unit file, refusing to overwrite a file this tool did not write.
fn write_unit(ctx: &Ctx, path: &Path, contents: &str) -> Result<()> {
    let existing = std::fs::read_to_string(path);
    may_replace(path, existing.as_deref())?;
    std::fs::write(path, contents).map_err(|e| Error::io(path, e))?;
    ctx.term.step(&format!("wrote {}", path.display()));
    Ok(())
}

/// Whether the file at `path` may be replaced, given how reading it went.
///
/// Rejects a file that exists but cannot be read, such as a hand-written unit at mode 000 or
/// holding bytes that are not UTF-8.
fn may_replace(path: &Path, existing: std::result::Result<&str, &std::io::Error>) -> Result<()> {
    match existing {
        Ok(text) if !text.contains(MARKER_SIGNATURE) => Err(Error::refused(
            format!("{} was not written by this tool", path.display()),
            "edit it yourself, or move it aside and run this again",
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::refused(
            format!("{} is there and could not be read ({e})", path.display()),
            "this tool will not overwrite a unit it cannot recognise; move it aside and run \
             this again",
        )),
    }
}

/// Quotes one `ExecStart=` argument so systemd reads it back unchanged.
///
/// systemd word-splits an unquoted argument, and substitutes `$VAR` and `%h` even inside
/// quotes, so `$` and `%` are doubled. An ssh recipient's free-text comment can hold either.
fn systemd_quoted(argument: &str) -> String {
    format!(
        "\"{}\"",
        argument
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "$$")
            .replace('%', "%%")
    )
}

/// Quotes one argument of a crontab line so `sh` reads it back unchanged.
///
/// cron reads a bare `%` as a line break before `sh` sees it, and strips the backslash from
/// `\%`.
fn shell_systemd_quoted(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "'\\''").replace('%', "\\%"))
}

/// The encryption flags for the unit's command line.
///
/// A recipient is not a secret, and `--plaintext` belongs where a reader of the unit sees it.
fn encryption_arguments(recipients: &[String], plaintext: bool) -> String {
    if plaintext {
        return " --plaintext".to_string();
    }
    recipients
        .iter()
        .map(|key| format!(" --recipient {}", systemd_quoted(key)))
        .collect()
}

/// The encryption flags for the crontab line, quoted for `sh`.
fn shell_encryption_arguments(recipients: &[String], plaintext: bool) -> String {
    if plaintext {
        return " --plaintext".to_string();
    }
    recipients
        .iter()
        .map(|key| format!(" --recipient {}", shell_systemd_quoted(key)))
        .collect()
}

fn service_unit(environment: &Path, encryption: &str) -> String {
    let binary = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "rad-backup".to_string());
    format!(
        "{MARKER_UNIT}
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
        systemd_quoted(&binary)
    )
}

fn timer_unit(calendar: &str) -> String {
    format!(
        "{MARKER_UNIT}
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
    #[test]
    fn a_timer_enabled_only_until_the_next_reboot_is_still_a_timer_that_is_on() {
        assert!(super::timer_is_on("enabled"));
        assert!(super::timer_is_on("enabled-runtime"));

        for off in [
            "disabled", "static", "indirect", "masked", "linked", "unknown", "",
        ] {
            assert!(!super::timer_is_on(off), "{off}");
        }
    }

    use super::*;

    #[test]
    fn a_unit_that_is_there_and_unreadable_is_not_a_unit_that_is_absent() {
        use std::io::{Error as IoError, ErrorKind};

        let path = Path::new("/etc/systemd/system/rad-backup.service");

        let absent = IoError::from(ErrorKind::NotFound);
        assert!(may_replace(path, Err(&absent)).is_ok());

        let ours = format!("[Unit]\n{MARKER_SIGNATURE}\n");
        assert!(may_replace(path, Ok(&ours)).is_ok());

        let theirs = may_replace(path, Ok("[Unit]\nDescription=my own timer\n"))
            .expect_err("a unit this tool did not write is not this tool's to replace");
        assert!(theirs.to_string().contains("was not written by this tool"));

        let unreadable = IoError::from(ErrorKind::PermissionDenied);
        let refused = may_replace(path, Err(&unreadable))
            .expect_err("a file that could not be read is not a file that is not there");
        assert!(
            refused.to_string().contains("could not be read"),
            "{refused}"
        );
    }

    #[test]
    fn a_unit_this_tool_wrote_carries_the_mark_that_lets_it_be_replaced() {
        assert!(timer_unit("daily").contains(MARKER_UNIT));
        assert!(service_unit(Path::new("/tmp/env"), "").contains(MARKER_UNIT));
    }

    #[test]
    fn a_timer_that_was_never_installed_reads_as_off_rather_than_unknown() {
        // `is-enabled` prints nothing for a unit that is not there
        assert_eq!(
            timer_verdict("", "LoadState=not-found").as_deref(),
            Some("disabled")
        );
    }

    #[test]
    fn a_systemd_that_could_not_be_asked_is_neither_on_nor_off() {
        // An ssh session with no user bus gets nothing on stdout and no load state
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
        // systemd word-splits an unquoted recipient into flags it does not recognise
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
        // A timer that writes the key in the clear every night says so where a reader looks
        let arguments = encryption_arguments(&[], true);
        assert_eq!(arguments, " --plaintext");
        assert!(service_unit(Path::new("/tmp/env"), &arguments).contains("--plaintext"));
    }

    #[test]
    fn a_recipient_that_holds_a_quote_cannot_break_out_of_the_unit() {
        let broken = systemd_quoted("ssh-ed25519 \"AAAA\" \\x");
        assert_eq!(broken, "\"ssh-ed25519 \\\"AAAA\\\" \\\\x\"");
    }

    #[test]
    fn a_recipient_systemd_would_expand_reaches_the_run_as_it_was_given() {
        // systemd substitutes `$HOME` and `%h` inside a quoted `ExecStart=` argument, and an
        // ssh recipient's free-text comment can hold both
        let expanded = systemd_quoted("ssh-ed25519 AAAA 100% of $HOME");
        assert_eq!(expanded, "\"ssh-ed25519 AAAA 100%% of $$HOME\"");
    }

    #[test]
    fn the_crontab_line_quotes_a_recipient_the_shell_would_otherwise_choke_on() {
        let arguments =
            shell_encryption_arguments(&["ssh-ed25519 AAAA it's mine".to_string()], false);
        assert_eq!(arguments, " --recipient 'ssh-ed25519 AAAA it'\\''s mine'");

        // `sh` reads the quoted recipient back as one word
        let said = std::process::Command::new("sh")
            .args(["-c", &format!("printf '%s'{arguments}")])
            .output()
            .expect("sh runs");
        assert!(said.status.success(), "sh refused: {arguments}");
        assert_eq!(
            String::from_utf8_lossy(&said.stdout),
            "--recipientssh-ed25519 AAAA it's mine"
        );

        // cron ends the command at a bare `%`
        assert_eq!(shell_systemd_quoted("/backups/100%"), "'/backups/100\\%'");
    }

    #[test]
    fn a_path_systemd_would_read_back_differently_is_refused_rather_than_written() {
        // systemd reads this file a line at a time, so the second half would be a setting
        let smuggled = Path::new("/home/someone/backups\nRAD_BACKUP_PASSPHRASE=hunter2");
        let ok = Path::new("/home/ok");
        assert!(environment_text(smuggled, None, None, None, None).is_err());
        assert!(environment_text(ok, Some(smuggled), None, None, None).is_err());
        assert!(environment_text(ok, None, None, Some(smuggled), None).is_err());
        assert!(environment_text(ok, None, None, None, Some(smuggled)).is_err());
        // A carriage return alone ends a line for the same readers
        let returned = Path::new("/home/someone/backups\rRAD_BACKUP_KEEP=1");
        assert!(environment_text(returned, None, None, None, None).is_err());
        // A trailing backslash joins the next setting onto this value
        let joined = Path::new("/home/someone/backups\\");
        assert!(environment_text(ok, Some(joined), None, None, None).is_err());
        // systemd trims a space at either end of a value and keeps one inside it
        let trailing = Path::new("/home/someone/backups ");
        assert!(environment_text(ok, Some(trailing), None, None, None).is_err());
        let spaced = Path::new("/home/some one/.radicle/bin/rad");
        let text = environment_text(ok, None, None, None, Some(spaced))
            .expect("a space inside a path survives systemd's reading");
        assert!(
            text.lines()
                .any(|line| line == "RAD=/home/some one/.radicle/bin/rad"),
            "{text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_is_refused_rather_than_written() {
        use std::os::unix::ffi::OsStrExt;
        let garbled = Path::new(OsStr::from_bytes(b"/home/someone/\xffbackups"));
        assert!(environment_text(Path::new("/home/ok"), Some(garbled), None, None, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rad_is_found_as_an_absolute_path_wherever_the_given_path_puts_it() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = crate::key::tests::TestScratch::create("schedule-find-rad");
        let installed = scratch.path_of("installed");
        let decoy = scratch.path_of("decoy");
        for dir in [&installed, &decoy] {
            std::fs::create_dir(dir).expect("the test's scratch takes a directory");
        }
        let rad = installed.join("rad");
        std::fs::write(&rad, "#!/bin/sh\n").expect("the test's scratch takes a file");
        std::fs::set_permissions(&rad, std::fs::Permissions::from_mode(0o755))
            .expect("the test owns the file it made");
        // A shell passes over this non-executable `rad`
        std::fs::write(decoy.join("rad"), "").expect("the test's scratch takes a file");

        let elsewhere = Path::new("/nonexistent");
        let both = std::env::join_paths([&decoy, &installed]).expect("no separator in the paths");
        assert_eq!(
            find_program(OsStr::new("rad"), Some(&both), elsewhere),
            Some(rad.clone())
        );
        assert_eq!(
            find_program(OsStr::new("rad"), Some(decoy.as_os_str()), elsewhere),
            None
        );
        assert_eq!(find_program(OsStr::new("rad"), None, elsewhere), None);

        // A relative RAD is read against the directory it was given in
        let root = installed.parent().expect("the scratch dir has a parent");
        // An empty or relative PATH entry is the directory `schedule` runs in, and is skipped
        let relative = std::env::join_paths([Path::new(""), Path::new("installed")])
            .expect("no separator in the paths");
        assert_eq!(find_program(OsStr::new("rad"), Some(&relative), root), None);
        assert_eq!(
            find_program(OsStr::new("installed/rad"), Some(decoy.as_os_str()), root),
            Some(root.join("installed/rad"))
        );
    }

    #[test]
    fn the_environment_file_does_not_promise_that_an_edit_will_survive() {
        let text = environment_text(Path::new("/home/someone/.radicle"), None, None, None, None)
            .expect("an ordinary path is writable as a setting");

        // Every run rewrites this file in full, so deleting its header keeps no edit
        assert!(!text.contains("Delete both these lines"), "{text}");
        assert!(text.contains("rewritten in full"), "{text}");
        for line in text.lines().take(2) {
            assert!(line.starts_with('#'), "not a comment line: {line:?}");
        }
    }

    #[test]
    fn the_marker_says_the_unit_will_be_replaced_rather_than_promising_it_will_not() {
        // `write_unit` overwrites a file carrying the marker, so the marker must say so
        assert!(!MARKER_UNIT.contains("will not be replaced"));
        assert!(MARKER_UNIT.contains("replaced by its next run"));

        // Units written by an older version are recognised by the signature alone
        assert!(MARKER_UNIT.contains(MARKER_SIGNATURE));
        for line in MARKER_UNIT.lines() {
            // systemd reads a line as a comment only when `#` starts it
            assert!(line.starts_with('#'), "not a comment line: {line:?}");
        }
    }

    #[test]
    fn a_binary_whose_path_holds_a_space_still_produces_a_unit_systemd_can_run() {
        // systemd word-splits an unquoted ExecStart=, and the failure shows only when the
        // timer first fires
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
        // `--every` takes any OnCalendar expression, and systemd alone interprets it
        assert!(timer_unit("Mon *-*-* 03:30:00").contains("OnCalendar=Mon *-*-* 03:30:00"));
    }
}
