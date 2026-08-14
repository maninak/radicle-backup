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
const MARKER: &str = "# Written by `rad backup schedule`. Edit freely; it will not be replaced.";

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
        return without_systemd(ctx, args);
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
    let passphrase_file = ctx.global.passphrase_file.clone();
    if passphrase_file.is_none() && std::env::var_os(crate::crypt::PASSPHRASE_ENV).is_none() {
        return Err(Error::refused(
            "a scheduled run has nobody to ask for the archive passphrase",
            "put it in a file only you can read and pass --passphrase-file <path>, or export \
             RAD_BACKUP_PASSPHRASE where the timer can see it",
        ));
    }

    let dir = unit_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let environment = environment_file()?;
    write_environment(ctx, &environment, args, passphrase_file.as_deref())?;
    write_unit(ctx, &dir.join(SERVICE), &service_unit(&environment))?;
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

fn status(ctx: &Ctx, systemctl: &Tool) -> Result<()> {
    let enabled = systemctl
        .raw_output(&["--user", "is-enabled", TIMER])?
        .map(|out| out.trim().to_string())
        .unwrap_or_else(|| "disabled".to_string());
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
            "next": next,
            "lastFailure": last,
        }));
    }
    if enabled == "enabled" {
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

/// What to do on a machine with no systemd. Nothing is installed, and the line that would do
/// the same job is printed rather than described, so it can be pasted.
fn without_systemd(ctx: &Ctx, args: &Schedule) -> Result<()> {
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
    ctx.term.print(&format!(
        "  0 3 * * *  {binary} --output {} --keep {keep} --yes --quiet",
        output.display()
    ));
    ctx.term.blank();
    ctx.term.hint(
        "the run needs RAD_BACKUP_PASSPHRASE_FILE set in that crontab, or it will stop \
               to ask for a passphrase nobody is there to type",
    );
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

/// The environment a scheduled run reads. Written owner-only, because the path to a
/// passphrase file is a map to the passphrase.
fn write_environment(
    ctx: &Ctx,
    path: &Path,
    args: &Schedule,
    passphrase_file: Option<&Path>,
) -> Result<()> {
    let mut lines = vec![
        MARKER.to_string(),
        format!("RAD_HOME={}", ctx.home.path().display()),
    ];
    if let Some(output) = &args.output {
        lines.push(format!("RAD_BACKUP_DIR={}", output.display()));
    }
    if let Some(keep) = args.keep {
        lines.push(format!("RAD_BACKUP_KEEP={keep}"));
    }
    if let Some(file) = passphrase_file {
        lines.push(format!("RAD_BACKUP_PASSPHRASE_FILE={}", file.display()));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let text = format!("{}\n", lines.join("\n"));
    crate::cmd::write_owner_only(path, text.as_bytes())?;
    ctx.term.step(&format!("wrote {}", path.display()));
    Ok(())
}

fn write_unit(ctx: &Ctx, path: &Path, contents: &str) -> Result<()> {
    if std::fs::read_to_string(path).is_ok_and(|existing| !existing.contains(MARKER)) {
        return Err(Error::refused(
            format!("{} was not written by this tool", path.display()),
            "edit it yourself, or move it aside and run this again",
        ));
    }
    std::fs::write(path, contents).map_err(|e| Error::io(path, e))?;
    ctx.term.step(&format!("wrote {}", path.display()));
    Ok(())
}

fn service_unit(environment: &Path) -> String {
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
ExecStart={binary} --yes --quiet
Nice=10
IOSchedulingClass=idle
",
        environment.display()
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
        assert!(service_unit(Path::new("/tmp/env")).contains(MARKER));
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
