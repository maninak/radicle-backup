//! Stopping the node for the length of a backup, and putting it back.
//!
//! Separate from the archiving itself because it is the one part of a backup that changes the
//! machine: everything else reads. A guard type keeps the restart on the unwinding path, which
//! is where it has to be when `run` can fail anywhere between the stop and the finish.

use std::time::{Duration, Instant};

use crate::cli::Create;
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::rad::Rad;

/// How long to wait for a node to let go of its control socket after being asked to stop.
const NODE_STOP_TIMEOUT: Duration = Duration::from_secs(20);
const NODE_STOP_POLL: Duration = Duration::from_millis(200);

/// A node this run may have stopped, and the promise to put it back.
///
/// The promise is kept on a return and on a panic, and on neither when a signal kills the
/// process: Ctrl-C during a long `--stop-node` backup leaves the node down with nothing said.
/// The scheduled unit this tool writes never passes `--stop-node`, so a killed timer run
/// cannot strand a seed, and the person who pressed Ctrl-C is by definition at the keyboard.
/// Revisit if `--stop-node` ever becomes something a machine turns on by itself.
///
/// A guard rather than a pair of booleans and a call at the end, because every `?` in `run`
/// between the stop and the restart (a repository that changes size mid-read, a full disk)
/// used to unwind past the restart and leave a seed offline until somebody noticed. `Drop`
/// runs on all of them.
pub(super) struct NodeGuard<'a> {
    ctx: &'a Ctx,
    rad: Option<&'a Rad>,
    pub(super) was_running: bool,
    /// The error the control socket gave, when it gave one. `was_running` above is then a
    /// precaution rather than a reading, and the manifest carries this so the far end can say
    /// "may have had a node running" instead of asserting it.
    pub(super) why_running_is_unknown: Option<String>,
    pub(super) was_stopped_by_backup: bool,
}

impl NodeGuard<'_> {
    /// Put the node back now rather than at the end of the scope, for the paths that want to
    /// report it in order. Idempotent: the flag is cleared, so `Drop` then does nothing.
    pub(super) fn restart(&mut self) {
        if !self.was_stopped_by_backup {
            return;
        }
        self.was_stopped_by_backup = false;
        self.ctx.term.step("starting the node again");
        let Some(rad) = self.rad else {
            self.ctx
                .term
                .warn("rad is no longer on PATH, so the node this run stopped is still stopped");
            return;
        };
        if !matches!(rad.start_node(), Ok(true)) {
            self.ctx
                .term
                .warn("`rad node start` failed, so the node this run stopped is still stopped");
            self.ctx.term.detail("start it with `rad node start`");
        }
    }
}

impl Drop for NodeGuard<'_> {
    fn drop(&mut self) {
        self.restart();
    }
}

/// Stop the node when `--stop-node` asks for it, and warn when it is running and nothing asked.
///
/// Only git storage is at risk from a running node: the databases are snapshotted through
/// SQLite's own backup API, and keys and config do not change. So a running node is a warning
/// with a reason attached, not a refusal.
pub(super) fn quiesce<'a>(
    ctx: &'a Ctx,
    args: &Create,
    rad: Option<&'a Rad>,
    warnings: &mut Vec<String>,
) -> Result<NodeGuard<'a>> {
    // A doubt is said out loud and then treated as "running", which is the cautious half:
    // the warning about refs fetched mid-run is printed, and `--stop-node` still tries. Read
    // as stopped, this wrote `node.was_running: false` into the manifest over a home whose
    // node was up, and the restore on the far end skipped the warning that costs an identity.
    let state = ctx.home.probe_node_state();
    let why_running_is_unknown = state.doubt();
    if let Some(doubt) = &why_running_is_unknown {
        warnings.push(format!(
            "whether the node is running could not be established ({doubt}), so this archive \
             was taken as though it were"
        ));
        ctx.term
            .warn(&format!("cannot tell whether the node is running: {doubt}"));
    }
    let was_running = !state.is_stopped();
    if !was_running {
        return Ok(NodeGuard {
            ctx,
            rad,
            was_running: false,
            why_running_is_unknown,
            was_stopped_by_backup: false,
        });
    }
    if !args.stop_node {
        warnings.push(
            "the node was running: databases were snapshotted consistently, but a repository \
             fetched during the run may be missing its newest refs"
                .to_string(),
        );
        ctx.term
            .warn("the node is running; pass --stop-node for a guaranteed-clean copy");
        return Ok(NodeGuard {
            ctx,
            rad,
            was_running: true,
            why_running_is_unknown,
            was_stopped_by_backup: false,
        });
    }

    let rad = rad.ok_or_else(|| {
        Error::refused(
            "--stop-node was passed but rad is not on PATH",
            "install rad, or stop the node yourself and run again",
        )
    })?;
    ctx.term.step("stopping the node");
    // The exit status, not just the spawn. A `rad node stop` that fails outright used to be
    // discarded here, and the run then spent the whole timeout watching a socket that was
    // never going to close before blaming the node for not stopping.
    let stop_accepted = rad.stop_node()?;

    // The guard exists from the moment the stop is asked for, not from the moment it is
    // confirmed. `rad node stop` can succeed and the socket still be up when the deadline
    // passes, and that path returned an error with nothing recorded as owing a restart.
    let mut node = NodeGuard {
        ctx,
        rad: Some(rad),
        was_running: true,
        why_running_is_unknown: why_running_is_unknown.clone(),
        was_stopped_by_backup: true,
    };

    // A stop that failed outright is asked about once and no more: there is nothing in
    // flight to wait for, and the whole timeout spent on it only delays the refusal. A stop
    // that was accepted gets the full deadline, because the node closes its socket when it is
    // done serving and that is not instant.
    let deadline = Instant::now()
        + if stop_accepted {
            NODE_STOP_TIMEOUT
        } else {
            Duration::ZERO
        };
    loop {
        if ctx.home.probe_node_state().is_stopped() {
            return Ok(node);
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(NODE_STOP_POLL);
    }
    // It never went down, so there is nothing this run stopped and nothing to put back.
    node.was_stopped_by_backup = false;
    // Both of these say the socket is still being served, and neither knows that when the
    // socket is the thing that could not be reached: the same EACCES that made the state a
    // doubt made every poll above a doubt too. Saying so is the difference between sending
    // the user to stop a node and sending them to look at a permission.
    let still_up = match &why_running_is_unknown {
        Some(doubt) => format!("the node could not be asked whether it stopped ({doubt})"),
        None => "the node is still serving its control socket".to_string(),
    };
    Err(if stop_accepted {
        Error::refused(
            format!("{still_up} after being asked to stop"),
            "stop it by hand and run again, or run without --stop-node",
        )
    } else {
        Error::refused(
            format!("`rad node stop` failed, and {still_up}"),
            "read what it said above, stop it by hand, or run without --stop-node",
        )
    })
}
