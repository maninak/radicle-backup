//! Stopping the node for the length of a backup, and putting it back.
//!
//! Separate from the archiving itself because it is the one part of a backup that changes the
//! machine: everything else reads. A guard type keeps the restart on the unwinding path, which
//! is where it has to be when `run` has a dozen ways to fail between the stop and the finish.

use std::time::{Duration, Instant};

use crate::cli::Create;
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::home::NodeState;
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
/// A guard rather than a pair of booleans and a call at the end, because `run` has about
/// fifteen `?` sites between the stop and the restart: a passphrase that cannot be read, a
/// repository that changes size mid-read, a full disk. Every one of them used to unwind past
/// the restart and leave a seed offline until somebody noticed. `Drop` runs on all of them.
pub(super) struct NodeGuard<'a> {
    ctx: &'a Ctx,
    rad: Option<&'a Rad>,
    pub(super) was_running: bool,
    pub(super) stopped_by_backup: bool,
}

impl NodeGuard<'_> {
    /// Put the node back now rather than at the end of the scope, for the paths that want to
    /// report it in order. Idempotent: the flag is cleared, so `Drop` then does nothing.
    pub(super) fn restart(&mut self) {
        if !self.stopped_by_backup {
            return;
        }
        self.stopped_by_backup = false;
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

/// Stop the node if asked, and say so plainly if it is running and we were not.
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
    let was_running = ctx.home.node_state() == NodeState::Running;
    if !was_running {
        return Ok(NodeGuard {
            ctx,
            rad,
            was_running: false,
            stopped_by_backup: false,
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
            stopped_by_backup: false,
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
    let stopped = rad.stop_node()?;

    // The guard exists from the moment the stop is asked for, not from the moment it is
    // confirmed. `rad node stop` can succeed and the socket still be up when the deadline
    // passes, and that path returned an error with nothing recorded as owing a restart.
    let mut node = NodeGuard {
        ctx,
        rad: Some(rad),
        was_running: true,
        stopped_by_backup: true,
    };

    // A stop that failed outright is asked about once and no more: there is nothing in
    // flight to wait for, and spending the whole timeout on it only delays the refusal by
    // twenty seconds. A stop that was accepted gets the full deadline, because the node closes
    // its socket when it is done serving and that is not instant.
    let deadline = Instant::now()
        + if stopped {
            NODE_STOP_TIMEOUT
        } else {
            Duration::ZERO
        };
    loop {
        if ctx.home.node_state() == NodeState::Stopped {
            return Ok(node);
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(NODE_STOP_POLL);
    }
    // It never went down, so there is nothing this run stopped and nothing to put back.
    node.stopped_by_backup = false;
    Err(if stopped {
        Error::refused(
            "the node is still serving its control socket after being asked to stop",
            "stop it by hand and run again, or run without --stop-node",
        )
    } else {
        Error::refused(
            "`rad node stop` failed, and the node is still serving its control socket",
            "read what it said above, stop it by hand, or run without --stop-node",
        )
    })
}
