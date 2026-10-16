//! Stopping the node for the length of a backup and starting it again.

use std::time::{Duration, Instant};

use crate::cli::Create;
use crate::cmd::Ctx;
use crate::error::{Error, Result};
use crate::rad::Rad;

// How long to wait, and how often to poll, for a stopping node to release its control socket
const NODE_STOP_TIMEOUT: Duration = Duration::from_secs(20);
const NODE_STOP_POLL: Duration = Duration::from_millis(200);

/// A node this run may have stopped, started again on drop.
///
/// `Drop` restarts the node on every `?` between the stop and the finish, and on a panic. A
/// signal kills the process without it, so Ctrl-C during `--stop-node` leaves the node down.
/// The scheduled unit never passes `--stop-node`. Revisit if a machine ever turns it on.
pub(super) struct NodeGuard<'a> {
    ctx: &'a Ctx,
    rad: Option<&'a Rad>,
    pub(super) was_running: bool,
    /// The control socket's error, when the probe got one.
    ///
    /// `was_running` is then a precaution, and the manifest carries this so a restore can say
    /// the node may have been running.
    pub(super) why_running_is_unknown: Option<String>,
    pub(super) was_stopped_by_backup: bool,
}

impl NodeGuard<'_> {
    /// Starts the node now, for paths that report the restart in order.
    ///
    /// Idempotent, because it clears the flag and `Drop` then does nothing.
    pub(super) fn restart(&mut self) {
        if !self.was_stopped_by_backup {
            return;
        }
        self.was_stopped_by_backup = false;
        // The step prints only once `rad` is found, so no warning contradicts it a line later
        let Some(rad) = self.rad else {
            self.ctx.term.warn(&format!(
                "{}, so the node this run stopped is still stopped",
                crate::exec::rad_missing(crate::exec::rad_override_from_env().as_deref())
            ));
            return;
        };
        self.ctx.term.step("starting the node again");
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

/// Whether this run owes the node a restart after a stop it never saw complete.
///
/// A restart is owed only when the stop was accepted and the probe could not see the socket,
/// since the stop may then have worked. A needless start costs a line of output, and a missed
/// one leaves the node down.
fn owes_a_restart(stop_accepted: bool, why_running_is_unknown: Option<&str>) -> bool {
    stop_accepted && why_running_is_unknown.is_some()
}

/// What a running node can cost a backup, printed when `--stop-node` is absent.
const MAY_LAG: &str = "a repository that syncs during the backup may be saved slightly behind. \
                       Use --stop-node for an exact copy.";

/// Stops the node when `--stop-node` asks, and otherwise prints what a running node costs.
///
/// A running node puts only git storage at risk, because the databases are snapshotted and
/// restore compares repositories with the network. So a running node is a step, not a warning.
pub(super) fn quiesce<'a>(
    ctx: &'a Ctx,
    args: &Create,
    rad: Option<&'a Rad>,
) -> Result<NodeGuard<'a>> {
    // A doubt is printed and then treated as running, so `--stop-node` still tries and the
    // manifest records the doubt. Read as stopped, a restore would skip its double-signing
    // warning.
    let state = ctx.home.probe_node_state();
    let why_running_is_unknown = state.doubt();
    if let Some(doubt) = &why_running_is_unknown {
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
        // After a doubt, "the node is running" would contradict the line just printed
        match why_running_is_unknown {
            Some(_) => ctx.term.detail(&format!("if it is, {MAY_LAG}")),
            None => ctx.term.step(&format!("the node is running, so {MAY_LAG}")),
        }
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
            format!(
                "--stop-node was passed, but {}",
                crate::exec::rad_missing(crate::exec::rad_override_from_env().as_deref())
            ),
            "install rad, or stop the node yourself and run again",
        )
    })?;
    ctx.term.step("stopping the node");
    // The exit status matters, because a failed stop would otherwise cost the whole timeout
    // watching a socket that never closes
    let stop_accepted = rad.stop_node()?;

    // The guard exists from the moment the stop is asked, because `rad node stop` can succeed
    // while the socket outlives the deadline
    let mut node = NodeGuard {
        ctx,
        rad: Some(rad),
        was_running: true,
        why_running_is_unknown: why_running_is_unknown.clone(),
        was_stopped_by_backup: true,
    };

    // A failed stop is checked once, because nothing is in flight. An accepted stop gets the
    // full deadline, because the node closes its socket only once it finishes serving.
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
    node.was_stopped_by_backup = owes_a_restart(stop_accepted, why_running_is_unknown.as_deref());
    // Under a doubt, every poll above failed the way the probe did, so the message points
    // the user at a permission and not at a running node
    let still_up = match &why_running_is_unknown {
        Some(doubt) => format!("the node could not be asked whether it stopped ({doubt})"),
        None => "the node is still serving its control socket".to_string(),
    };
    Err(if stop_accepted {
        Error::refused(
            format!("{still_up} after being asked to stop"),
            match why_running_is_unknown.is_some() {
                // The stop may have worked unseen, so the node starts again on the way out and
                // the advice targets the real fault
                true => {
                    "check who owns the node directory and its control socket, then run \
                         again; the node is being started again in case the stop did work"
                }
                false => "stop it by hand and run again, or run without --stop-node",
            },
        )
    } else {
        Error::refused(
            format!("`rad node stop` failed, and {still_up}"),
            "read what it said above, stop it by hand, or run without --stop-node",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::owes_a_restart;

    #[test]
    fn a_stop_this_run_could_not_confirm_still_owes_the_node_a_restart() {
        const DOUBT: &str = "permission denied on the control socket";

        assert!(owes_a_restart(true, Some(DOUBT)));
        assert!(
            !owes_a_restart(false, Some(DOUBT)),
            "a stop that failed outright stopped nothing"
        );
        assert!(
            !owes_a_restart(true, None),
            "the socket kept answering, so nothing went down"
        );
        assert!(!owes_a_restart(false, None));
    }
}
