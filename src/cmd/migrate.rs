//! Moving an identity to another machine.
//!
//! This is the common case, and it is the one with the footgun: two nodes running one key sign
//! conflicting histories for the same peer, and the network sees a fork that nothing resolves.
//! So the source key is retired as part of the move, not left behind as a courtesy copy.

use std::path::{Path, PathBuf};

use crate::cli::{Create, Migrate, TierArg, Verify};
use crate::cmd::{Ctx, backup, verify};
use crate::error::{Error, Result};
use crate::home::NodeState;

/// What the retired key is renamed to. It stays on disk rather than being deleted, because a
/// move that goes wrong halfway needs a way back.
const RETIRED_KEY: &str = "radicle.retired";
const RETIRED_NOTE: &str = "RETIRED.txt";

pub fn run(ctx: &Ctx, args: &Migrate) -> Result<()> {
    ctx.home.require()?;

    if ctx.home.node_state() == NodeState::Running {
        return Err(Error::refused(
            "the node is running",
            "run `rad node stop` first: a move that leaves it running is how two nodes end up \
             sharing one key",
        ));
    }

    let create = Create {
        output: Some(args.output.clone()),
        tier: TierArg::Full,
        repos: None,
        stdout: false,
        plaintext: false,
        recipient: Vec::new(),
        stop_node: false,
        with_node_db: true,
        keep: None,
        scratch_dir: None,
    };
    let archive = backup::run(ctx, &create)?.ok_or_else(|| {
        Error::refused(
            "a move needs an archive on disk",
            "give a path to write it to",
        )
    })?;

    ctx.term.blank();
    ctx.term
        .step("checking the archive before retiring anything");
    let report = verify::check(
        ctx,
        &Verify {
            target: crate::cli::Target {
                archive: archive.clone(),
            },
            deep: true,
        },
    )?;
    if !report.passed() {
        for problem in &report.problems {
            ctx.term.fail(problem);
        }
        return Err(Error::refused(
            "the archive did not verify, so this machine's key was left alone",
            "fix the problems above and run the move again",
        ));
    }
    ctx.term.ok("the archive restores this identity");

    if args.keep_source {
        ctx.term
            .warn("--keep-source: this machine keeps its key, and you now have two copies");
        ctx.term
            .hint("start only one of them, ever, or your peer id will fork");
    } else {
        retire(ctx, &archive)?;
    }

    ctx.term.blank();
    ctx.term.headline("on the other machine");
    ctx.term.hint(&format!(
        "copy {} across, then run:",
        archive.file_name().unwrap_or_default().to_string_lossy()
    ));
    ctx.term.hint("    rad-backup restore <archive>");
    ctx.term
        .hint("it will put the identity, the policies and the repositories back, then check");
    ctx.term
        .hint("each repository against the network before you write to it");
    Ok(())
}

/// Rename the key so this node cannot start with it, and leave a note saying why.
fn retire(ctx: &Ctx, archive: &Path) -> Result<()> {
    let question = format!(
        "Retire the key on this machine? {} keeps the only usable copy.",
        archive.display()
    );
    if !ctx.term.confirm(&question)? {
        return Err(Error::refused(
            "nothing was retired, so this machine still holds the identity",
            "pass --keep-source if that is what you meant, and never start both nodes",
        ));
    }

    let from = ctx.home.secret_key();
    let to = retired_path(&ctx.home.keys_dir());
    std::fs::rename(&from, &to).map_err(|e| Error::io(&to, e))?;

    let note = format!(
        "This identity was moved to another machine on {}.\n\
         \n\
         The key that used to be at keys/radicle is now beside this note as {RETIRED_KEY}.\n\
         It still works, which is exactly the problem: if you put it back and start a node\n\
         here while the other machine is also running one, both will sign refs under the same\n\
         peer id and the network will see your identity fork.\n\
         \n\
         Put it back only if the move failed and the other machine never started its node.\n\
         \n\
         The archive it was moved with: {}\n",
        crate::cmd::iso_stamp(jiff::Timestamp::now()),
        archive.display()
    );
    let note_path = ctx.home.keys_dir().join(RETIRED_NOTE);
    std::fs::write(&note_path, note).map_err(|e| Error::io(&note_path, e))?;

    ctx.term
        .ok(&format!("retired this machine's key to {}", to.display()));
    Ok(())
}

/// Where a retired key goes. Kept as a function so the note and the rename cannot disagree.
fn retired_path(keys_dir: &Path) -> PathBuf {
    keys_dir.join(RETIRED_KEY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_retired_key_sits_beside_the_one_it_replaced() {
        let path = retired_path(Path::new("/home/me/.radicle/keys"));
        assert_eq!(
            path,
            PathBuf::from("/home/me/.radicle/keys/radicle.retired")
        );
        assert_ne!(path.file_name(), Some(std::ffi::OsStr::new("radicle")));
    }
}
