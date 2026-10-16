//! Deciding which repositories an archive carries and what it records about them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::db::{Policies, SeedingPolicy};
use crate::error::{Error, Result};
use crate::git::{self, Git};
use crate::home::Home;
use crate::manifest::{RepoRecord, RepoSelection};
use crate::rad::{Described, Listed, Listing, Rad};

/// The repositories a run will describe and carry, worked out before anything is written.
pub struct Inventory {
    /// Every repository the archive will describe, whether or not it carries its data.
    pub records: Vec<RepoRecord>,
    /// The ids of the repositories whose data the archive will carry.
    pub selected: BTreeSet<String>,
    pub warnings: Vec<String>,
}

impl Inventory {
    pub fn private(&self) -> impl Iterator<Item = &RepoRecord> {
        self.records.iter().filter(|record| record.is_private())
    }

    /// A repository's name for messages, or its id when its identity document gave none.
    pub fn display_name(&self, rid: &str) -> String {
        self.records
            .iter()
            .find(|record| record.rid == rid)
            .map(|record| record.display_name().to_string())
            .unwrap_or_else(|| rid.to_string())
    }

    /// The number of repositories whose identity document went unread, leaving their
    /// visibility and delegates unknown.
    ///
    /// Counts every repository when `rad` is missing.
    pub fn identities_not_read(&self) -> usize {
        self.records
            .iter()
            .filter(|record| !record.identity_was_read())
            .count()
    }

    /// The repositories this identity is the sole delegate of.
    ///
    /// Losing the key ends their governance.
    pub fn solely_delegated(&self) -> impl Iterator<Item = &RepoRecord> {
        self.records
            .iter()
            .filter(|record| record.is_delegate && record.delegates.len() == 1)
    }
}

/// Whether a run could tell which stored repositories are private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateSight {
    /// Every visibility was read, or the selection did not need it.
    Seen,
    /// A private selection with no `rad` to read visibility, over a storage that holds
    /// repositories. The selection resolves to nothing, which is never what was meant.
    Blind,
    /// A `mine` or `private` selection built on a partial view of the user's repositories,
    /// which can miss one.
    ///
    /// The causes are no `rad` for `mine`, a failed `rad` listing, or an unchecked repository.
    Guessed,
}

/// Whether the caller is choosing repositories for an archive it is about to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// `backup`, where the selection decides what the archive holds.
    Archive,
    /// `doctor` and `diff`, which write nothing, so no warning may mention an archive.
    Inspection,
}

/// Works out what is in storage, which of it is the user's, and what the selection asks for.
#[allow(clippy::too_many_arguments)]
pub fn collect(
    home: &Home,
    git: &Git,
    rad: Option<&Rad>,
    selection: RepoSelection,
    purpose: Purpose,
    node_id: &str,
    policies: &Policies,
    routing: &BTreeMap<String, u64>,
) -> Result<Inventory> {
    collect_with_sight(
        home, git, rad, selection, purpose, node_id, policies, routing,
    )
    .map(|(inventory, _)| inventory)
}

/// Runs [`collect`] and also reports whether it could see which repositories are private.
#[allow(clippy::too_many_arguments)]
pub fn collect_with_sight(
    home: &Home,
    git: &Git,
    rad: Option<&Rad>,
    selection: RepoSelection,
    purpose: Purpose,
    node_id: &str,
    policies: &Policies,
    routing: &BTreeMap<String, u64>,
) -> Result<(Inventory, PrivateSight)> {
    let mut warnings = Vec::new();
    let (stored, not_utf8_names) = home.read_inventory()?;
    for name in &not_utf8_names {
        warnings.push(format!(
            "storage/{name} was skipped. Its name is not valid UTF-8, so it cannot be a \
             repository."
        ));
    }

    let (mine, own_sight) = own_repository_ids(home, rad, node_id, &stored, &mut warnings)?;
    let stored_ids: BTreeSet<&str> = stored.iter().map(String::as_str).collect();
    let selected: BTreeSet<String> = match selection {
        RepoSelection::None => BTreeSet::new(),
        // `Private` resolves below, once the identity documents are read. `Unknown` comes from
        // a newer build and carries nothing, because guessing its meaning can put a private
        // repository in an archive nobody expected it in.
        RepoSelection::Private | RepoSelection::Unknown => BTreeSet::new(),
        RepoSelection::Mine => mine.clone(),
        RepoSelection::Seeded => policies
            .seeded()
            .map(|policy| policy.rid.clone())
            .filter(|rid| stored_ids.contains(rid.as_str()))
            .collect(),
        RepoSelection::All => stored.iter().cloned().collect(),
    };

    // Identity documents are read only for the user's repositories and the carried ones,
    // because a seed holds thousands of others and each read spawns `rad`
    let to_describe: BTreeSet<&String> = mine.iter().chain(selected.iter()).collect();
    let seeding = policies.seeding_by_rid();
    let mut records = Vec::with_capacity(to_describe.len());
    let mut undescribed = BTreeSet::new();
    let mut first_undescribed_why = None;
    let mut unreadable = BTreeSet::new();
    let mut first_unreadable = None;
    for rid in to_describe {
        let (record, trouble) = describe(home, git, rad, rid, node_id, &seeding, routing)?;
        if let Some(why) = trouble.undescribed {
            first_undescribed_why.get_or_insert(why);
            undescribed.insert(record.rid.clone());
        }
        if let Some(why) = trouble.unreadable {
            first_unreadable.get_or_insert(why);
            unreadable.insert(record.rid.clone());
        }
        records.push(record);
    }
    records.sort_by(|a, b| a.rid.cmp(&b.rid));

    // The private selection waits for the records, because only the identity document says
    // what is private
    let selected = match selection {
        RepoSelection::Private => private_selection(&records, &undescribed),
        _ => selected,
    };
    // Visibility lives in the identity document, which only `rad` reads, so without `rad` a
    // private selection resolves to nothing. The archive still holds the identity, so this
    // run exits 3 through `PrivateSight` and does not refuse.
    let unaided = purpose == Purpose::Archive && rad.is_none() && !stored.is_empty();
    // `mine` carries the user's repositories and `private` describes only them
    let partly_judged = purpose == Purpose::Archive
        && own_sight == OwnSight::Partial
        && matches!(selection, RepoSelection::Mine | RepoSelection::Private);
    let sight = match (unaided, selection) {
        (true, RepoSelection::Private) => PrivateSight::Blind,
        (true, RepoSelection::Mine) => PrivateSight::Guessed,
        _ if partly_judged => PrivateSight::Guessed,
        _ => PrivateSight::Seen,
    };
    // This warning appears only where `rad` changes what an archive holds. Without `rad`,
    // `mine` falls back to refs alone and can miss a repository.
    if rad.is_none() && purpose == Purpose::Archive {
        let missing = crate::exec::rad_missing(crate::exec::rad_override_from_env().as_deref());
        match sight {
            PrivateSight::Blind => warnings.push(format!(
                "{missing}. rad-backup cannot tell which repositories are private, so {} Install \
                 rad, or set RAD to its full path.",
                match stored.len() {
                    1 => "the one repository on this machine is not in the archive.".to_string(),
                    n => format!("none of the {n} on this machine are in the archive."),
                }
            )),
            PrivateSight::Guessed => {
                warnings.push(format!(
                    "{missing}. rad-backup may miss some of your repositories."
                ));
            }
            PrivateSight::Seen => {}
        }
    }

    // These warnings follow the selection, because what they may promise depends on it. Each
    // is one line for all repositories, because a dead `rad` fails them all at once and a
    // line each would push the manifest past `MAX_MANIFEST_BYTES`.
    if let Some(why) = first_unreadable {
        warnings.push(unreadable_warning(&unreadable, &selected, purpose, &why));
    }
    if let Some(why) = first_undescribed_why {
        warnings.push(undescribed_warning(
            &undescribed,
            &selected,
            selection,
            purpose,
            &why,
        ));
    }

    Ok((
        Inventory {
            records,
            selected,
            warnings,
        },
        sight,
    ))
}

/// The one warning that stands for every repository `rad` could not describe.
fn undescribed_warning(
    undescribed: &BTreeSet<String>,
    selected: &BTreeSet<String>,
    selection: RepoSelection,
    purpose: Purpose,
    why: &str,
) -> String {
    // A private selection carries them as though private, because a repository whose
    // visibility cannot be read must not be left out for looking public
    let fate = match (count_also_selected(undescribed, selected), selection) {
        _ if purpose == Purpose::Inspection => String::new(),
        (0, _) => left_out(undescribed.len()),
        (n, RepoSelection::Private) => format!(
            " {n} of them {} included in case {} private.",
            crate::term::is_or_are(n),
            match n {
                1 => "it is",
                _ => "they are",
            }
        ),
        (n, _) => format!(" {n} of them {} included.", crate::term::is_or_are(n)),
    };
    format!(
        "`rad` could not read the details of {}: {} ({why}).{fate}",
        crate::term::count(undescribed.len(), "repository", "repositories"),
        crate::term::shortlist(undescribed)
    )
}

/// The one warning that stands for every repository `git` could not read.
fn unreadable_warning(
    unreadable: &BTreeSet<String>,
    selected: &BTreeSet<String>,
    purpose: Purpose,
    why: &str,
) -> String {
    let fate = match count_also_selected(unreadable, selected) {
        _ if purpose == Purpose::Inspection => String::new(),
        0 => left_out(unreadable.len()),
        n => format!(" {n} of them cannot be saved, so the archive will be marked incomplete."),
    };
    format!(
        "`git` could not read {}: {} ({why}).{fate}",
        crate::term::count(unreadable.len(), "repository", "repositories"),
        crate::term::shortlist(unreadable)
    )
}

/// The sentence appended when the archive does not carry the troubled repositories.
fn left_out(troubled: usize) -> String {
    match troubled {
        1 => " It is not in this archive.".to_string(),
        _ => " They are not in this archive.".to_string(),
    }
}

/// The number of troubled repositories this run carries.
fn count_also_selected(troubled: &BTreeSet<String>, selected: &BTreeSet<String>) -> usize {
    troubled.intersection(selected).count()
}

/// The repositories a private-only archive carries, those whose identity document says
/// private plus those whose document could not be read.
///
/// A wrong answer here empties an archive, so the function stays pure and testable without
/// `rad`.
fn private_selection(records: &[RepoRecord], undescribed: &BTreeSet<String>) -> BTreeSet<String> {
    records
        .iter()
        .filter(|record| record.is_private() || undescribed.contains(&record.rid))
        .map(|record| record.rid.clone())
        .collect()
}

/// The repositories this identity has a stake in, those it created, forked or marked private,
/// and any whose storage holds refs under its namespace.
fn own_repository_ids(
    home: &Home,
    rad: Option<&Rad>,
    node_id: &str,
    stored: &[String],
    warnings: &mut Vec<String>,
) -> Result<(BTreeSet<String>, OwnSight)> {
    let mut mine = BTreeSet::new();
    let mut sight = OwnSight::Whole;

    // `collect` warns about a missing `rad`, because it knows whether the run is blind
    if let Some(rad) = rad {
        for listing in [Listing::Own, Listing::Private] {
            match rad.list(listing)? {
                Listed::Ids(ids) => mine.extend(ids),
                // A failed listing differs from an empty one, and decides whether a repository
                // is archived at all
                Listed::Unavailable { why } => {
                    sight = OwnSight::Partial;
                    warnings.push(format!(
                        "`rad {}` failed, so repositories it would have named were judged by \
                         their refs alone: {why}",
                        listing.spelling()
                    ));
                }
            }
        }
    }

    for rid in stored {
        // One unreadable `packed-refs` must not stop the backup, and the repository it hides
        // is named in a warning, never dropped in silence
        match has_namespace_at(&home.repository_path(rid), node_id) {
            Ok(true) => {
                mine.insert(rid.clone());
            }
            Ok(false) => {}
            Err(e) => {
                // A listing that already named it has decided it is the user's
                if !mine.contains(rid) {
                    sight = OwnSight::Partial;
                }
                warnings.push(format!(
                    "{rid} could not be checked for refs of this identity, so it was left out: \
                     {}",
                    e.one_line()
                ));
            }
        }
    }
    // A listing can name a repository no longer in storage, and the archive carries only what
    // is there. The set keeps this check cheap at five figures of repositories.
    let stored_ids: BTreeSet<&str> = stored.iter().map(String::as_str).collect();
    mine.retain(|rid| stored_ids.contains(rid.as_str()));
    Ok((mine, sight))
}

/// Whether [`own_repository_ids`] could judge every stored repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnSight {
    Whole,
    /// A `rad` listing failed, or a repository could not be checked and was left out.
    Partial,
}

fn describe(
    home: &Home,
    git: &Git,
    rad: Option<&Rad>,
    rid: &str,
    node_id: &str,
    seeding: &BTreeMap<&str, &SeedingPolicy>,
    routing: &BTreeMap<String, u64>,
) -> Result<(RepoRecord, Trouble)> {
    let path = home.repository_path(rid);
    // A repository `git` cannot read is recorded as trouble, because one damaged repository
    // must not stop the whole home from being archived
    let (refs, unreadable) = match git.refs(&path) {
        Ok(refs) => (refs, None),
        Err(e) => (Vec::new(), Some(e.one_line())),
    };
    let sigrefs = sigrefs_by_peer(&refs);
    let head = match unreadable {
        None => git.head_target(&path)?,
        // A repository whose refs would not list fails the HEAD query for the same reason
        Some(_) => None,
    };

    let policy = seeding.get(rid);
    let described = match rad {
        Some(rad) => Some(rad.describe_repo(rid)?),
        None => None,
    };
    // A missing `rad` is reported once by the caller. Only a `rad` that was asked and could
    // not answer earns a line naming this repository.
    let (identity, unavailable) = match described {
        Some(Described::Identity(identity)) => (Some(identity), None),
        Some(Described::Unavailable { why }) => (None, Some(why)),
        None => (None, None),
    };
    let (name, delegates, visibility, allowed) = match identity {
        Some(identity) => (
            identity.name,
            identity.delegates,
            Some(identity.visibility),
            identity.allowed,
        ),
        None => (None, Vec::new(), None, Vec::new()),
    };

    let did = format!("did:key:{node_id}");
    Ok((
        RepoRecord {
            rid: rid.to_string(),
            name,
            visibility,
            allowed,
            is_delegate: delegates.contains(&did),
            delegates,
            scope: policy.map(|policy| policy.scope.clone()),
            policy: policy.map(|policy| policy.policy.clone()),
            head,
            refs: refs.len(),
            sigrefs,
            other_seeds: routing.get(rid).copied(),
            bundle: None,
        },
        Trouble {
            undescribed: unavailable,
            unreadable,
        },
    ))
}

/// What could not be learned about one repository.
///
/// Both fields hold reasons, because the line a user acts on is the one that says why.
struct Trouble {
    /// Why `rad` could not describe it, leaving its visibility unknown.
    undescribed: Option<String>,
    /// Why `git` could not read it, leaving its record nearly empty.
    unreadable: Option<String>,
}

/// The signed refs each peer published, read from the ref list already in hand.
fn sigrefs_by_peer(refs: &[git::Ref]) -> BTreeMap<String, String> {
    const PREFIX: &str = "refs/namespaces/";
    const SUFFIX: &str = "/refs/rad/sigrefs";

    refs.iter()
        .filter_map(|reference| {
            let rest = reference.name.strip_prefix(PREFIX)?;
            let peer = rest.strip_suffix(SUFFIX)?;
            Some((peer.to_string(), reference.oid.clone()))
        })
        .collect()
}

/// Whether a repository directory holds loose or packed refs under `node_id`'s namespace,
/// read without spawning git.
///
/// Fails when `packed-refs` exists and cannot be read, so a repository whose refs are all
/// packed never reads as someone else's.
pub fn has_namespace_at(repo: &Path, node_id: &str) -> Result<bool> {
    let loose = repo.join("refs").join("namespaces").join(node_id);
    if loose.is_dir() {
        return Ok(true);
    }
    let packed = repo.join("packed-refs");
    match std::fs::read_to_string(&packed) {
        Ok(text) => Ok(text.contains(&format!("refs/namespaces/{node_id}/"))),
        // No packed-refs means every ref is loose, and the check above already looked
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io(&packed, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_refs_are_indexed_by_the_peer_that_signed_them() {
        let refs = vec![
            git::Ref {
                name: "refs/heads/master".to_string(),
                oid: "aaa".to_string(),
            },
            git::Ref {
                name: "refs/namespaces/z6MkAAA/refs/rad/sigrefs".to_string(),
                oid: "bbb".to_string(),
            },
            git::Ref {
                name: "refs/namespaces/z6MkBBB/refs/rad/sigrefs".to_string(),
                oid: "ccc".to_string(),
            },
            git::Ref {
                name: "refs/namespaces/z6MkAAA/refs/heads/master".to_string(),
                oid: "ddd".to_string(),
            },
        ];
        let sigrefs = sigrefs_by_peer(&refs);
        assert_eq!(sigrefs.len(), 2);
        assert_eq!(sigrefs.get("z6MkAAA"), Some(&"bbb".to_string()));
        assert_eq!(sigrefs.get("z6MkBBB"), Some(&"ccc".to_string()));
    }

    fn record(rid: &str, visibility: Option<&str>) -> RepoRecord {
        RepoRecord {
            rid: rid.to_string(),
            name: None,
            visibility: visibility.map(str::to_string),
            allowed: Vec::new(),
            is_delegate: false,
            delegates: Vec::new(),
            scope: None,
            policy: None,
            head: None,
            refs: 0,
            sigrefs: BTreeMap::new(),
            other_seeds: None,
            bundle: None,
        }
    }

    #[test]
    fn one_warning_stands_for_every_repository_git_could_not_read() {
        let many: BTreeSet<String> = (0..9).map(|n| format!("rad:z{n:02}")).collect();
        let warning = unreadable_warning(
            &many,
            &many,
            Purpose::Archive,
            "fatal: not a git repository",
        );

        // A vanished storage directory fails every repository at once, and one line each
        // would push the manifest past `MAX_MANIFEST_BYTES`
        assert_eq!(warning.lines().count(), 1);
        assert!(warning.contains("9 repositories"), "{warning}");
        assert!(warning.contains("and 4 more"), "{warning}");
        // The warning says what happens next, so the user knows whether the archive is whole
        assert!(warning.contains("incomplete"), "{warning}");
    }

    #[test]
    fn one_warning_stands_for_every_repository_rad_could_not_describe() {
        let many: BTreeSet<String> = (0..12).map(|n| format!("rad:z{n:02}")).collect();
        let warning = undescribed_warning(
            &many,
            &many,
            RepoSelection::Private,
            Purpose::Archive,
            "rad exited 1",
        );

        // A dead `rad` fails every repository at once, and one line each would push the
        // manifest past `MAX_MANIFEST_BYTES`
        assert_eq!(warning.lines().count(), 1);
        assert!(warning.contains("12 repositories"), "{warning}");
        assert!(warning.contains("and 7 more"), "{warning}");
        assert!(warning.contains("rad exited 1"), "{warning}");
    }

    #[test]
    fn a_handful_of_undescribable_repositories_are_all_named() {
        let few = BTreeSet::from(["rad:zA".to_string(), "rad:zB".to_string()]);
        let warning = undescribed_warning(
            &few,
            &few,
            RepoSelection::Private,
            Purpose::Archive,
            "rad exited 1",
        );
        assert!(warning.contains("rad:zA, rad:zB"), "{warning}");
        assert!(!warning.contains("more"), "{warning}");
    }

    #[test]
    fn a_troubled_repository_this_run_does_not_carry_is_not_promised_a_place_in_the_archive() {
        let troubled = BTreeSet::from(["rad:zA".to_string()]);
        let nothing = BTreeSet::new();
        const GIT_SAID: &str = "fatal: not a git repository";

        // `--repos seeded` carries only what is seeded, so the warning may not promise the
        // repository a place, nor mark the archive incomplete over it
        let undescribed = undescribed_warning(
            &troubled,
            &nothing,
            RepoSelection::Seeded,
            Purpose::Archive,
            "x",
        );
        assert!(undescribed.contains("not in this archive"), "{undescribed}");
        assert!(!undescribed.contains("included"), "{undescribed}");
        let unreadable = unreadable_warning(&troubled, &nothing, Purpose::Archive, GIT_SAID);
        assert!(unreadable.contains("not in this archive"), "{unreadable}");
        assert!(!unreadable.contains("incomplete"), "{unreadable}");

        // `doctor` and `diff` write no archive, so neither warning may mention one, even over
        // a repository their selection would carry
        for said in [
            undescribed_warning(
                &troubled,
                &troubled,
                RepoSelection::Private,
                Purpose::Inspection,
                "x",
            ),
            unreadable_warning(&troubled, &troubled, Purpose::Inspection, GIT_SAID),
        ] {
            assert!(!said.contains("archive"), "{said}");
        }
    }

    #[test]
    fn a_repository_rad_could_not_describe_is_carried_rather_than_taken_for_public() {
        let records = vec![
            record("rad:zPrivate", Some("private")),
            record("rad:zPublic", Some("public")),
            record("rad:zUnknown", None),
        ];
        let undescribed = BTreeSet::from(["rad:zUnknown".to_string()]);

        let selected = private_selection(&records, &undescribed);

        // The repository `rad` could not describe is carried, because one with no visibility
        // reads as public and a private-only archive would then come back empty
        assert!(selected.contains("rad:zUnknown"));
        assert!(selected.contains("rad:zPrivate"));
        assert!(!selected.contains("rad:zPublic"));
    }

    #[test]
    fn nothing_is_carried_when_every_repository_is_public_and_all_of_them_were_described() {
        let records = vec![record("rad:zA", Some("public")), record("rad:zB", None)];
        // `rad` was never asked about B, which differs from being asked and failing
        assert!(private_selection(&records, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn a_namespace_is_found_whether_its_refs_are_loose_or_packed() {
        let dir = std::env::temp_dir().join(format!("rad-backup-namespace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("refs/namespaces/z6MkLoose"))
            .expect("loose ref directory is creatable");
        let held = |id| has_namespace_at(&dir, id).expect("the repository is readable");
        assert!(held("z6MkLoose"));
        assert!(!held("z6MkPacked"));

        std::fs::write(
            dir.join("packed-refs"),
            "# pack-refs with: peeled fully-peeled sorted\n\
             aaa refs/namespaces/z6MkPacked/refs/rad/sigrefs\n",
        )
        .expect("packed-refs is writable");
        assert!(held("z6MkPacked"));
        assert!(!held("z6MkAbsent"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_repository_whose_refs_cannot_be_read_is_not_reported_as_somebody_elses() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir =
            std::env::temp_dir().join(format!("rad-backup-unreadable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch repository is creatable");
        let packed = dir.join("packed-refs");
        std::fs::write(&packed, "aaa refs/namespaces/z6MkMine/refs/rad/sigrefs\n")
            .expect("packed-refs is writable");
        std::fs::set_permissions(&packed, std::fs::Permissions::from_mode(0o000))
            .expect("mode is settable");

        let answer = has_namespace_at(&dir, "z6MkMine");
        std::fs::set_permissions(&packed, std::fs::Permissions::from_mode(0o600))
            .expect("mode is settable back");

        // Root reads the file whatever its mode, and then the test checks the answer it found
        if let Ok(found) = answer {
            assert!(found, "root read it, so it is ours");
        } else {
            assert!(
                answer.is_err_and(|e| e.one_line().contains("packed-refs")),
                "an unreadable file has to name itself"
            );
        }

        let _ = std::fs::remove_dir_all(dir);
    }
}
