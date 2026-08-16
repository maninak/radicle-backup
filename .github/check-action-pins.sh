#!/usr/bin/env bash
# Every third-party action must be pinned to a commit SHA that is at least MIN_AGE_DAYS old.
#
# Dependabot's cooldown covers the updates it raises, but not a pin typed by hand, which is
# exactly when somebody is in a hurry. This reads the workflows rather than the config, so it
# fails on whatever is actually there.
set -euo pipefail

MIN_AGE_DAYS=${MIN_AGE_DAYS:-7}
now=$(date -u +%s)
status=0
seen=0

# `actions/*` is GitHub's own namespace, published from the same place the runner comes from.
# Everything else is a third party and gets no exemption.
while read -r file line spec; do
  # A local path is not a pin problem: `./.github/workflows/x.yml` is read from the very commit
  # that is running, which is a tighter guarantee than any SHA could give. Skipped before the
  # counter so it cannot pad `seen` and prop up the examined-nothing guard below.
  if [[ $spec == ./* ]]; then
    continue
  fi
  seen=$((seen + 1))
  # A `uses:` with no `@` at all resolves the action's default branch at run time, which is the
  # worst pin there is. Matched separately from the pattern below, because a value with no `@`
  # cannot be split into repo and ref.
  if [[ $spec != *@* ]]; then
    echo "$file:$line  $spec names no ref at all, so it tracks a branch" >&2
    status=1
    continue
  fi
  repo="${spec%@*}"
  ref="${spec##*@}"
  if [[ ! $ref =~ ^[0-9a-f]{40}$ ]]; then
    echo "$file:$line  $spec is not pinned to a commit SHA" >&2
    status=1
    continue
  fi
  if ! date=$(gh api "repos/$repo/commits/$ref" --jq '.commit.committer.date' 2>/dev/null); then
    echo "$file:$line  $repo has no commit $ref" >&2
    status=1
    continue
  fi
  age=$(( (now - $(date -u -d "$date" +%s)) / 86400 ))
  if [ "$age" -lt "$MIN_AGE_DAYS" ]; then
    echo "$file:$line  $repo is pinned to a ${age}-day-old commit, minimum is $MIN_AGE_DAYS" >&2
    status=1
  fi
done < <(
  # Both spellings of the extension, and composite actions too, because a workflow this
  # misses is a workflow that goes unchecked. `uses:` is matched with one-or-more spaces
  # and an optional quote, and WITHOUT requiring an `@`, so a completely unpinned action
  # reaches the loop above instead of failing to match and vanishing.
  find .github -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 \
    | xargs -0 -r grep -Hno "uses:[[:space:]]\+[\"']\?[^ \"']*" \
    | sed "s/:uses:[[:space:]]*[\"']\?/ /" \
    | awk '{print $1, $2, $3}' FS='[: ]' OFS=' '
)

# A gate that examined nothing must not report success. Without this the script printed its
# green line and exited 0 when the glob matched no file at all, which is what it did for every
# workflow named `.yaml` and for any move of the directory.
if [ "$seen" -eq 0 ]; then
  echo "no \`uses:\` found under .github, so this check verified nothing" >&2
  exit 1
fi

[ "$status" -eq 0 ] && echo "checked $seen action pins: every one is a commit SHA at least $MIN_AGE_DAYS days old"
exit "$status"
