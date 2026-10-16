#!/usr/bin/env bash
# Every action pin is a commit SHA at least MIN_AGE_DAYS old, hand-typed ones included
set -euo pipefail

MIN_AGE_DAYS=${MIN_AGE_DAYS:-7}
now=$(date -u +%s)
status=0
seen=0

while read -r file line spec; do
  # A local path runs from the current commit. It is skipped before the counter, so it cannot
  # pad `seen` past the examined-nothing guard below.
  if [[ $spec == ./* ]]; then
    continue
  fi
  seen=$((seen + 1))
  # A `uses:` with no `@` tracks the action's default branch, and has no ref to split off
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
  # Both extensions and composite actions are read. A `uses:` matches without an `@`, so an
  # unpinned action reaches the loop above and fails there.
  find .github -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 \
    | xargs -0 -r grep -Hno "uses:[[:space:]]\+[\"']\?[^ \"']*" \
    | sed "s/:uses:[[:space:]]*[\"']\?/ /" \
    | awk '{print $1, $2, $3}' FS='[: ]' OFS=' '
)

# A gate that examined nothing fails, because a glob matching no file would otherwise pass
if [ "$seen" -eq 0 ]; then
  echo "no \`uses:\` found under .github, so this check verified nothing" >&2
  exit 1
fi

[ "$status" -eq 0 ] && echo "checked $seen action pins: every one is a commit SHA at least $MIN_AGE_DAYS days old"
exit "$status"
