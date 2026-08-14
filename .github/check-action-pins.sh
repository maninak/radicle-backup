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

# `actions/*` is GitHub's own namespace, published from the same place the runner comes from.
# Everything else is a third party and gets no exemption.
while read -r file line spec; do
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
done < <(grep -Hno 'uses: [^ ]*@[^ ]*' .github/workflows/*.yml | sed 's/:uses: / /' | awk '{print $1, $2, $3}' FS='[: ]' OFS=' ')

[ "$status" -eq 0 ] && echo "every action pin is a commit SHA at least $MIN_AGE_DAYS days old"
exit "$status"
