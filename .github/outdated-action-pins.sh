#!/usr/bin/env bash
# Every action pin behind what its trailing comment tracks: `# v...` a release, else a branch
set -euo pipefail

MIN_AGE_DAYS=${MIN_AGE_DAYS:-7}
now=$(date -u +%s)
seen=0
behind=0
unchecked=0

while read -r repo sha tracked; do
  seen=$((seen + 1))
  if [[ $tracked == v* ]]; then
    if ! ref=$(gh api "repos/$repo/releases/latest" --jq .tag_name 2>&1); then
      unchecked=$((unchecked + 1))
      case "$ref" in
      *"HTTP 404"*) echo "$repo has no GitHub release to compare against" >&2 ;;
      *) echo "$repo could not be checked: $ref" >&2 ;;
      esac
      continue
    fi
  else
    ref=$tracked
  fi
  if ! answer=$(gh api "repos/$repo/commits/$ref" --jq '.sha + " " + .commit.committer.date' 2>&1); then
    unchecked=$((unchecked + 1))
    echo "$repo could not be checked: $answer" >&2
    continue
  fi
  read -r latest date <<< "$answer"
  if [ "$latest" != "$sha" ]; then
    behind=$((behind + 1))
    age=$(( (now - $(date -u -d "$date" +%s)) / 86400 ))
    if [ "$age" -lt "$MIN_AGE_DAYS" ]; then
      echo "$repo is pinned to $sha # $tracked, and $ref is $latest, ${age} days old so not yet adoptable"
    else
      echo "$repo is pinned to $sha # $tracked, and $ref is $latest (${age} days old)"
    fi
  fi
done < <(
  find .github -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 \
    | xargs -0 -r grep -ho "uses:[[:space:]]\+[\"']\?[^ ./\"'][^ \"']*@[0-9a-f]\{40\}[\"']\?[[:space:]]\+#[[:space:]]\+[^ ]*" \
    | sed -E "s/^uses:[[:space:]]+[\"']?([^/]+\/[^/@]+)[^@]*@([0-9a-f]{40})[\"']?[[:space:]]+#[[:space:]]+(.*)$/\1 \2 \3/" \
    | sort -u
)

# A sweep that examined nothing must not read as "everything is current"
if [ "$seen" -eq 0 ]; then
  echo "no pinned \`uses:\` with a trailing comment found under .github, so nothing was checked" >&2
  exit 1
fi
[ "$unchecked" -gt 0 ] && echo "$unchecked of $seen action pins could not be checked" >&2
[ "$behind" -eq 0 ] && [ "$unchecked" -eq 0 ] && echo "checked $seen action pins: every one is current"
exit 0
