#!/usr/bin/env bash
#
# Check a downloaded release against its checksum file, signed by a key this project names.
#
#   ./verify.sh <directory of downloaded files>
#
# Needs only openssh and either coreutils or the `shasum` macOS ships. It fetches nothing, so
# point it at what you downloaded, including allowed_signers from the repository.
set -euo pipefail

DIR="${1:?usage: verify.sh <directory of downloaded files>}"
# Made absolute before the `cd` below, because a relative `dirname "$0"` would then resolve
# inside the download directory
SIGNERS="${ALLOWED_SIGNERS:-$(cd "$(dirname "$0")" && pwd)/allowed_signers}"
NAMESPACE="radicle.tools"

cd "$DIR"
[ -f sha256sums.txt ] || { echo "no sha256sums.txt here" >&2; exit 1; }
[ -f sha256sums.txt.sig ] || { echo "no sha256sums.txt.sig here" >&2; exit 1; }
[ -f "$SIGNERS" ] || { echo "no allowed_signers at $SIGNERS" >&2; exit 1; }

# A checksum file anyone can rewrite proves nothing, so a signer this project names must sign
# shellcheck disable=SC2013 # a key blob cannot hold whitespace, so words and lines are the
# same list here
for signer in $(awk '{print $1}' "$SIGNERS" | sort -u); do
  if ssh-keygen -Y verify -f "$SIGNERS" -I "$signer" -n "$NAMESPACE" \
       -s sha256sums.txt.sig < sha256sums.txt > /dev/null 2>&1; then
    echo "signed by $signer"
    signed=1
    break
  fi
done
[ "${signed:-0}" = 1 ] || { echo "the signature is not from a key this project names" >&2; exit 1; }

# Only the lines for files that are here, so verifying one downloaded artifact passes
present=$(mktemp)
trap 'rm -f "$present"' EXIT
while read -r sum name; do
  [ -f "$name" ] && printf '%s  %s\n' "$sum" "$name" >> "$present"
done < <(sed 's/^\\//' sha256sums.txt)
[ -s "$present" ] || { echo "none of the files in sha256sums.txt are here" >&2; exit 1; }

# macOS ships `shasum` and no GNU coreutils
if command -v sha256sum > /dev/null 2>&1; then
  sha256sum -c "$present"
else
  shasum -a 256 -c "$present"
fi
echo "every file present matches what the signed checksum file says it should be"
