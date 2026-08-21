#!/usr/bin/env bash
#
# Check a downloaded release: that the files are the ones the checksum file names, and that
# the checksum file was signed by a key this project says signs releases.
#
#   ./verify.sh <directory of downloaded files>
#
# Needs nothing but openssh and either coreutils or the `shasum` macOS ships. It does not fetch
# anything: point it at what you already downloaded, including allowed_signers from the
# repository.
set -euo pipefail

DIR="${1:?usage: verify.sh <directory of downloaded files>}"
# Absolute before the `cd` below, because `dirname "$0"` is relative to where this was
# invoked from and would then be resolved inside the download directory instead. Called
# as `./packaging/release/verify.sh release`, every run exited 1 with "no allowed_signers".
SIGNERS="${ALLOWED_SIGNERS:-$(cd "$(dirname "$0")" && pwd)/allowed_signers}"
NAMESPACE="radicle.tools"

cd "$DIR"
[ -f sha256sums.txt ] || { echo "no sha256sums.txt here" >&2; exit 1; }
[ -f sha256sums.txt.sig ] || { echo "no sha256sums.txt.sig here" >&2; exit 1; }
[ -f "$SIGNERS" ] || { echo "no allowed_signers at $SIGNERS" >&2; exit 1; }

# Who signed it, and is that somebody this project names? This is the whole point: a checksum
# file anyone can rewrite proves nothing on its own.
for signer in $(awk '{print $1}' "$SIGNERS" | sort -u); do
  if ssh-keygen -Y verify -f "$SIGNERS" -I "$signer" -n "$NAMESPACE" \
       -s sha256sums.txt.sig < sha256sums.txt > /dev/null 2>&1; then
    echo "signed by $signer"
    signed=1
    break
  fi
done
[ "${signed:-0}" = 1 ] || { echo "the signature is not from a key this project names" >&2; exit 1; }

# Only the lines for files that are actually here, so verifying one downloaded artifact does
# not fail over the seven you did not want.
present=$(mktemp)
trap 'rm -f "$present"' EXIT
while read -r sum name; do
  [ -f "$name" ] && printf '%s  %s\n' "$sum" "$name" >> "$present"
done < <(sed 's/^\\//' sha256sums.txt)
[ -s "$present" ] || { echo "none of the files in sha256sums.txt are here" >&2; exit 1; }

# macOS ships `shasum` and no GNU coreutils, and this project publishes two darwin binaries and
# a Homebrew formula, so the one script that tells a downloader whether to trust them must run
# there. The release workflow already falls back the same way.
if command -v sha256sum > /dev/null 2>&1; then
  sha256sum -c "$present"
else
  shasum -a 256 -c "$present"
fi
echo "every file present matches what the signed checksum file says it should be"
