#!/usr/bin/env bash
#
# Sign a release's checksum file with an ssh key named in packaging/release/allowed_signers.
#
#   ./packaging/release/sign.sh <directory holding sha256sums.txt>
#
# The key comes from, in order:
#   RELEASE_SIGNING_KEY  the private key itself, in the environment. What CI uses.
#   RELEASE_SIGNING_FILE a path to it.
#   ssh-agent            whatever is loaded, if neither is set. What a person uses.
set -euo pipefail

DIR="${1:?usage: sign.sh <directory holding sha256sums.txt>}"
SUMS="$DIR/sha256sums.txt"
NAMESPACE="radicle.tools"

[ -f "$SUMS" ] || { echo "no $SUMS to sign" >&2; exit 1; }
# ssh-keygen asks before replacing a signature, and a CI job has nobody to ask
rm -f "$SUMS.sig"

if [ -n "${RELEASE_SIGNING_KEY:-}" ]; then
  KEY="$(mktemp)"
  chmod 600 "$KEY"
  printf '%s\n' "$RELEASE_SIGNING_KEY" > "$KEY"
  trap 'rm -f "$KEY"' EXIT
elif [ -n "${RELEASE_SIGNING_FILE:-}" ]; then
  KEY="$RELEASE_SIGNING_FILE"
else
  # `-Y sign` reads from the agent but still needs a key to select, so the agent's first
  # identity signs
  KEY=""
fi

if [ -n "$KEY" ]; then
  ssh-keygen -Y sign -f "$KEY" -n "$NAMESPACE" "$SUMS"
else
  ssh-add -L > /dev/null || { echo "no key given and no ssh-agent identities" >&2; exit 1; }
  AGENT_KEY="$(mktemp)"
  ssh-add -L | head -1 > "$AGENT_KEY"
  trap 'rm -f "$AGENT_KEY"' EXIT
  ssh-keygen -Y sign -f "$AGENT_KEY" -n "$NAMESPACE" "$SUMS"
fi

echo "signed: $SUMS.sig"
ssh-keygen -Y check-novalidate -n "$NAMESPACE" -s "$SUMS.sig" < "$SUMS"
