#!/usr/bin/env bash
#
# Publish .deb files into the signed apt repository at https://apt.radicle.tools.
#
#   ./packaging/apt/publish.sh <directory of .deb files>
#
# The repository is a plain static tree in a Cloudflare R2 bucket, so it can be served with no
# server to run, mirrored with a recursive fetch, and read by apt with nothing but HTTP.
#
# Every run rebuilds the indexes from the whole pool rather than appending to them, because an
# index that drifts from the pool is an apt client that gets a hash mismatch and no way to tell
# why. The existing pool is pulled down first for the same reason: an index must describe every
# package that is there, not only the ones this run happened to upload.
#
# Needs: apt-utils (apt-ftparchive), gpg, rclone. In CI, APT_GPG_PRIVATE_KEY and
# APT_GPG_PASSPHRASE hold the signing key, and R2_* the bucket credentials.
set -euo pipefail

INCOMING="${1:?usage: publish.sh <directory of .deb files>}"
ORIGIN="radicle-tools"
LABEL="radicle-tools"
SUITE="stable"
CODENAME="stable"
COMPONENT="main"
ARCHITECTURES="amd64 arm64"
SITE="https://apt.radicle.tools"
REMOTE="r2:${R2_BUCKET:-radicle-tools-apt}"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

log() { printf '\033[36m::\033[0m %s\n' "$*"; }

mapfile -t debs < <(find "$INCOMING" -type f -name '*.deb' | sort)
[ "${#debs[@]}" -gt 0 ] || { echo "no .deb files under $INCOMING" >&2; exit 1; }
log "publishing ${#debs[@]} package(s)"

# rclone reads its remote from the environment, so nothing has to be written to disk.
export RCLONE_CONFIG_R2_TYPE=s3
export RCLONE_CONFIG_R2_PROVIDER=Cloudflare
export RCLONE_CONFIG_R2_ENDPOINT="${R2_ENDPOINT:?R2_ENDPOINT is not set}"
export RCLONE_CONFIG_R2_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?R2_ACCESS_KEY_ID is not set}"
export RCLONE_CONFIG_R2_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?R2_SECRET_ACCESS_KEY is not set}"
# R2 has no ACLs and returns an error for the header rclone sends by default.
export RCLONE_S3_NO_CHECK_BUCKET=true
export RCLONE_S3_ACL=

if [ -n "${APT_GPG_PRIVATE_KEY:-}" ]; then
  log "importing the signing key"
  GNUPGHOME="$(mktemp -d)"
  export GNUPGHOME
  chmod 700 "$GNUPGHOME"
  printf '%s' "$APT_GPG_PRIVATE_KEY" | gpg --batch --import
fi
# Signing key selection. Only one that can sign and is not expired, revoked, disabled or
# invalid: the fresh GNUPGHOME above exists only when CI supplies the key, so a local run reads
# whatever the keyring already holds and the first entry there is rarely this repository's.
# Several candidates refuse rather than pick, because an index signed by the wrong key is
# rejected by every client holding the right one, with nothing in between to say why.
# Capability matches in either case: gpg writes it lowercase for the primary and uppercase for
# the whole key.
if [ -n "${APT_GPG_KEY_ID:-}" ]; then
  KEY_ID="$APT_GPG_KEY_ID"
else
  mapfile -t usable < <(
    gpg --list-secret-keys --with-colons |
      awk -F: '$1 == "sec" && $2 !~ /[erid]/ && $12 ~ /[sS]/ { print $5 }'
  )
  case ${#usable[@]} in
    1) KEY_ID="${usable[0]}" ;;
    0)
      echo "no secret key here can sign: every one is expired, revoked, disabled or has no" \
           "signing capability" >&2
      gpg --list-secret-keys --keyid-format=long >&2 || true
      exit 1
      ;;
    *)
      echo "more than one secret key here could sign (${usable[*]}), and picking one would be" \
           "a guess; name it with APT_GPG_KEY_ID" >&2
      exit 1
      ;;
  esac
fi
log "signing with $KEY_ID"

log "fetching the current pool"
mkdir -p "$ROOT/pool/$COMPONENT"
# `|| true` here swallowed every failure, so a rotated token or a 5xx rebuilt the indexes from
# this run's .debs alone and delisted every version already published. rclone exits 3 for
# "directory not found", which is the only case that legitimately starts from an empty pool.
probe=0
rclone lsf "$REMOTE/pool/$COMPONENT" > /dev/null 2>&1 || probe=$?
if [ "$probe" -eq 0 ]; then
  rclone copy "$REMOTE/pool/$COMPONENT" "$ROOT/pool/$COMPONENT" --quiet
elif [ "$probe" -eq 3 ]; then
  log "nothing in the pool yet, so this is the first publish"
else
  echo "could not read the existing pool (rclone exit $probe); refusing to publish an index that would drop every version already there" >&2
  exit 1
fi
cp -v "${debs[@]}" "$ROOT/pool/$COMPONENT/"

for arch in $ARCHITECTURES; do
  dir="$ROOT/dists/$SUITE/$COMPONENT/binary-$arch"
  mkdir -p "$dir"
  ( cd "$ROOT" && apt-ftparchive --arch "$arch" packages "pool/$COMPONENT" ) > "$dir/Packages"
  gzip -9fkn "$dir/Packages"
  # A client that speaks only the older index format still needs this to exist.
  cat > "$dir/Release" <<EOF
Archive: $SUITE
Component: $COMPONENT
Origin: $ORIGIN
Label: $LABEL
Architecture: $arch
EOF
done

log "writing dists/$SUITE/Release"
( cd "$ROOT" && apt-ftparchive \
    -o "APT::FTPArchive::Release::Origin=$ORIGIN" \
    -o "APT::FTPArchive::Release::Label=$LABEL" \
    -o "APT::FTPArchive::Release::Suite=$SUITE" \
    -o "APT::FTPArchive::Release::Codename=$CODENAME" \
    -o "APT::FTPArchive::Release::Components=$COMPONENT" \
    -o "APT::FTPArchive::Release::Architectures=$ARCHITECTURES" \
    -o "APT::FTPArchive::Release::Description=radicle-backup and other radicle.tools packages" \
    release "dists/$SUITE" ) > "$ROOT/dists/$SUITE/Release"

gpg_batch=(--batch --yes --pinentry-mode loopback --local-user "$KEY_ID")
[ -n "${APT_GPG_PASSPHRASE:-}" ] && gpg_batch+=(--passphrase "$APT_GPG_PASSPHRASE")

rm -f "$ROOT/dists/$SUITE/Release.gpg" "$ROOT/dists/$SUITE/InRelease"
gpg "${gpg_batch[@]}" --armor --detach-sign --output "$ROOT/dists/$SUITE/Release.gpg" "$ROOT/dists/$SUITE/Release"
gpg "${gpg_batch[@]}" --clearsign --output "$ROOT/dists/$SUITE/InRelease" "$ROOT/dists/$SUITE/Release"
gpg --armor --export "$KEY_ID" > "$ROOT/pubkey.asc"

# So the tree is browsable, and so `curl $SITE` explains itself to whoever finds it.
cat > "$ROOT/index.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>radicle.tools apt repository</title>
<h1>radicle.tools apt repository</h1>
<pre>
curl -fsSL $SITE/pubkey.asc | sudo tee /etc/apt/keyrings/radicle-tools.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/radicle-tools.asc] $SITE $SUITE $COMPONENT" | sudo tee /etc/apt/sources.list.d/radicle-tools.list
sudo apt update && sudo apt install radicle-backup
</pre>
<p>Origin <code>$ORIGIN</code>, suite <code>$SUITE</code>, component <code>$COMPONENT</code>, architectures <code>$ARCHITECTURES</code>.</p>
<p><a href="https://radicle.tools">radicle.tools</a> &middot; <a href="https://github.com/maninak/radicle-backup">source</a></p>
EOF

# The pool goes up before the indexes that name it: for the moments in between, a client that
# reads an old index and fetches a package it names still finds it. The other order would
# serve an index pointing at a .deb that is not there yet.
log "uploading the pool"
rclone copy "$ROOT/pool" "$REMOTE/pool" --checksum --quiet
log "uploading the indexes"
rclone copy "$ROOT/dists" "$REMOTE/dists" --checksum
rclone copy "$ROOT/pubkey.asc" "$REMOTE/" --checksum
rclone copy "$ROOT/index.html" "$REMOTE/" --checksum

log "published to $SITE"
