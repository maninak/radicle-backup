#!/usr/bin/env bash
#
# Publish .deb files into the signed apt repository on the gh-pages branch.
#
#   ./packaging/apt/publish.sh <directory of .deb files>
#
# The repository is a plain static tree, so GitHub Pages can serve it and anyone can mirror
# it with a recursive fetch. Every run rebuilds the indexes from the whole pool rather than
# appending to them, because an index that drifts from the pool is an apt client that gets a
# hash mismatch and no way to tell why.
#
# Needs: apt-utils (apt-ftparchive), gpg, git. In CI, APT_GPG_PRIVATE_KEY and
# APT_GPG_PASSPHRASE hold the signing key; locally, whatever gpg is already configured with.
set -euo pipefail

INCOMING="${1:?usage: publish.sh <directory of .deb files>}"
ORIGIN="radicle-tools"
LABEL="radicle-tools"
SUITE="stable"
CODENAME="stable"
COMPONENT="main"
ARCHITECTURES="amd64 arm64"
PAGES_BRANCH="gh-pages"
WORKTREE="$(mktemp -d)"

log() { printf '\033[36m::\033[0m %s\n' "$*"; }

mapfile -t debs < <(find "$INCOMING" -type f -name '*.deb' | sort)
[ "${#debs[@]}" -gt 0 ] || { echo "no .deb files under $INCOMING" >&2; exit 1; }
log "publishing ${#debs[@]} package(s)"

if [ -n "${APT_GPG_PRIVATE_KEY:-}" ]; then
  log "importing the signing key"
  export GNUPGHOME="$(mktemp -d)"
  chmod 700 "$GNUPGHOME"
  printf '%s' "$APT_GPG_PRIVATE_KEY" | gpg --batch --import
fi
KEY_ID="$(gpg --list-secret-keys --with-colons | awk -F: '/^sec:/ { print $5; exit }')"
[ -n "$KEY_ID" ] || { echo "no secret key to sign the repository with" >&2; exit 1; }
log "signing with $KEY_ID"

# gh-pages may not exist yet on a first release.
git fetch origin "$PAGES_BRANCH" --depth 1 2>/dev/null || true
if git rev-parse --verify "origin/$PAGES_BRANCH" >/dev/null 2>&1; then
  git worktree add --force "$WORKTREE" "origin/$PAGES_BRANCH"
else
  log "creating $PAGES_BRANCH"
  git worktree add --force --detach "$WORKTREE"
  (cd "$WORKTREE" && git checkout --orphan "$PAGES_BRANCH" && git rm -rf --quiet --ignore-unmatch .)
fi

ROOT="$WORKTREE/apt"
POOL="$ROOT/pool/$COMPONENT"
mkdir -p "$POOL"
cp -v "${debs[@]}" "$POOL/"

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
    -o "APT::FTPArchive::Release::Description=rad-backup and other radicle.tools packages" \
    release "dists/$SUITE" ) > "$ROOT/dists/$SUITE/Release"

gpg_batch=(--batch --yes --pinentry-mode loopback --local-user "$KEY_ID")
[ -n "${APT_GPG_PASSPHRASE:-}" ] && gpg_batch+=(--passphrase "$APT_GPG_PASSPHRASE")

rm -f "$ROOT/dists/$SUITE/Release.gpg" "$ROOT/dists/$SUITE/InRelease"
gpg "${gpg_batch[@]}" --armor --detach-sign --output "$ROOT/dists/$SUITE/Release.gpg" "$ROOT/dists/$SUITE/Release"
gpg "${gpg_batch[@]}" --clearsign --output "$ROOT/dists/$SUITE/InRelease" "$ROOT/dists/$SUITE/Release"
gpg --armor --export "$KEY_ID" > "$ROOT/pubkey.asc"

# So the apt tree is browsable, and so `curl .../apt/` explains itself to whoever finds it.
cat > "$ROOT/index.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>radicle.tools apt repository</title>
<h1>radicle.tools apt repository</h1>
<pre>
curl -fsSL https://maninak.github.io/radicle-backup/apt/pubkey.asc | sudo tee /etc/apt/keyrings/radicle-backup.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/radicle-backup.asc] https://maninak.github.io/radicle-backup/apt $SUITE $COMPONENT" | sudo tee /etc/apt/sources.list.d/radicle-backup.list
sudo apt update && sudo apt install rad-backup
</pre>
<p>Origin <code>$ORIGIN</code>, suite <code>$SUITE</code>, component <code>$COMPONENT</code>, architectures <code>$ARCHITECTURES</code>.</p>
<p><a href="https://github.com/maninak/radicle-backup">Source, and what the packages do.</a></p>
EOF
# GitHub Pages otherwise hides directories whose names begin with an underscore, and skips
# files Jekyll decides are its own. This repository is not a Jekyll site.
touch "$WORKTREE/.nojekyll"

cd "$WORKTREE"
git add -A apt .nojekyll
if git diff --cached --quiet; then
  log "nothing changed"
else
  git -c user.name="github-actions[bot]" \
      -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
      commit -q -m "apt: publish ${#debs[@]} package(s)"
  git push origin "HEAD:$PAGES_BRANCH"
  log "pushed to $PAGES_BRANCH"
fi

cd - > /dev/null
git worktree remove --force "$WORKTREE"
