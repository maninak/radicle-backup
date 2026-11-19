#!/usr/bin/env bash

# Test the library without its `cli` feature, then build it for the browser's target and hold
# that build to reading no file system, environment, process or terminal

set -euo pipefail

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

target=wasm32-unknown-unknown

# `clippy.toml` lists the calls a tab cannot make, and this is the only build that denies them
RUSTFLAGS="-D warnings" cargo clippy --lib --no-default-features --locked

# Tests built with `cli` reach code the library leaves out, so only this run proves the library
# alone passes its own tests and the format's
RUSTFLAGS="-D warnings" cargo test --lib --test conformance --no-default-features --locked

# A missing toolchain piece fails CI, which must run the build. Elsewhere it skips loudly, so a
# contributor without a wasm clang can still run `just check`.
unavailable() {
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		echo "$1, so the $target build did not run" | complain
		exit 1
	fi
	echo "SKIPPED the $target build: $1. CI runs it." \
		"To run it here, install clang and llvm, or set CC_wasm32_unknown_unknown and" \
		"AR_wasm32_unknown_unknown to a wasm-capable clang and llvm-ar" >&2
	exit 0
}

if command -v rustup >/dev/null; then
	# Not `grep -q`, which can exit before rustup finishes writing and fail the pipe
	if ! rustup target list --installed | grep -x "$target" >/dev/null; then
		if [ -n "${GITHUB_ACTIONS:-}" ]; then
			rustup target add "$target"
		else
			unavailable "the $target target is not installed (rustup target add $target)"
		fi
	fi
elif [ ! -d "$(rustc --print sysroot)/lib/rustlib/$target" ]; then
	unavailable "this rustc has no $target standard library"
fi

# zstd-sys compiles zstd's C, so the target needs a clang that emits wasm and an llvm-ar. A
# distribution names them with a version suffix, newest first here.
emits_wasm() {
	echo 'int f(void) { return 0; }' |
		"$1" --target="$target" -x c -c - -o /dev/null 2>/dev/null
}
newest_first() {
	compgen -c "$1-" | grep -E "^$1-[0-9]+$" | sort -u |
		awk -F- '{ print $NF, $0 }' | sort -rn | cut -d' ' -f2 || [ $? -eq 1 ]
}
if [ -z "${CC_wasm32_unknown_unknown:-}" ]; then
	for candidate in clang $(newest_first clang); do
		if command -v "$candidate" >/dev/null && emits_wasm "$candidate"; then
			CC_wasm32_unknown_unknown=$(command -v "$candidate")
			break
		fi
	done
fi
if [ -z "${CC_wasm32_unknown_unknown:-}" ]; then
	unavailable "no clang here can compile for $target"
fi
if [ -z "${AR_wasm32_unknown_unknown:-}" ]; then
	suffix=${CC_wasm32_unknown_unknown##*/clang}
	for candidate in "llvm-ar$suffix" llvm-ar $(newest_first llvm-ar); do
		if command -v "$candidate" >/dev/null; then
			AR_wasm32_unknown_unknown=$(command -v "$candidate")
			break
		fi
	done
fi
if [ -z "${AR_wasm32_unknown_unknown:-}" ]; then
	unavailable "no llvm-ar was found to archive the C for $target"
fi
export CC_wasm32_unknown_unknown AR_wasm32_unknown_unknown
echo "compiling the C for $target with $CC_wasm32_unknown_unknown and $AR_wasm32_unknown_unknown"

# The library leaves the randomness source to whoever builds it, so a throwaway crate picks the
# one a browser uses. The build must stay inside the committed lock, because only its crates
# have passed the dependency-age gate.
probe=target/wasm-check
mkdir -p "$probe"
cat >"$probe/Cargo.toml" <<'EOF'
[package]
name = "wasm-check"
version = "0.0.0"
edition = "2024"
publish = false

[lib]
path = "lib.rs"

[dependencies]
radicle-backup = { path = "../..", default-features = false }
getrandom = { version = "0.2", features = ["js"] }

[workspace]
EOF
echo 'extern crate radicle_backup;' >"$probe/lib.rs"
cp Cargo.lock "$probe/Cargo.lock"
# Resolving runs no build script, so a crate the lock lacks is refused before any of it runs
(cd "$probe" && cargo metadata --format-version 1 >/dev/null)
packages() {
	awk '/^name = /{ name = $3 } /^version = /{ print name, $3 }' "$1" | sort -u
}
added=$(comm -13 <(packages Cargo.lock) <(packages "$probe/Cargo.lock") |
	grep -v '^"wasm-check" ' || [ $? -eq 1 ])
if [ -n "$added" ]; then
	echo "the $target build needs crates Cargo.lock does not hold: $added" | complain
	exit 1
fi
(cd "$probe" && CARGO_TARGET_DIR=.. RUSTFLAGS="-D warnings" cargo check --locked --target "$target")
