#!/usr/bin/env python3
"""Refuse a dependency version that was published less than MIN_AGE_DAYS ago.

Dependabot's cooldown holds back the pull requests IT raises. It says nothing about a
`cargo update` run by hand, which is the case where somebody is already in a hurry. This
reads Cargo.lock instead of the config, so it judges what is actually pinned.

By default it looks only at versions this commit ADDS relative to a base ref, because that is
the moment a dependency is adopted; an existing pin only ever gets older. Pass --all to sweep
the whole lockfile, which is slow enough to be a manual act (crates.io is rate limited, so
requests are spaced a second apart).
"""

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

# crates.io asks that automated clients identify themselves and say where to complain.
USER_AGENT = "radicle-backup-ci (https://github.com/maninak/radicle-backup)"
PACKAGE = re.compile(r"^\[\[package\]\]$")
FIELD = re.compile(r'^(name|version|source) = "(.*)"$')


def packages(text):
    """Every registry-sourced (name, version) in a Cargo.lock.

    Entries with no `source` are workspace members, and a git or path source is not on
    crates.io to be asked about.
    """
    found, current = set(), {}
    for line in text.splitlines():
        if PACKAGE.match(line):
            if current.get("source", "").startswith("registry+"):
                found.add((current["name"], current["version"]))
            current = {}
            continue
        match = FIELD.match(line)
        if match:
            current[match.group(1)] = match.group(2)
    if current.get("source", "").startswith("registry+"):
        found.add((current["name"], current["version"]))
    return found


def published(name, version):
    """When crates.io says this exact version appeared, and whether it has been yanked."""
    url = f"https://crates.io/api/v1/crates/{name}/{version}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)["version"]
    created = dt.datetime.strptime(body["created_at"][:19], "%Y-%m-%dT%H:%M:%S")
    return created.replace(tzinfo=dt.timezone.utc), bool(body.get("yanked"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", help="git ref whose Cargo.lock this one is compared against")
    parser.add_argument("--all", action="store_true", help="check every entry, not just the new ones")
    parser.add_argument("--min-age-days", type=int, default=7)
    args = parser.parse_args()

    current = packages(open("Cargo.lock").read())
    if args.all or not args.base:
        subjects = current
        scope = "every entry"
    else:
        try:
            before = subprocess.run(
                ["git", "show", f"{args.base}:Cargo.lock"],
                capture_output=True, text=True, check=True,
            ).stdout
        except subprocess.CalledProcessError:
            # No lockfile at the base (a new branch, a first commit). Everything is new.
            before = ""
        subjects = current - packages(before)
        scope = f"what this changes against {args.base}"

    if not subjects:
        print(f"no dependency versions added ({scope})", flush=True)
        return 0

    noun = "version" if len(subjects) == 1 else "versions"
    print(f"checking {len(subjects)} dependency {noun} ({scope})", flush=True)
    now = dt.datetime.now(dt.timezone.utc)
    status = 0
    for index, (name, version) in enumerate(sorted(subjects)):
        if index:
            time.sleep(1)
        try:
            created, yanked = published(name, version)
        except urllib.error.HTTPError as error:
            print(f"  {name} {version}: crates.io answered {error.code}", file=sys.stderr)
            status = 1
            continue
        age = (now - created).days
        if age < args.min_age_days:
            print(
                f"  {name} {version} was published {age} days ago, minimum is {args.min_age_days}",
                file=sys.stderr,
            )
            status = 1
        # Reported, never fatal: a yank is somebody else's decision landing on a lockfile that
        # was fine when it was written, and it should not turn an unrelated change red.
        if yanked:
            print(f"::warning::{name} {version} has been yanked from crates.io")

    if status == 0:
        print(f"every added dependency version is at least {args.min_age_days} days old")
    return status


if __name__ == "__main__":
    sys.exit(main())
