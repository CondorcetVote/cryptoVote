#!/bin/sh
# Create a `.tar.gz` whose bytes depend only on the archived content and
# the current commit: entries are sorted, timestamps are pinned to the
# commit date, ownership and permissions are normalised, and gzip does
# not record a name or mtime. See "Reproducible builds" in README.md.
#
# Requires GNU tar (`gtar` on macOS, preinstalled on GitHub runners).
#
# Usage: scripts/reproducible-tar.sh <archive.tar.gz> <directory>
set -eu

archive="$1"
directory="$2"
tar="$(command -v gtar || command -v tar)"
commit_time="$(git -C "$(dirname "$0")" log -1 --format=%ct)"

"$tar" --create --file=- \
    --sort=name \
    --mtime="@${commit_time}" \
    --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' \
    --format=gnu \
    "$directory" | gzip -n > "$archive"
