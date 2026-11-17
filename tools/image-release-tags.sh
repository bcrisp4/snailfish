#!/usr/bin/env bash
# Print the moving image tags of a release: tools/image-release-tags.sh VERSION
#
# Stdin holds the release tags of the repository, one per line, as
# `git ls-remote --tags --refs` prints them or as bare tag names. A tag moves
# only to the highest release that it covers:
#
#   latest           the highest release
#   <major>.<minor>  the highest release of that minor line
#   <major>          the highest release of that major line, from 1.0
#
# A patch release on an older line therefore does not move `latest`. A release
# candidate gets no moving tag.
set -euo pipefail

version=${1:?usage: tools/image-release-tags.sh VERSION}
stable='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if ! [[ "$version" =~ $stable ]]; then
  exit 0
fi
major=${BASH_REMATCH[1]}
minor=${BASH_REMATCH[2]}

releases=$(
  { sed -E 's|.*refs/tags/||; s|^v||' | grep -E "$stable" || true; echo "$version"; } | sort -uV
)
highest() { grep -E "$1" <<< "$releases" | tail -n 1; }

if [ "$(highest '.')" = "$version" ]; then
  echo latest
fi
if [ "$(highest "^$major\\.$minor\\.")" = "$version" ]; then
  echo "$major.$minor"
fi
if [ "$major" != 0 ] && [ "$(highest "^$major\\.")" = "$version" ]; then
  echo "$major"
fi
