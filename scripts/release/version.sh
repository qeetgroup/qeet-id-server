#!/usr/bin/env bash
# version.sh <branch> — print the version a release or hotfix branch ships.
#
# Qeet ID releases are named after the month they go out, YEAR.MONTH.N with no
# leading zeros: release/2027.1.0 is January 2027's monthly release, and
# hotfix/2027.1.1 the first urgent fix to it. Exits non-zero, saying why, for
# any other branch name. Used by candidate.yml (the image testers run) and
# deploy.yml (what a merge into main releases).
set -euo pipefail

branch="${1:?usage: version.sh <branch>}"
calver='(20[0-9]{2})\.([1-9]|1[0-2])\.(0|[1-9][0-9]*)'

if [[ $branch =~ ^release/${calver}$ ]]; then
  if [ "${BASH_REMATCH[3]}" != 0 ]; then
    echo "a release branch is release/YEAR.MONTH.0 (fixes after it are hotfix/YEAR.MONTH.N): $branch" >&2
    exit 1
  fi
elif [[ $branch =~ ^hotfix/${calver}$ ]]; then
  if [ "${BASH_REMATCH[3]}" = 0 ]; then
    echo "a hotfix counts from 1 (hotfix/YEAR.MONTH.1, .2 …): $branch" >&2
    exit 1
  fi
else
  echo "not a release/YEAR.MONTH.0 or hotfix/YEAR.MONTH.N branch (no leading zeros): $branch" >&2
  exit 1
fi

echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
