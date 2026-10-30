#!/usr/bin/env bash
# Regenerate the hash-locked requirements. Needs uv (https://docs.astral.sh/uv/).
#   requirements/relock.sh               re-resolve; the kit stays at the commit in kit-override.txt
#   requirements/relock.sh <kit-commit>  pin the kit to that full commit SHA first
#
# build.txt  : the build backend (hatchling), installed first so nothing is built with an unpinned backend
# runtime.txt: what the image installs;  dev.txt: runtime + test/lint tools (CI);  tools.txt: pip-audit and bandit (CI)
# Every file is --require-hashes clean. Install order is in the Dockerfile and the workflow.
# The kit is pinned to a commit-addressed GitHub archive and locked by sha256; if GitHub ever changes the archive bytes the
# install fails closed and this script recomputes the hash.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${1:-}" ]; then
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || { echo "kit commit must be a full 40-hex SHA" >&2; exit 2; }
  echo "agentpg-kit @ https://github.com/elchinoo/agentpg-kit/archive/$1.tar.gz" > requirements/kit-override.txt
fi
c="uv pip compile --universal --python-version 3.11 --generate-hashes --no-header --quiet"
$c requirements/build.in -o requirements/build.txt
$c requirements/tools.in -o requirements/tools.txt
$c pyproject.toml --override requirements/kit-override.txt -o requirements/runtime.txt
$c pyproject.toml --extra dev --override requirements/kit-override.txt -o requirements/dev.txt
