#!/usr/bin/env bash
# gitleaks-delta-scan.sh - scan ONLY the commits a pull request or a push introduces.
#
# Runs the same rules as the pre-commit hook (.pre-commit-config.yaml /
# .gitleaks.toml), so a hardcoded key cannot land even where a contributor never
# installed the hook. Called from two places, which is why it is a script:
#   .github/workflows/repository-gates.yml  on pull_request (BASE = PR base)
#   .github/workflows/gitleaks.yml          on push to main (BASE = event.before)
# One pinned version, one range rule and one set of flags, rather than two
# copies of an inline block drifting apart.
#
# DELTA, NOT THE FULL TREE. A full-tree scan re-reports the ~600 placeholder keys
# in *.env.example and test fixtures, plus the already-revoked pre-rotation keys
# in history, and fails every run. This gate's job is to stop NEW secrets from
# entering the tree. --redact keeps any matched value out of the log.
#
# The binary lands under $RUNNER_TEMP, which the runner makes private per job
# on hosted and self-hosted runners alike. A fixed /tmp path is shared by every
# slot of the self-hosted fleet, and two concurrent downloads there leave the
# loser executing a half-written file (no_shared_install_path_from_fleet_jobs_test.sh).
#
# Env: HEAD_SHA (required); BASE_SHA (empty or all-zero on a branch's first push,
#      in which case only the tip commit is scanned).
set -euo pipefail

# Keep in lockstep with the gitleaks `rev` in .pre-commit-config.yaml.
GITLEAKS_VERSION=8.21.2
: "${HEAD_SHA:?HEAD_SHA is required}"

dir="${RUNNER_TEMP:?RUNNER_TEMP is required - the download must land in a per-job directory}/gitleaks-${GITLEAKS_VERSION}"
mkdir -p "$dir"
curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
  -o "$dir/gitleaks.tar.gz"
tar -xzf "$dir/gitleaks.tar.gz" -C "$dir" gitleaks
chmod +x "$dir/gitleaks"

ZERO="0000000000000000000000000000000000000000"
if [ -z "${BASE_SHA:-}" ] || [ "${BASE_SHA}" = "${ZERO}" ]; then
  LOG_OPTS="-1 ${HEAD_SHA}"
else
  LOG_OPTS="${BASE_SHA}..${HEAD_SHA}"
fi
echo "Scanning commit range: ${LOG_OPTS}"
"$dir/gitleaks" detect \
  --source . \
  --log-opts="${LOG_OPTS}" \
  --config .gitleaks.toml \
  --redact \
  --verbose \
  --no-banner
