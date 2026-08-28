#!/usr/bin/env bash
#
# Regression test for scripts/setup-e2e-testing.sh's container cleanup scope.
#
# WHAT HAPPENED, so the assertions below read as consequences rather than
# style. docker_cleanup_containers() was `docker ps -aq` with no filter, and it
# stopped and removed EVERY container on the daemon. It is called from the
# three SETUP paths as well as teardown, so merely running
# `setup-e2e-testing.sh enterprise` destroyed every container belonging to
# every other session sharing the machine. Measured on 2026-08-25: one run took
# out three unrelated stacks that had been up for days.
#
# It stayed invisible for a whole session because every check written
# afterwards is name-filtered. `docker ps | grep '^axonflow-'` shows a
# perfectly healthy stack and CANNOT show what is missing: a check scoped to
# your own containers cannot fail on somebody else's.
#
# The SECOND half of the same incident was `docker network prune -f`, which sat
# on the line after every one of those four calls. It has no project filter and
# no name filter: it removes every network the daemon currently considers
# unused, so a peer stack that is merely stopped loses the network it needs to
# come back up. `docker compose down -v` already removes this project's own
# network, so nothing replaces it. Part 1 pins that too.
#
# Part 1 is a shape assertion: the unfiltered spellings must not come back.
# Part 2 drives the name selection over fixture compose files, with no daemon.
# Part 3 is the behavioural half and needs docker: it builds decoys that a
# broken scope would eat and asserts they survive, and decoys each half of the
# filter owns and asserts they are removed. It is the only part that proves the
# property rather than the text, so it RUNS IN CI: its fixture image is built
# locally from an empty tarball, needing no registry, no pull and no network,
# and the containers are only ever `create`d because the property under test is
# about which names are selected, not about anything running.
#
# Run locally:
#   bash tests/regression-test-required/e2e_setup_cleanup_scope_test.sh

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SETUP="${REPO_ROOT}/scripts/setup-e2e-testing.sh"
fail=0

if [ ! -f "${SETUP}" ]; then
  echo "FAIL: ${SETUP} not found."
  exit 1
fi

# --- 1. The unfiltered spelling must not come back ------------------------
#
# Anchored to the FUNCTION BODY, not the whole file: `docker ps -aq` is a
# perfectly good thing to write elsewhere, and a file-wide grep would either
# false-positive on that or be silenced by someone moving the call.
body="$(awk '/^docker_cleanup_containers\(\) \{/{p=1} p{print} p && /^\}/{exit}' "${SETUP}")"
if [ -z "${body}" ]; then
  echo "FAIL: docker_cleanup_containers() not found in ${SETUP} - it was renamed or"
  echo "      removed, and every assertion in this section would silently check nothing."
  fail=1
else
  if printf '%s\n' "${body}" | grep -qE 'docker ps -aq[[:space:]]*(2>|\||$|\))'; then
    echo "FAIL: docker_cleanup_containers() calls 'docker ps -aq' with NO filter."
    echo "      That is every container on the daemon, including every other session's."
    echo "      Filter by com.docker.compose.project and by exact pinned name."
    fail=1
  else
    echo "ok: docker_cleanup_containers() does not enumerate the whole daemon"
  fi
  if printf '%s\n' "${body}" | grep -q 'label=com.docker.compose.project='; then
    echo "ok: cleanup is scoped to a compose project"
  else
    echo "FAIL: cleanup no longer filters on com.docker.compose.project."
    fail=1
  fi
  # The exact-name anchor. A prefix match on 'axonflow-' would put the defect
  # straight back, one filter narrower: it would collect a sibling session's
  # axonflow-agent-3492.
  if printf '%s\n' "${body}" | grep -q 'name=\^/'; then
    echo "ok: pinned names are matched by exact name, not by prefix"
  else
    echo "FAIL: pinned-name matching is not anchored (expected a 'name=^/...\$' filter)."
    echo "      A prefix match collects another session's container whose name merely"
    echo "      starts the same way."
    fail=1
  fi
fi

# --- 1b. No daemon-global network prune, anywhere in the script -----------
#
# File-wide, not function-scoped: the four prunes were never inside
# docker_cleanup_containers(), they were the line after each of its call sites,
# and a new call site would come with a new one. Comment lines are stripped
# first, because the script explains at each of those four sites WHY there is no
# prune there and those sentences must not read as the offence.
#
# The non-comment body is captured into a variable BEFORE it is searched, and
# deliberately not piped. `writer | grep -q` under `set -o pipefail` is a
# guard that cannot fail: grep -q closes its stdin on the first match, the
# writer takes SIGPIPE and exits 141, and pipefail promotes that non-zero to
# the pipeline status, so the `if` takes the FALSE branch while the offence is
# sitting in the file. That is not hypothetical here: it was measured on this
# very guard, which reported ok 5 times out of 5 with a live
# `docker network prune -f` reinstated.
setup_body="$(grep -v '^[[:space:]]*#' "${SETUP}")"
if printf '%s\n' "${setup_body}" | grep -qE 'docker[[:space:]]+(network|system|container|volume)[[:space:]]+prune'; then
  echo "FAIL: ${SETUP} runs a docker prune."
  echo "      Prune has no project filter and no name filter - it deletes across the"
  echo "      whole daemon, which is how this incident took out three stacks' networks"
  echo "      as well as their containers. 'docker compose down -v' already removes"
  echo "      this project's own network. If a specific one must go, remove it BY NAME."
  grep -vn '^[[:space:]]*#' "${SETUP}" | grep -E 'docker[[:space:]]+(network|system|container|volume)[[:space:]]+prune' | sed 's/^/      /'
  fail=1
else
  echo "ok: no daemon-global docker prune in the script"
fi

# --- 2. Name selection, over fixtures, with no daemon ---------------------

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cat > "${work}/a.yml" <<'YAML'
services:
  postgres:
    image: postgres:15-alpine
    container_name: axonflow-postgres
  agent:
    container_name: "axonflow-agent"
YAML
cat > "${work}/b.yml" <<'YAML'
services:
  portal:
    container_name: axonflow-customer-portal
  dupe:
    container_name: axonflow-postgres
  # container_name: axonflow-not-real
YAML

# Source ONLY the pure helper, so this part needs neither docker nor the rest
# of the script's global state.
helper="$(awk '/^compose_pinned_container_names\(\) \{/{p=1} p{print} p && /^\}/{exit}' "${SETUP}")"
if [ -z "${helper}" ]; then
  echo "FAIL: compose_pinned_container_names() not found - the name selection this"
  echo "      test exists to pin is gone, and part 2 would check nothing."
  fail=1
else
  eval "${helper}"
  got="$(compose_pinned_container_names "${work}/a.yml" "${work}/b.yml" | tr '\n' ' ')"
  want="axonflow-agent axonflow-customer-portal axonflow-postgres "
  if [ "${got}" = "${want}" ]; then
    echo "ok: names are read, dequoted, deduplicated and sorted"
  else
    echo "FAIL: compose_pinned_container_names"
    echo "      got:  ${got}"
    echo "      want: ${want}"
    fail=1
  fi
  # A commented-out container_name is not a container. The sed is anchored to
  # the start of the line for exactly this reason.
  if printf '%s\n' "${got}" | grep -q 'axonflow-not-real'; then
    echo "FAIL: a COMMENTED-OUT container_name was collected as a real one."
    fail=1
  else
    echo "ok: a commented-out container_name is not collected"
  fi
  if [ -z "$(compose_pinned_container_names "${work}/does-not-exist.yml")" ]; then
    echo "ok: a missing compose file yields no names rather than erroring"
  else
    echo "FAIL: a missing compose file produced names."
    fail=1
  fi
fi

# --- 3. Behavioural: which containers the two filters actually select -----
#
# EVERY name this part creates carries the ${uniq} suffix, and every `docker rm`
# below names one of them. This test runs on shared daemons where other people's
# stacks are up: an earlier draft used the bare name `axonflow-postgres` as its
# "owned" decoy and removed it at the end, which on a shared machine destroys
# somebody else's postgres - the same class of defect as the one under test,
# committed by the test for it.
#
# The owned-by-NAME decoy therefore cannot be a name the real compose files pin.
# Instead part 3 points the function's default file list at a FIXTURE repo that
# pins the uniquified name, by overriding REPO_ROOT for the call. The function
# is then exercised exactly as production runs it - no-arg, reading whatever
# ${REPO_ROOT} holds - while owning nothing that is not ours.

skip_part3() {
  # Docker is on every GitHub-hosted ubuntu runner, so in CI an absent daemon is
  # a broken job, not a reason to report success on the text-only halves.
  if [ "${CI:-}" = "true" ]; then
    echo "FAIL: $1"
    echo "      In CI this is not a skip. Part 3 is the only part that proves the"
    echo "      PROPERTY rather than the TEXT, and a green run without it means the"
    echo "      required check covers grep assertions only."
    fail=1
  else
    echo "SKIPPED: $1"
    echo "         Parts 1 and 2 passed, and neither would have caught a scope that is"
    echo "         correct in shape and wrong in effect. Re-run where docker works."
  fi
}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  skip_part3 "docker is not available, so the behavioural part did not run."
else
  uniq="cleanupscope$$"
  img="axonflow-cleanupscope-fixture:${uniq}"

  # Built from an EMPTY tarball, so this needs no registry, no pull, no network
  # and no cached image: it runs identically on a laptop and on ubuntu-latest.
  # The containers below are `create`d, never started - the property under test
  # is which names the filters select, and `docker ps -aq` lists Created
  # containers exactly as it lists running ones.
  if ! tar -cf - -T /dev/null 2>/dev/null | docker import - "${img}" >/dev/null 2>&1; then
    skip_part3 "could not build the local fixture image ${img}."
  else
    fixrepo="${work}/fixture-repo"
    mkdir -p "${fixrepo}"

    decoy_other="othersession-${uniq}"        # another project's label
    decoy_prefix="axonflow-agent-${uniq}"     # our prefix, but not a pinned name
    owned_name="axonflow-postgres-${uniq}"    # pinned by the fixture compose file
    owned_label="labelowned-${uniq}"          # our project label, name matches nothing

    cat > "${fixrepo}/docker-compose.yml" <<YAML
services:
  postgres:
    container_name: ${owned_name}
YAML
    : > "${fixrepo}/docker-compose.enterprise.yml"

    docker rm -fv "${decoy_other}" "${decoy_prefix}" "${owned_name}" "${owned_label}" >/dev/null 2>&1 || true
    docker create --name "${decoy_other}" --label com.docker.compose.project=someoneelse "${img}" /bin/true >/dev/null
    docker create --name "${decoy_prefix}" "${img}" /bin/true >/dev/null
    docker create --name "${owned_name}" "${img}" /bin/true >/dev/null
    # The ONLY thing that can select this one is the label half of the filter:
    # its name is not pinned by the fixture compose file and does not start with
    # anything the name half looks for. Without it, breaking the label filter
    # leaves every assertion in this part passing.
    docker create --name "${owned_label}" --label "com.docker.compose.project=${uniq}" "${img}" /bin/true >/dev/null

    # Invoked indirectly, from inside the functions sourced immediately below.
    # shellcheck disable=SC2329
    log_info() { :; }
    cleanup_fn="$(awk '/^docker_cleanup_containers\(\) \{/{p=1} p{print} p && /^\}/{exit}' "${SETUP}")"
    if [ -z "${cleanup_fn}" ]; then
      echo "FAIL: docker_cleanup_containers() not found - part 3 would check nothing."
      fail=1
    else
      eval "${cleanup_fn}"
      ( cd "${fixrepo}" \
          && REPO_ROOT="${fixrepo}" COMPOSE_PROJECT_NAME="${uniq}" docker_cleanup_containers )

      for name in "${decoy_other}" "${decoy_prefix}"; do
        if docker ps -aq --filter "name=^/${name}$" | grep -q .; then
          echo "ok: ${name} survived the cleanup"
        else
          echo "FAIL: ${name} was destroyed. The cleanup is reaching containers this"
          echo "      deployment does not own - the exact defect this file exists for."
          fail=1
        fi
      done

      if docker ps -aq --filter "name=^/${owned_name}$" | grep -q .; then
        echo "FAIL: ${owned_name} SURVIVED. It is pinned by this deployment's compose"
        echo "      file, so the pinned-NAME half of the filter selected nothing and"
        echo "      this test would pass on a function that does nothing at all."
        fail=1
      else
        echo "ok: ${owned_name}, a pinned name this bundle owns, was removed"
      fi

      if docker ps -aq --filter "name=^/${owned_label}$" | grep -q .; then
        echo "FAIL: ${owned_label} SURVIVED. Nothing but the compose-project LABEL can"
        echo "      select it, so the label half of the filter is not working - and"
        echo "      Compose-managed containers whose names are not pinned are exactly"
        echo "      what that half exists to clean up."
        fail=1
      else
        echo "ok: ${owned_label}, selected only by the compose-project label, was removed"
      fi
    fi

    docker rm -fv "${decoy_other}" "${decoy_prefix}" "${owned_name}" "${owned_label}" >/dev/null 2>&1 || true
    docker rmi -f "${img}" >/dev/null 2>&1 || true
  fi
fi

echo
if [ "${fail}" -ne 0 ]; then
  echo "e2e_setup_cleanup_scope_test.sh: FAILED"
  exit 1
fi
echo "e2e_setup_cleanup_scope_test.sh: PASSED"
exit 0
