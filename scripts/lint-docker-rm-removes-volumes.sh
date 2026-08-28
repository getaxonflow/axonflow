#!/usr/bin/env bash
# Every force-remove of a container must also remove its anonymous volumes.
#
# WHY THIS EXISTS, measured rather than asserted. `postgres` (and `mysql`,
# `mongo`, `redis`) declare a VOLUME in their Dockerfile, so every container
# started from them gets an ANONYMOUS volume. `docker rm -f` deletes the
# container and ORPHANS that volume. It is unreachable by name, holds a full
# initdb plus whatever the test wrote, and nothing ever collects it.
#
# On a developer daemon on 2026-08-26: 684 volumes, 680 of them anonymous,
# 52.84 GB, 100% reclaimable - and 680 of the 684 had been created in the
# preceding TWO DAYS. Containers read 0 the whole time, which is why it went
# unnoticed: `docker ps -a` is clean while the disk fills.
#
# CI never noticed either, and that is the more important half. Its
# between-arms reaper runs `docker system prune -af --volumes`, which sweeps
# them wholesale - so the leak is invisible exactly where it is compensated,
# and unbounded everywhere else.
#
# `platform/agent/approletest/setup.go` was fixed to `-fv` when this was first
# found. The fix was applied to that ONE call site and its siblings were left:
# six more Go helpers and 33 shell sites were still leaking when this guard was
# written. That is the failure this ratchet exists to stop repeating - not the
# original bug, but the half-applied fix.
#
# `-v` IS SAFE TO ADD ANYWHERE. `docker rm --help`: "Remove anonymous volumes
# associated with the container." NAMED volumes are never removed by it, so a
# compose stack's `postgres-data` survives `docker rm -fv` untouched. There is
# no case where `-f` is correct and `-fv` is not.
#
# SECOND RULE, added after the first proved insufficient: an EPHEMERAL postgres
# container must mount something at /var/lib/postgresql/data.
#
# `-fv` only reclaims the anonymous volume if the cleanup actually RUNS, and it
# does not run on a `go test -timeout` kill, a Ctrl-C, or a panic that takes
# the process down. Measured: with a plain `docker run`, killing the container
# and never removing it leaves +1 volume; with a tmpfs at that path it leaves
# +0, because the anonymous volume is never created at all. Supplying ANY mount
# at a declared VOLUME path suppresses it.
#
# THIS RULE IS NOT BLANKET, and the exclusions are the interesting part:
#
#   * `docker run --rm ... postgres:14 psql` is a CLIENT. It writes no data
#     directory, so there is nothing to mount and nothing to leak.
#   * `scripts/multi-tenant/deploy-client.sh` starts PERSISTENT demo databases
#     with `--restart unless-stopped`. Mounting a tmpfs there would silently
#     destroy their data on every restart - a data-loss bug introduced by a
#     tidiness fix. They are excluded by path, deliberately and loudly.
#
# The scan joins line continuations before matching. A line-oriented pass
# missed three real sites here, including a `docker run -d --name X \` whose
# image sits two lines below - the same shape that defeated the #3334 guard and
# then the #3408 one.
#
# KNOWN LIMITS of the tmpfs rule, stated rather than papered over, each pinned
# as a NEGATIVE fixture so the limit is a tested fact:
#
#   1. An IMAGE HELD IN A VARIABLE (`docker run -d "$POSTGRES_IMAGE"`) matches
#      no literal. R3 found a live leaking site behind exactly this shape
#      (scripts/debugging/validate-all-migrations.sh, since fixed by hand).
#      Closing it needs variable resolution - an interpreter, not a grep.
#   2. docker-compose services declare volumes in YAML, a different grammar
#      entirely; compose stacks are governed by their own `down -v` teardown
#      convention, not by this rule.
#   3. The rule is postgres-with-its-path only; see the inline comment at the
#      image match for why widening the image set without per-image data
#      paths produced false positives.
#
# Usage:
#   scripts/lint-docker-rm-removes-volumes.sh            scan the repo
#   scripts/lint-docker-rm-removes-volumes.sh --self-test
set -uo pipefail

# scan ROOT - prints one `<file>:<line>: <text>` per offending site.
#
# Comments are stripped FIRST, and that is not cosmetic: setup.go's own doc
# comment contains the string `docker rm -f` while EXPLAINING why it is wrong.
# A guard that flagged its own rationale would be reverted within a day.
#
# Line comments only. A `/* */` block cannot open on a shell line and the Go
# sites here are single-line, so the block-comment machinery that bit
# lint-hitl-queue-choke-point.sh (a `/*` inside a string literal opening a
# strip window) is deliberately not reproduced.
scan() {
  local root="$1"
  find "$root" \
    \( -name .git -o -name node_modules -o -name vendor -o -name build \) -prune -o \
    \( -name '*.sh' -o -name '*.go' -o -name '*.yml' -o -name '*.yaml' \) -print 2>/dev/null \
  | LC_ALL=C sort \
  | while IFS= read -r f; do
      # `docs/` is prose for humans, not something CI runs.
      #
      # THIS SCRIPT EXCLUDES ITSELF, and it has to. Its self-test writes
      # fixtures containing the bad form, so the strings live in this file
      # as literals - a guard that reads its own fixtures as findings can
      # never pass on the repository that contains it. Found by running the
      # guard against the real tree, which is the only reason it is here.
      case "${f#"$root"/}" in
        docs/*|*/docs/*) continue ;;
        scripts/lint-docker-rm-removes-volumes.sh) continue ;;
        # PRODUCTION DEPLOYMENT SCRIPTS are excluded from the rm rule as a
        # class, and the reason is scope, not correctness. These run over
        # SSH/SSM against LIVE hosts (blue-green, rolling, marketplace, demo
        # instances). Adding -v there is almost certainly safe - it removes
        # only anonymous volumes - but changing container-removal behaviour on
        # production machines is a reviewed deployment change, not something a
        # test-tooling ratchet gets to force. If someone makes that change
        # deliberately, delete the matching line here in the same diff.
        scripts/utilities/blue-green-deployment.sh|\
        scripts/utilities/rolling-deployment.sh|\
        scripts/utilities/deploy-with-zero-downtime.sh|\
        scripts/marketplace/deploy-with-metering.sh|\
        scripts/deployment/deploy-demo-compose.sh|\
        scripts/multi-tenant/deploy-client.sh) continue ;;
      esac
      LC_ALL=C grep -n -E 'docker[[:space:]]+rm|"rm",[[:space:]]*"-[a-zA-Z]+"' "$f" 2>/dev/null \
      | while IFS= read -r hit; do
          # ONE strip, not two. grep -n output is `NN:code`; the first
          # ${hit#*:} removes the line number. A second strip removed the code
          # up to its OWN first colon, so any offending line containing a
          # colon after the command - `2>&1 | grep -v "Error: ..."`, or an
          # inline `# note:` - was invisible. R3 measured it: the ratchet's
          # primary rule had a reproducible false negative on exactly the kind
          # of line somebody adds next week. Pinned as a fixture below.
          text=${hit#*:}
          # Strip a leading line comment marker, then re-test. A comment that
          # merely NAMES the bad form is prose; one that is a runnable
          # instruction is not, and those were converted by hand instead.
          # A YAML `name:` value is prose too - the lint job that RUNS this
          # guard names it "Lint - docker rm must remove anonymous volumes",
          # and a guard that flags its own job title can never pass.
          if printf '%s' "$text" | LC_ALL=C grep -qE '^[[:space:]-]*name:'; then
            continue
          fi
          stripped=$(printf '%s' "$text" | sed -E 's@^[[:space:]]*(//|#)[[:space:]]*@@')
          if printf '%s' "$stripped" | LC_ALL=C grep -qE '`docker rm -f`|docker rm -f. removes'; then
            continue
          fi
          # ANY `docker rm` - force or not - in either the shell form or the
          # exec.Command form. The first version matched only -f, reasoning a
          # plain rm "fails on a running container rather than silently
          # orphaning anything"; measured false: stop-then-rm succeeds and
          # orphans the volume identically (+1), and that exact sequence was
          # live in scripts/debugging/validate-all-migrations.sh.
          if printf '%s' "$text" | LC_ALL=C grep -qE 'docker[[:space:]]+rm([[:space:]]|$)|"rm",'; then
            # ...one that already removes volumes is fine, in any flag order
            # or the long form. The -v must belong to the `docker rm` COMMAND:
            # the check is scoped to the segment after `docker rm` and before
            # the first pipe, because this fixture's own first version
            # searched the whole line and a downstream `grep -v` satisfied it
            # - the guard's added test caught the guard's own widened matcher,
            # which is the reason both directions get fixtures.
            rmseg=${text#*docker rm}
            rmseg=${rmseg%%|*}
            case "$text" in *'"rm",'*) rmseg=${text#*\"rm\",}; rmseg=${rmseg%%)*} ;; esac
            if printf '%s' "$rmseg" | LC_ALL=C grep -qE '\-[a-zA-Z]*v|--volumes'; then
              continue
            fi
            printf '%s:%s\n' "$f" "$hit"
          fi
        done
    done
}

# scan_tmpfs ROOT - ephemeral postgres servers started without a mount at the
# declared VOLUME path. Statement-aware: line continuations are joined first.
scan_tmpfs() {
  local root="$1"
  find "$root" \
    \( -name .git -o -name node_modules -o -name vendor -o -name build \) -prune -o \
    \( -name '*.sh' -o -name '*.yml' -o -name '*.yaml' -o -name '*.go' \) -print 2>/dev/null \
  | LC_ALL=C sort \
  | while IFS= read -r f; do
      case "${f#"$root"/}" in
        docs/*|*/docs/*) continue ;;
        scripts/lint-docker-rm-removes-volumes.sh) continue ;;
        # Persistent demo databases: a tmpfs here is DATA LOSS, not tidiness.
        scripts/multi-tenant/deploy-client.sh) continue ;;
      esac
      # Join line continuations so a multi-line `docker run` is one statement,
      # then look at each resulting logical line.
      perl -0pe 's/\\\s*\n\s*/ /g' "$f" 2>/dev/null \
      | LC_ALL=C grep -nE 'docker[[:space:]]+(run|create)|"(run|create)",' 2>/dev/null \
      | while IFS= read -r hit; do
          text=${hit#*:}
          # Line comments are prose here exactly as in scan() - the
          # connectors integration doc carries `docker run` instructions in
          # `//` comments, and flagging an instruction that was already
          # corrected by hand would be a false positive.
          printf '%s' "$text" | LC_ALL=C grep -qE '^[[:space:]]*(//|#)' && continue
          # A postgres SERVER only, and postgres ONLY on purpose: the rule
          # pairs an image with ITS declared data path, and this repo's
          # ephemeral servers are all postgres. Widening to mysql/mongo/redis
          # without their paths (/var/lib/mysql, /data/db, /data) would flag
          # them against a postgres path they never mount - measured as three
          # false positives before this comment existed. The image match
          # covers a bare `postgres`, `postgres:latest` and pinned tags (R3:
          # `postgres:[0-9]` alone let all but the pinned form through), and
          # must NOT match the `postgres://` URL scheme in a DSN env var.
          # No lookahead in POSIX ERE, and none needed: a tag cannot contain
          # a slash, so `postgres://` fails both branches - the bare form
          # because the next char is `:`, the tagged form because `/` is not a
          # tag character.
          printf '%s' "$text" | LC_ALL=C grep -qE '(^|[[:space:]"\x27])postgres(:[A-Za-z0-9._-]+)?([[:space:]"\x27]|$)' || continue
          printf '%s' "$text" | LC_ALL=C grep -qE '(^|[[:space:]])(psql|pg_dump|pg_restore|pg_isready)([[:space:]]|$)' && continue
          # Detached servers only, either spelling - and `docker create` is
          # ALWAYS a server start (it exists to be started later), so it
          # needs no -d. R3 measured create+start leaking identically.
          if printf '%s' "$text" | LC_ALL=C grep -qE 'docker[[:space:]]+run|"run",'; then
            printf '%s' "$text" | LC_ALL=C grep -qE '(^|[[:space:]])(-d|--detach)([[:space:]]|$)|"-d"|"--detach"' || continue
          fi
          # Already mounted at the data dir - fine, whatever the mount type.
          printf '%s' "$text" | LC_ALL=C grep -q '/var/lib/postgresql/data' && continue
          # ...and the ephemeral label must be present too, or orphaned
          # containers are unreapable by exact match. Enforcing it here is
          # what stops the NEXT site being tmpfs'd but unlabelled.
          if printf '%s' "$text" | LC_ALL=C grep -q 'axonflow.test.ephemeral=1'; then
            printf '%s:%s [has the label but no data-dir mount]\n' "$f" "$hit"
          else
            printf '%s:%s\n' "$f" "$hit"
          fi
        done
    done
}

run_lint() {
  local root="${1:-.}" found tmpfs_found rc=0
  found=$(scan "$root")
  tmpfs_found=$(scan_tmpfs "$root")
  if [ -n "$tmpfs_found" ]; then
    echo "❌ an ephemeral postgres container has no mount at /var/lib/postgresql/data:"
    printf '%s\n' "$tmpfs_found" | sed 's/^/   /'
    cat <<'EOF'

postgres declares that path as a VOLUME, so without a mount there Docker
creates an ANONYMOUS volume per container. `docker rm -fv` reclaims it ONLY if
the cleanup runs - it does not on a -timeout kill, a Ctrl-C or a panic.

Add:  --tmpfs /var/lib/postgresql/data:rw,size=1g
Measured: 46 MB fresh initdb (69 MB with the full core migration chain), so 1g is ~15x headroom, and the data is
worthless the moment the test ends.

If this is a PERSISTENT database rather than a test fixture, a tmpfs would
destroy its data - exclude it by path in scan_tmpfs and say why.
EOF
    rc=1
  fi
  if [ -z "$found" ]; then
    [ "$rc" = 0 ] && echo "✅ every 'docker rm -f' also removes its anonymous volumes (-fv), and every ephemeral postgres mounts its data dir."
    return "$rc"
  fi
  echo "❌ docker rm force-removes a container WITHOUT removing its anonymous volume:"
  printf '%s\n' "$found" | sed 's/^/   /'
  cat <<'EOF'

`postgres`, `mysql`, `mongo` and `redis` declare a VOLUME, so each container
gets an anonymous volume that `docker rm -f` ORPHANS. They are unreachable by
name and nothing collects them: one developer daemon reached 52.84 GB across
680 of them in two days, while `docker ps -a` read 0 the whole time.

Use `docker rm -fv` (or `--volumes`). It removes ONLY anonymous volumes -
named volumes such as a compose stack's `postgres-data` are never touched -
so there is no case where `-f` is correct and `-fv` is not.
EOF
  return 1
}

self_test() {
  local pass=0 fail=0
  # NOT `local`: the EXIT trap fires after this function returns, when a
  # function-scoped variable is already gone and `set -u` would abort.
  SELFTEST_TMP=$(mktemp -d)
  tmp="$SELFTEST_TMP"
  trap 'rm -rf "${SELFTEST_TMP:-}"' EXIT

  mk() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; }
  check() {
    local desc="$1" want="$2" root="$3" got
    scan "$root" >/dev/null 2>&1
    run_lint "$root" >/dev/null 2>&1; got=$?
    if [ "$got" = "$want" ]; then
      echo "  ok   $desc (rc=$got)"; pass=$((pass+1))
    else
      echo "  FAIL $desc (rc=$got, want $want)"; fail=$((fail+1))
    fi
  }

  # A clean tree.
  local ok="$tmp/ok"
  mk "$ok/scripts/a.sh" 'docker rm -fv "$PG"'
  check "a -fv shell site passes" 0 "$ok"

  # The bug, in each form.
  local sh="$tmp/sh"; cp -R "$ok" "$sh"
  mk "$sh/runtime-e2e/x/test.sh" 'docker rm -f "$PG" >/dev/null 2>&1'
  check "a bare -f shell site is caught" 1 "$sh"

  local go="$tmp/go"; cp -R "$ok" "$go"
  mk "$go/platform/a_test.go" '_ = exec.Command("docker", "rm", "-f", containerName).Run()'
  check "a bare -f exec.Command site is caught" 1 "$go"

  local gofv="$tmp/gofv"; cp -R "$ok" "$gofv"
  mk "$gofv/platform/a_test.go" '_ = exec.Command("docker", "rm", "-fv", containerName).Run()'
  check "a -fv exec.Command site passes" 0 "$gofv"

  # Flag ORDER must not matter, and neither must the long form.
  local vf="$tmp/vf"; cp -R "$ok" "$vf"
  mk "$vf/scripts/b.sh" 'docker rm -vf "$PG"'
  check "-vf (reversed order) passes" 0 "$vf"

  local long="$tmp/long"; cp -R "$ok" "$long"
  mk "$long/scripts/b.sh" 'docker rm --volumes -f "$PG"'
  check "--volumes long form passes" 0 "$long"

  # THE FALSE POSITIVE THIS GUARD MUST NOT HAVE. approletest/setup.go's own
  # comment contains the bad string while explaining why it is bad.
  local prose="$tmp/prose"; cp -R "$ok" "$prose"
  mk "$prose/platform/setup.go" '		// `docker rm -f` removes the container while orphaning it. Each one holds'
  check "prose EXPLAINING the bad form does not trip it" 0 "$prose"

  # A NON-force remove orphans the volume exactly like -f does. The first
  # version of this guard excluded it, reasoning "it fails on a running
  # container rather than silently orphaning anything" - R3 measured that to
  # be false: `docker stop X && docker rm X` succeeds and leaves the anonymous
  # volume behind (+1, verified), and that stop-then-rm sequence is precisely
  # what scripts/debugging/validate-all-migrations.sh was doing while both of
  # this guard's rules looked the other way.
  local plain="$tmp/plain"; cp -R "$ok" "$plain"
  mk "$plain/scripts/c.sh" 'docker rm "$PG" || true'
  check "a NON-force 'docker rm' without -v is caught too" 1 "$plain"

  # The false negative R3 reproduced: an offending line whose first colon sits
  # AFTER the command. The old double-strip ate the code up to that colon.
  local colon="$tmp/colon"; cp -R "$ok" "$colon"
  mk "$colon/scripts/d.sh" 'docker rm -f "$PG" 2>&1 | grep -v "Error: No such container"'
  check "an offending line containing a later COLON is still caught" 1 "$colon"

  # --- the tmpfs rule ---------------------------------------------------
  #
  # BOTH directions matter more than usual here: a false POSITIVE on a
  # persistent database would push someone to mount a tmpfs over real data.
  local nomount="$tmp/nomount"; cp -R "$ok" "$nomount"
  mk "$nomount/runtime-e2e/y/test.sh" 'docker run -d --name "$PG" -e POSTGRES_PASSWORD=p postgres:15'
  check "an ephemeral postgres with NO data-dir mount is caught" 1 "$nomount"

  local mounted="$tmp/mounted"; cp -R "$ok" "$mounted"
  mk "$mounted/runtime-e2e/y/test.sh" 'docker run -d --name "$PG" --tmpfs /var/lib/postgresql/data:rw,size=1g -e POSTGRES_PASSWORD=p postgres:15'
  check "a tmpfs at the data dir passes" 0 "$mounted"

  # A named volume or a bind is equally effective at suppressing the anonymous
  # one, so the rule is "any mount", not "a tmpfs".
  local namedvol="$tmp/namedvol"; cp -R "$ok" "$namedvol"
  mk "$namedvol/runtime-e2e/y/test.sh" 'docker run -d --name "$PG" -v pgdata:/var/lib/postgresql/data postgres:15'
  check "a NAMED volume at the data dir also passes" 0 "$namedvol"

  # THE MULTI-LINE CASE. A line-oriented pass missed three real sites here,
  # including one whose image sits two lines below the `docker run`. Same shape
  # that defeated the #3334 guard and then the #3408 one.
  local multiline="$tmp/multiline"; cp -R "$ok" "$multiline"
  mk "$multiline/runtime-e2e/y/test.sh" 'docker run -d --name "$PG" \\'
  printf '%s\n' '  -e POSTGRES_PASSWORD=p \\' '  postgres:15' >> "$multiline/runtime-e2e/y/test.sh"

  check "a MULTI-LINE docker run is caught (continuations joined)" 1 "$multiline"

  # A psql CLIENT writes no data directory - nothing to mount, nothing to leak.
  local client="$tmp/client"; cp -R "$ok" "$client"
  mk "$client/scripts/m.sh" 'docker run --rm -e PGPASSWORD=x postgres:14 psql -h host -c "select 1"'
  check "a psql CLIENT is not flagged" 0 "$client"

  # THE FALSE POSITIVE THAT WOULD CAUSE DATA LOSS. Persistent demo databases
  # are excluded by path; mounting a tmpfs over them destroys real data.
  local persist="$tmp/persist"; cp -R "$ok" "$persist"
  mk "$persist/scripts/multi-tenant/deploy-client.sh" 'docker run -d --name ecommerce-db --restart unless-stopped postgres:15'
  check "a PERSISTENT database is excluded, not flagged" 0 "$persist"

  # R3 round 2 gaps, each measured as an evasion before being closed:
  local notag="$tmp/notag"; cp -R "$ok" "$notag"
  mk "$notag/runtime-e2e/y/test.sh" 'docker run -d --name "$PG" -e POSTGRES_PASSWORD=p postgres'
  check "a BARE-tag postgres (no :NN) is caught" 1 "$notag"

  local detach="$tmp/detach"; cp -R "$ok" "$detach"
  mk "$detach/runtime-e2e/y/test.sh" 'docker run --detach --name "$PG" -e POSTGRES_PASSWORD=p postgres:15'
  check "the --detach long form is caught" 1 "$detach"

  local created="$tmp/created"; cp -R "$ok" "$created"
  mk "$created/runtime-e2e/y/test.sh" 'docker create --name "$PG" -e POSTGRES_PASSWORD=p postgres:15'
  check "docker create (started later) is caught" 1 "$created"

  # False positives that round closed in the SAME sweep - the widened match
  # must not fire on a DSN env var or on a commented instruction:
  local dsn="$tmp/dsn"; cp -R "$ok" "$dsn"
  mk "$dsn/runtime-e2e/y/test.sh" 'docker run -d --name "$ORCH" -e DATABASE_URL="postgres://u:p@host:5432/db" my-orchestrator:1'
  check "a postgres:// DSN env var is NOT an image match" 0 "$dsn"

  local cmt="$tmp/cmt"; cp -R "$ok" "$cmt"
  mk "$cmt/platform/x_test.go" '//	docker run -d --name pg-test -p 5432:5432 postgres:15'
  check "a commented docker-run instruction is not flagged" 0 "$cmt"

  # KNOWN LIMIT 1, pinned as a negative fixture: a variable image is invisible.
  # If someone closes the class properly this row FAILS, which is the prompt
  # to delete it and the KNOWN LIMITS entry together.
  local varimg="$tmp/varimg"; cp -R "$ok" "$varimg"
  mk "$varimg/scripts/m.sh" 'POSTGRES_IMAGE="postgres:15-alpine"
docker run -d --name "$C" "$POSTGRES_IMAGE"'
  check "KNOWN LIMIT: an image held in a VARIABLE is NOT caught" 0 "$varimg"

  # The production-deploy class exclusion on the rm rule: a plain rm inside
  # one of the excluded deployment scripts must not be flagged, because
  # changing removal behaviour on live hosts is a reviewed deployment change.
  local prod="$tmp/prod"; cp -R "$ok" "$prod"
  mk "$prod/scripts/utilities/blue-green-deployment.sh" 'docker rm $old_container > /dev/null 2>&1 || true'
  check "a PRODUCTION deployment script is excluded from the rm rule" 0 "$prod"

  # docs/ is prose for humans.
  local docs="$tmp/docs"; cp -R "$ok" "$docs"
  mk "$docs/docs/guide.md" 'docker rm -f mycontainer'
  mk "$docs/docs/guide.sh" 'docker rm -f mycontainer'
  check "docs/ is excluded" 0 "$docs"

  # ...and the real repository must pass, or this is a guard nobody can land.
  check "the real repository passes" 0 "."

  # Anti-vacuity: the scan must actually be LOOKING at the real tree, not
  # returning empty because the walk found nothing.
  local n
  n=$(find . \( -name .git -o -name node_modules \) -prune -o \( -name '*.sh' -o -name '*.go' \) -print 2>/dev/null | wc -l | tr -d ' ')
  if [ "$n" -gt 100 ]; then
    echo "  ok   the walk sees the real tree ($n files)"; pass=$((pass+1))
  else
    echo "  FAIL the walk saw only $n files - every assertion above is vacuous"; fail=$((fail+1))
  fi

  echo ""
  echo "=== SELF-TEST: $((pass+fail)) assertions, $fail failures ==="
  [ "$fail" -eq 0 ]
}

# The DEFAULT root is the repository this script lives in, never the CWD.
# The sibling guard documents the trap at its own top: run from a
# subdirectory, a CWD-rooted scan sees a fraction of the tree and prints an
# all-clear built from the files it happened to be standing near. R3 measured
# it here: from platform/ the offender was invisible and the self-test's
# anti-vacuity row cheerfully certified the wrong root.
REPO_ROOT_DEFAULT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "${1:-}" in
  --self-test) self_test ;;
  *) run_lint "${1:-$REPO_ROOT_DEFAULT}" ;;
esac
