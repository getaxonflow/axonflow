#!/usr/bin/env bash
# Regression guard: no NEW push-to-main job may be invisible when it fails.
#
# THE BUG CLASS (#3730). `partner ECS template drift-guard` was red on
# axonflow-enterprise main for 3.5 days - 23 consecutive failed runs, from
# 31b963cb5 (2026-09-01T05:30Z) to ca9fccefd (2026-09-04T06:39Z) - while every
# PR board in that window was legitimately green. Nine PRs merged onto a red
# main and nobody, including the session driving the train, saw it.
#
# Three properties combine, and it takes all three:
#
#   1. The job is NOT a required status-check context, so it gates no merge -
#      and, more to the point, nothing re-verifies the property on the PR tier
#      where it would have to pass again on every change.
#   2. Its enforcing arm is `push: branches: [main]`, so its verdict lands on
#      a commit rather than on a PR - and nobody reads a merged commit.
#   3. That push arm carries a path filter, so it reports on an ARBITRARY
#      SUBSET of main commits. This is the part that makes the failure
#      invisible rather than merely unread: main's TIP usually carries no
#      verdict at all for the job, and `gh api .../commits/main/check-runs`
#      reports absence of the context, which every tool and every human reads
#      as health.
#
# Measured on the real case: `ca9fccefd` got a verdict only because it happened
# to touch an unrelated runtime-e2e fixture matching '**/docker-compose*.yml'.
# The three commits merged after it matched none of infra-validation.yml's 34
# push paths, so `gh run list --workflow infra-validation.yml --commit <sha>`
# returned zero runs for each, and main read green while carrying a stale red.
#
# WHAT THIS TEST DOES. It censuses the class and holds the population to
# tests/regression-test-required/lib/main-guard-dispositions.tsv in BOTH
# directions. Every member must be dispositioned WATCH (the freshness reader
# fails on a stale red) or ADVISORY (it reports and does not fail), each with
# a reason. A new member fails on its own PR instead of joining a population
# nobody is counting.
#
# EXACT IN BOTH DIRECTIONS, deliberately. An unexpected member is a new blind
# spot. A dispositioned entry that is NO LONGER a member is also a failure: it
# means the job was made visible (promoted to a required context, or its path
# filter dropped) and the entry must go in that same diff. A list checked only
# in the "too many" direction grows monotonically and stops describing the tree.
#
# WHY THERE IS NO `needs:`-CLOSURE EXEMPTION. See the header of
# scripts/ci/lib/main_guard_census.py. Short version, measured: the required
# `Security Scan Summary` `needs:` seven jobs and compares the results of
# four, so crediting a job as "guarded" because a required context needs it
# was wrong three times out of seven on the only workflow that has such a
# summary. "A required summary reads this job's result" is now a claim a human
# makes in the reason column of the disposition file, where a reviewer can
# check it, rather than a property inferred by machinery that cannot see it.
#
# WHAT THIS TEST IS NOT. It is not the reader. The reader is
# scripts/ci/check-main-guard-freshness.sh, which walks main's ancestors and
# fails on a stale red; this test makes sure the set it must watch cannot grow,
# shrink, or lose its reasons silently.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

REQUIRED_FILE="tests/regression-test-required/lib/required-contexts-enterprise.txt"
DISPOSITIONS="tests/regression-test-required/lib/main-guard-dispositions.tsv"
CENSUS="scripts/ci/lib/main_guard_census.py"
WORKFLOW_DIR="${WORKFLOW_DIR:-.github/workflows}"

for f in "$REQUIRED_FILE" "$DISPOSITIONS" "$CENSUS"; do
  if [ ! -f "$f" ]; then
    echo "FAIL: $f is missing - the census cannot run"
    exit 1
  fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

run_census() { # <workflow_dir> <allowlist> [repo]
  python3 "$CENSUS" --workflow-dir "$1" --required-file "$REQUIRED_FILE" \
    --allow "$2" --repo "${3:-getaxonflow/axonflow-enterprise}"
}

# ---------------------------------------------------------------------------
# The reviewed dispositions, parsed once. Keys are `file :: job_id` and not
# display names, because two cache-seed.yml jobs share the display name
# `Seed ${{ matrix.name }}` and build-community.yml's summary name is an
# expression - a display-name key could not tell those apart.
# ---------------------------------------------------------------------------
grep -v '^[[:space:]]*#' "$DISPOSITIONS" | sed '/^[[:space:]]*$/d' > "$work/disp"
n_disp=$(wc -l < "$work/disp" | tr -d ' ')
if [ "${n_disp:-0}" -lt 5 ]; then
  echo "FAIL: read only ${n_disp:-0} disposition(s) from $DISPOSITIONS - it is not being read"
  exit 1
fi

status=0

# Well-formedness: three tab-separated fields, a known token, a non-empty
# reason. A blank reason is the failure mode this file exists to prevent - a
# member silenced without anyone having to say why.
bad=$(awk -F'\t' '
  NF != 3                                  { print "  " $1 " -> expected 3 tab-separated fields, got " NF; next }
  $2 != "WATCH" && $2 != "ADVISORY"        { print "  " $1 " -> disposition \"" $2 "\" is not WATCH or ADVISORY"; next }
  $3 ~ /^[[:space:]]*$/                    { print "  " $1 " -> empty reason" }
' "$work/disp")
if [ -n "$bad" ]; then
  echo "FAIL: malformed entries in $DISPOSITIONS:"
  printf '%s\n' "$bad"
  status=1
fi

# Duplicate keys would make the reader's first-match lookup silently pick one.
dupes=$(cut -f1 "$work/disp" | sort | uniq -d)
if [ -n "$dupes" ]; then
  echo "FAIL: duplicate key(s) in $DISPOSITIONS:"
  printf '%s\n' "$dupes" | sed 's/^/  /'
  status=1
fi

# ---------------------------------------------------------------------------
# The live census.
# ---------------------------------------------------------------------------
out=$(run_census "$WORKFLOW_DIR" "") || {
  echo "FAIL: the census program did not run to a verdict"
  printf '%s\n' "$out"
  exit 1
}

counts=$(printf '%s\n' "$out" | awk -F'\t' '$1=="COUNTS"{print $2, $3, $4, $5, $6, $7}')
read -r n_files n_pushmain n_filtered n_jobs n_required n_paths <<<"$counts"
printf '%s\n' "$out" | awk -F'\t' '$1=="MEMBER"{print $2}'      | sed '/^$/d' | sort > "$work/members"
printf '%s\n' "$out" | awk -F'\t' '$1=="CONTEXT"{print $2"\t"$3}' | sed '/^$/d' > "$work/contexts"
unresolved=$(printf '%s\n' "$out" | awk -F'\t' '$1=="UNRESOLVED"{print $2"  ("$3")"}')
printf '%s\n' "$out" | awk -F'\t' '$1=="UNWATCHABLE"{print $2}' | sed '/^$/d' | sort > "$work/unwatchable"

# -------------------------------------------------------------------------
# Anti-vacuity floors. Each one is a way this guard could pass while having
# verified nothing: a parse regression, a schema change, or a resolver that
# credits everything would all otherwise read as "class is empty, all clear".
# The floors are LOWER BOUNDS with headroom, so ordinary growth does not red
# them; the exactness check below is what pins today's set.
# -------------------------------------------------------------------------
floor() { # <label> <value> <min>
  if [ "${2:-0}" -lt "$3" ]; then
    echo "FAIL: $1 - got ${2:-0}, expected at least $3. The census is not reading the tree."
    exit 1
  fi
}
floor "workflow files censused"                  "$n_files"    100
floor "workflows firing on push to main"         "$n_pushmain" 5
floor "of those, carrying a path filter"         "$n_filtered" 3
floor "push path-filter entries across the tree" "$n_paths"    20
# The positive control for the required-context subtraction. `security.yml ::
# security-summary` produces `Security Scan Summary`, which IS required, so it
# must be counted here and must NOT appear as a member. If this were zero the
# subtraction would be inert and every verdict below meaningless - and the
# fixture assertions further down drive the same subtraction both ways.
floor "jobs recognised as producing a REQUIRED context" "$n_required" 1

echo "ok: censused ${n_files} workflow files; ${n_pushmain} fire on push to main, ${n_filtered} of them filtered; ${n_jobs} jobs examined"
echo "ok: ${n_required} job(s) recognised as producing a required context and subtracted"

if [ -n "$unresolved" ]; then
  echo ""
  echo "FAIL: job(s) whose display name is an expression that COULD evaluate to a"
  echo "      required status-check context. The census cannot rule them in or out,"
  echo "      and guessing in the permissive direction is how a class member hides:"
  printf '%s\n' "$unresolved" | sed 's/^/  /'
  echo ""
  echo "      Either give the job a literal name, or add its 'file :: job_id' to the"
  echo "      allow-list argument with the reason it cannot produce that context."
  status=1
fi

# Direction 1: a member with no disposition - a NEW blind spot.
cut -f1 "$work/disp" | sort > "$work/disp_keys"
extra=$(comm -23 "$work/members" "$work/disp_keys")
# Direction 2: a dispositioned entry that is no longer a member - a STALE row.
gone=$(comm -13 "$work/members" "$work/disp_keys")

if [ -n "$extra" ]; then
  echo ""
  echo "FAIL: new push-to-main job(s) that are not a required context, under a"
  echo "      path-filtered push trigger. When one of these fails, main's tip"
  echo "      usually carries NO verdict for it, so check-runs on main reports"
  echo "      absence - which reads as health. This is the #3730 defect:"
  printf '%s\n' "$extra" | sed 's/^/  /'
  echo ""
  echo "      PREFER MAKING IT VISIBLE over dispositioning it. The strongest fix is"
  echo "      to have the property re-verified on the pull-request tier by a"
  echo "      REQUIRED context, so it must pass again on every change. Otherwise add"
  echo "      the exact 'file :: job_id' to $DISPOSITIONS"
  echo "      as WATCH (the freshness reader fails on a stale red on main) or"
  echo "      ADVISORY (it reports and does not fail) WITH A REASON. Do not write"
  echo "      'a required summary needs: it' unless you have read that summary's own"
  echo "      script and it compares this job's result - four of Security Scan"
  echo "      Summary's seven dependencies are compared and three are only echoed."
  status=1
fi

if [ -n "$gone" ]; then
  echo ""
  echo "FAIL: disposition row(s) that are no longer in the class:"
  printf '%s\n' "$gone" | sed 's/^/  /'
  echo ""
  echo "      This is usually GOOD NEWS - the job was made a required context,"
  echo "      lost its path filter, or was removed. Delete the row in the same"
  echo "      diff. A list checked in only one direction grows forever and stops"
  echo "      describing the tree."
  status=1
fi

# A WATCH member whose display name cannot be resolved to a literal is a
# SILENT hole: the reader matches verdicts by context name, so it would watch
# nothing at all. An ADVISORY member being unwatchable is harmless, because
# nothing was going to fail on it.
watch_unwatchable=$(awk -F'\t' '$2=="WATCH"{print $1}' "$work/disp" | sort \
                    | comm -12 - "$work/unwatchable")
if [ -n "$watch_unwatchable" ]; then
  echo ""
  echo "FAIL: WATCH member(s) whose check-run name the census cannot resolve to a"
  echo "      literal, so the freshness reader would silently watch nothing:"
  printf '%s\n' "$watch_unwatchable" | sed 's/^/  /'
  echo ""
  echo "      Give the job a literal name, expand its matrix declaration so the"
  echo "      names are derivable, or disposition it ADVISORY with that reason."
  status=1
fi

# A check-run CONTEXT produced by both a WATCH and an ADVISORY member cannot be
# exempted: verdicts are keyed on the context name, so the ADVISORY row would
# silence the WATCH one. `Detect Changes` is produced by TWO different jobs
# (build-community.yml and security.yml), which is how this was noticed.
collisions=$(awk -F'\t' 'NR==FNR{d[$1]=$2;next} {print d[$1]"\t"$2}' \
               "$work/disp" "$work/contexts" \
             | sort -u | awk -F'\t' '{seen[$2]=seen[$2]" "$1} END{for(c in seen) if (seen[c] ~ /WATCH/ && seen[c] ~ /ADVISORY/) print "  " c " <-" seen[c]}')
if [ -n "$collisions" ]; then
  echo ""
  echo "FAIL: check-run context(s) produced by both a WATCH and an ADVISORY member."
  echo "      The reader keys verdicts on the context NAME, so the ADVISORY row"
  echo "      cannot exempt anything - it would only make the WATCH row's"
  echo "      disposition unenforceable and the file misleading:"
  printf '%s\n' "$collisions"
  status=1
fi

if [ "$status" -ne 0 ]; then
  exit 1
fi

n_members=$(wc -l < "$work/members" | tr -d ' ')
n_watch=$(awk -F'\t' '$2=="WATCH"' "$work/disp" | wc -l | tr -d ' ')
n_adv=$(awk -F'\t' '$2=="ADVISORY"' "$work/disp" | wc -l | tr -d ' ')
echo "ok: the invisible-on-main class is exactly the ${n_members} dispositioned member(s): ${n_watch} WATCH, ${n_adv} ADVISORY"

# -------------------------------------------------------------------------
# Fixture self-tests. The census above is a census; these drive the SAME
# module over synthetic workflows so each decision it makes is pinned by a
# behavioural assertion rather than by the live tree happening to agree.
# -------------------------------------------------------------------------
fx_write() { cat > "$work/fx/fx.yml"; }
mkdir -p "$work/fx"
fx_fails=0
fx_assert() { # <label> <grep-mode: has|hasnt> <pattern> <census-output>
  local label="$1" mode="$2" pat="$3" out="$4"
  if [ "$mode" = has ]; then
    printf '%s\n' "$out" | grep -qx "$pat" && { echo "ok: fixture - $label"; return 0; }
  else
    printf '%s\n' "$out" | grep -qx "$pat" || { echo "ok: fixture - $label"; return 0; }
  fi
  echo "FAIL: fixture - $label"
  printf '%s\n' "$out" | sed 's/^/    /'
  fx_fails=$((fx_fails + 1))
}

# 1. A required display name is subtracted; its sibling is a member. One
#    fixture, both verdicts, so neither can be a coincidence - and this is the
#    negative control for the `n_required` floor above.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
    paths: ['src/**']
jobs:
  required_one:
    name: Test Summary
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
  loner:
    name: loner
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "a job producing a REQUIRED context is not a member" hasnt "MEMBER	fx.yml :: required_one" "$fx"
fx_assert "its non-required sibling IS a member"                has   "MEMBER	fx.yml :: loner"        "$fx"

# ...and rename the required one: it must become a member. Without this, the
# subtraction could be exempting everything and assertion 1 would not see it.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
    paths: ['src/**']
jobs:
  required_one:
    name: Test Summary RENAMED
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "renaming the required context makes the job a member" has "MEMBER	fx.yml :: required_one" "$fx"

# 2. No path filter on the push arm => out of the class, because the job then
#    reports on EVERY main commit and a red is visible at main's tip.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
jobs:
  loner:
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "an unfiltered push-to-main arm is out of the class" hasnt "MEMBER	fx.yml :: loner" "$fx"

# 3. `paths-ignore:` filters the arm exactly as `paths:` does. Reading only
#    `paths:` reported such an arm as unfiltered and dropped the whole
#    workflow OUT of the class - the dangerous direction, and a hole the first
#    draft of this census had.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
    paths-ignore: ['docs/**']
jobs:
  loner:
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "a paths-ignore push arm IS path-filtered" has "MEMBER	fx.yml :: loner" "$fx"

# 4. A push arm naming only tags is not a push-to-main arm at all.
fx_write <<'YAML'
name: fx
on:
  push:
    tags: ['v*']
    paths: ['src/**']
jobs:
  loner:
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "a tags-only push trigger is not push-to-main" hasnt "MEMBER	fx.yml :: loner" "$fx"

# 5. A SCALAR `branches:` must be matched as a branch name, not as a substring.
#    `"main" not in "maintenance"` is False in Python, so the first draft put a
#    `branches: maintenance` workflow in the class.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: main
    paths: ['src/**']
jobs:
  loner:
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "a scalar 'branches: main' fires on main" has "MEMBER	fx.yml :: loner" "$fx"

fx_write <<'YAML'
name: fx
on:
  push:
    branches: maintenance
    paths: ['src/**']
jobs:
  loner:
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "a scalar 'branches: maintenance' does NOT fire on main" hasnt "MEMBER	fx.yml :: loner" "$fx"

# ...and a GLOB in `branches:` must be matched as a glob. GitHub accepts
# patterns there, so an exact string comparison would miss a workflow whose
# push arm is written `branches: ['ma*']` - the class census bounded by the
# shape searched for, again.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: ['ma*']
    paths: ['src/**']
jobs:
  loner:
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "a glob 'branches: [ma*]' fires on main" has "MEMBER	fx.yml :: loner" "$fx"

# 6. `branches-ignore:` with no `branches:` fires on main unless main is
#    itself ignored.
fx_write <<'YAML'
name: fx
on:
  push:
    branches-ignore: ['gh-pages']
    paths: ['src/**']
jobs:
  loner:
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "branches-ignore not naming main still fires on main" has "MEMBER	fx.yml :: loner" "$fx"

fx_write <<'YAML'
name: fx
on:
  push:
    branches-ignore: ['main']
    paths: ['src/**']
jobs:
  loner:
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "branches-ignore naming main does NOT fire on main" hasnt "MEMBER	fx.yml :: loner" "$fx"

# 7. The repo-conditional display name must be evaluated per tree, both ways.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
    paths: ['src/**']
jobs:
  summary:
    name: ${{ github.repository == 'getaxonflow/axonflow' && 'Test Summary' || 'Test Summary (Community)' }}
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx_ent=$(run_census "$work/fx" "")
fx_com=$(run_census "$work/fx" "" "getaxonflow/axonflow")
fx_assert "a repo-conditional name is a member in the enterprise tree"      has   "MEMBER	fx.yml :: summary" "$fx_ent"
fx_assert "the same name resolves to the required context in the mirror"    hasnt "MEMBER	fx.yml :: summary" "$fx_com"

# 8. A `${{ matrix.<key> }}` name is EXPANDED against the job's own matrix, so
#    a matrix job's check-runs are watchable by name. Left unexpanded, the two
#    real cache-seed.yml jobs were reported as unwatchable, which is a
#    permanent silent hole for anything ever dispositioned WATCH.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
    paths: ['src/**']
jobs:
  legs:
    name: Seed ${{ matrix.name }}
    strategy:
      matrix:
        include:
          - name: alpha
          - name: beta
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
  listform:
    name: Lint ${{ matrix.go }}
    strategy:
      matrix:
        go: ['1.23', '1.24']
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "an include: matrix name expands, leg 1"  has "CONTEXT	fx.yml :: legs	Seed alpha"     "$fx"
fx_assert "an include: matrix name expands, leg 2"  has "CONTEXT	fx.yml :: legs	Seed beta"      "$fx"
fx_assert "a list-valued matrix name expands too"   has "CONTEXT	fx.yml :: listform	Lint 1.23" "$fx"
fx_assert "an expanded matrix job is not unwatchable" hasnt "UNWATCHABLE	fx.yml :: legs	Seed \${{ matrix.name }}" "$fx"

# ...and a matrix key with no declaration cannot be expanded, so the job is
# reported UNWATCHABLE rather than credited with a name it does not have.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
    paths: ['src/**']
jobs:
  legs:
    name: Seed ${{ matrix.undeclared }}
    strategy:
      matrix:
        include:
          - name: alpha
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "an undeclared matrix key is UNWATCHABLE, not invented" has "UNWATCHABLE	fx.yml :: legs	Seed \${{ matrix.undeclared }}" "$fx"
fx_assert "...and is still reported as a member"                  has "MEMBER	fx.yml :: legs" "$fx"

# 9. An unevaluable expression that COULD match a required context must fail
#    loudly, not be quietly credited or quietly listed as an ordinary member.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
    paths: ['src/**']
jobs:
  sneaky:
    name: Test ${{ github.event_name }}
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
if ! printf '%s\n' "$fx" | grep -q "^UNRESOLVED	fx.yml :: sneaky"; then
  echo "FAIL: fixture - an expression name globbing to 'Test *' (which matches the required"
  echo "      'Test Summary') was not reported as unresolved"
  printf '%s\n' "$fx" | sed 's/^/    /'
  fx_fails=$((fx_fails + 1))
else
  echo "ok: fixture - an expression name that could be a required context fails loudly"
fi

fx=$(run_census "$work/fx" "fx.yml :: sneaky")
if printf '%s\n' "$fx" | grep -q "^UNRESOLVED"; then
  echo "FAIL: fixture - an allow-listed expression name was still reported as unresolved"
  printf '%s\n' "$fx" | sed 's/^/    /'
  fx_fails=$((fx_fails + 1))
else
  echo "ok: fixture - allow-listing a reviewed expression name clears it"
fi

# 10. An expression name that CANNOT match any required context is an ordinary
#     member (and unwatchable), not an unresolved one - otherwise every job
#     with an expression in its name would need an allow-list entry.
fx_write <<'YAML'
name: fx
on:
  push:
    branches: [main]
    paths: ['src/**']
jobs:
  harmless:
    name: Publish ${{ github.event_name }}
    runs-on: ubuntu-latest
    steps: [{run: 'true'}]
YAML
fx=$(run_census "$work/fx" "")
fx_assert "a non-colliding expression name is an ordinary member" has "MEMBER	fx.yml :: harmless" "$fx"
fx_assert "...and is reported unwatchable rather than guessed at" has "UNWATCHABLE	fx.yml :: harmless	Publish \${{ github.event_name }}" "$fx"

if [ "$fx_fails" -ne 0 ]; then
  echo ""
  echo "FAIL: $fx_fails fixture assertion(s) failed"
  exit 1
fi

echo "PASS: every push-to-main job invisible on main's tip is a reviewed, dispositioned member"
