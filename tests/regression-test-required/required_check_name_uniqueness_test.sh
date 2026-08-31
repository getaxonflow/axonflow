#!/usr/bin/env bash
# Regression guard: every REQUIRED status-check context has EXACTLY ONE
# producing workflow file in this tree - not zero, not two.
#
# THE BUG CLASS (#3573). Branch protection matches a required status check by
# NAME. Two workflows declared a job whose display name was `Test Summary`,
# and both fired on `pull_request`, so both reported a check run under that
# one name on the same head commit:
#
#   $ gh api "repos/.../commits/$SHA/check-runs?per_page=100" \
#       -q '.check_runs[]|select(.name=="Test Summary")|"\(.conclusion) \(.html_url)"'
#   success  ... run 33300213268   <- Test Suite            (runs the tests)
#   success  ... run 33300213230   <- Test Suite (Community) (3s, skipped)
#
# Which conclusion satisfies the requirement is then not something the
# workflow files decide, and the cheaper of the two producers is the one that
# skips. `Build Summary` had THREE declarations for the same reason. Both are
# fixed; this test is what stops the next copy-paste from re-opening it.
#
# THE OTHER DIRECTION MATTERS JUST AS MUCH. A required context with ZERO
# producers is not a loose gate, it is a wedged repository: nothing ever
# reports it, so every pull request sits pending until the ruleset is edited.
# Renaming a summary job without editing the ruleset does exactly that, which
# is why the fix for #3573 renamed the NON-required duplicate. This test fails
# on count 0 as loudly as it fails on count 2.
#
# WHY THE REQUIRED LISTS ARE SNAPSHOTTED HERE. Requiredness lives in a
# repository ruleset, which is not in the tree, so a tree-only test cannot
# read it. These two lists are byte-exact snapshots taken 2026-08-30. Refresh
# them with:
#
#   gh api repos/getaxonflow/axonflow-enterprise/rulesets/9199766 \
#     | jq -r '.rules[]|select(.type=="required_status_checks")
#              |.parameters.required_status_checks[].context'
#   gh api repos/getaxonflow/axonflow/rulesets/10855245 \
#     | jq -r '.rules[]|select(.type=="required_status_checks")
#              |.parameters.required_status_checks[].context'
#
# NOTE THE EM DASH. The enterprise context is `Lint <U+2014> no mocks in
# runtime-e2e/`, spelled above as the raw bytes \xe2\x80\x94 so that this file
# stays pure ASCII, and definition-of-done.yml declares it with the
# same character. Issue #3573 quotes it with an ASCII hyphen because the
# repository's markdown hook rewrites dashes in .md files; the ruleset and the
# workflow are what agree, and "normalising" the job name to a hyphen would
# silently orphan a required context. This test compares raw bytes.
#
# WHICH REPO AM I. The community mirror strips `ee/` wholesale, so its
# presence is the discriminator. The mirror has its own ruleset requiring its
# own four contexts, produced by the *-community.yml lanes, which is why
# those two summary jobs resolve their display name from `github.repository`
# instead of carrying a literal.
#
# AND WHY THE MIRROR ARM IS ALSO CHECKED FROM HERE. This suite is executed by
# `run-regression-suite` in regression-test-required.yml, which carries
# `if: github.repository == '...-enterprise'`. The file SYNCS to the mirror and
# the job that would run it does not, so the mirror branch below never executes
# in any CI. The whole justification for the github.repository expression is
# the mirror's ruleset 10855245, and an invariant nobody runs is not guarded -
# so the enterprise run additionally resolves the community-required contexts
# against the workflows that survive the sync. That is a partial model of the
# sync filter, not the whole of it, and it is deliberately partial: it names
# the four files that produce the mirror's four required contexts, which is the
# property that matters, rather than reimplementing an rsync include/exclude
# chain that would rot on its own.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if [ -d ee ]; then
  REPO="getaxonflow/axonflow-enterprise"
  REQUIRED=$'Build Summary\nTest Summary\nLint Summary\nSecurity Scan Summary\nLint \xe2\x80\x94 no mocks in runtime-e2e/\nRuntime E2E required for user-facing changes\nMigrations apply cleanly\nLint - no HTTP-code-only stack readiness waits'
else
  REPO="getaxonflow/axonflow"
  REQUIRED=$'Build Summary\nTest Summary\nLint Summary\nSecurity Scan Summary'
fi
echo "tree identity: $REPO"

# ---------------------------------------------------------------------------
# Expression-valued job names.
#
# A display name may be an expression, and an expression the guard cannot
# evaluate is the job MOST likely to be interesting - so none may be silently
# skipped. Three treatments, in order:
#
#   1. The repo-conditional shape used by the two *-community.yml summary jobs
#      is evaluated exactly, against this tree's repo identity.
#   2. Any other expression is reduced to a GLOB by replacing each `${{ ... }}`
#      with `*`. If that glob cannot match any required context, the name is
#      provably not a producer and is recorded under an opaque key.
#   3. If the glob COULD match a required context, the guard cannot rule the
#      job out and fails - unless the exact `file :: name` pair appears in the
#      allow-list below with a reason. Reviewed, not assumed.
# ---------------------------------------------------------------------------
#
# ALLOW-LIST. One entry today:
#
#   build-client-images.yml :: Build ${{ matrix.client }}
#     Reduces to the glob `Build *`, which matches the required context
#     `Build Summary`. It cannot produce it: the matrix comes from
#     `fromJson(needs.determine-clients.outputs.clients)` and the job body
#     rejects anything outside {ecommerce, travel, healthcare, banking} with
#     "Unknown client" (build-client-images.yml, the if/elif chain around
#     line 83). `Summary` is not a client, and a run with one would fail.
EXPR_ALLOWLIST=$'build-client-images.yml :: Build ${{ matrix.client }}'

# The census + the assertions live in one python program so the resolver is
# defined once and the fixture self-test below drives that same resolver.
CENSUS_PY='
import fnmatch, glob, io, json, os, re, sys, collections
import yaml

repo = sys.argv[1]
root = sys.argv[2]
required = [l for l in sys.argv[3].split("\n") if l]
allowed = set(l for l in sys.argv[4].split("\n") if l)

COND = re.compile(
    r"^\$\{\{\s*github\.repository\s*==\s*'"'"'([^'"'"']*)'"'"'\s*&&\s*'"'"'([^'"'"']*)'"'"'"
    r"\s*\|\|\s*'"'"'([^'"'"']*)'"'"'\s*\}\}$"
)
SUBST = re.compile(r"\$\{\{.*?\}\}")

def resolve(name, where):
    if "${{" not in name:
        return name
    m = COND.match(name.strip())
    if m:
        cond_repo, then_v, else_v = m.groups()
        return then_v if repo == cond_repo else else_v
    # Glob reduction. fnmatch is used only to ask "could this ever equal a
    # required context", never to decide that it does.
    pattern = SUBST.sub("*", name)
    collides = [c for c in required if fnmatch.fnmatchcase(c, pattern)]
    if collides and ("%s :: %s" % (where, name)) not in allowed:
        raise SystemExit(
            "FAIL: %s declares the job name %r, which reduces to the glob %r "
            "and could therefore collide with the required context(s) %r.\n"
            "      Either give the job a name that cannot collide, or add "
            "\"%s :: %s\" to EXPR_ALLOWLIST in "
            "tests/regression-test-required/required_check_name_uniqueness_test.sh "
            "with the reason it cannot produce that context."
            % (where, name, pattern, collides, where, name)
        )
    # Opaque, per-declaration key: never equal to any literal context name.
    return "\x00expr\x00%s\x00%s" % (where, name)

files = sorted(
    glob.glob(os.path.join(root, ".github/workflows/*.yml"))
    + glob.glob(os.path.join(root, ".github/workflows/*.yaml"))
)
producers = collections.defaultdict(set)
parsed = 0
jobs_seen = 0
for f in files:
    with io.open(f, encoding="utf-8") as fh:
        d = yaml.safe_load(fh) or {}
    parsed += 1
    base = os.path.basename(f)
    for jid, j in (d.get("jobs") or {}).items():
        jobs_seen += 1
        raw = (j or {}).get("name") or jid
        producers[resolve(str(raw), base)].add(base)

json.dump({
    "globbed": len(files),
    "parsed": parsed,
    "jobs": jobs_seen,
    "producers": {k: sorted(v) for k, v in producers.items()},
}, sys.stdout)
'

census() { python3 -c "$CENSUS_PY" "$1" "$2" "$REQUIRED" "$EXPR_ALLOWLIST"; }

RESULT=$(census "$REPO" ".") || exit 1

read_field() { printf '%s' "$RESULT" | python3 -c "import json,sys;print(json.load(sys.stdin)['$1'])"; }

GLOBBED=$(read_field globbed)
PARSED=$(read_field parsed)
JOBS=$(read_field jobs)

# ---------------------------------------------------------------------------
# Anti-vacuity. Every number below is DERIVED from the tree (files on disk,
# jobs parsed out of them), never a hand-picked floor that the first passing
# input happens to clear. The strong anti-vacuity property is the exactly-one
# assertion itself: a census that saw nothing reports 0 producers for every
# required context and fails on the zero-producer arm.
# ---------------------------------------------------------------------------
if [ "$PARSED" -ne "$GLOBBED" ]; then
  echo "FAIL: globbed $GLOBBED workflow file(s) but parsed $PARSED - the census is skipping files"
  exit 1
fi
if [ "$GLOBBED" -lt 1 ] || [ "$JOBS" -lt 1 ]; then
  echo "FAIL: censused $GLOBBED workflow file(s) / $JOBS job(s) - the census is not looking at the tree"
  exit 1
fi
echo "ok: censused $JOBS job(s) across $GLOBBED workflow file(s), zero parse skips"

# ---------------------------------------------------------------------------
# The assertion: exactly one producer per required context.
# ---------------------------------------------------------------------------
failures=0
checked=0
while IFS= read -r ctx; do
  [ -n "$ctx" ] || continue
  checked=$((checked + 1))
  owners=$(printf '%s' "$RESULT" | CTX="$ctx" python3 -c '
import json, os, sys
p = json.load(sys.stdin)["producers"]
print(" ".join(p.get(os.environ["CTX"], [])))')
  count=$(printf '%s' "$owners" | wc -w | tr -d ' ')
  if [ "$count" -eq 1 ]; then
    echo "ok: '$ctx' <- $owners"
  elif [ "$count" -eq 0 ]; then
    echo "FAIL: required context '$ctx' is declared by NO workflow in this tree."
    echo "      Nothing will ever report it, so every pull request stays pending."
    echo "      Either a job was renamed without the ruleset, or the snapshot in"
    echo "      this test is stale - refresh it with the gh command in the header."
    failures=$((failures + 1))
  else
    echo "FAIL: required context '$ctx' is declared by $count workflows: $owners"
    echo "      This is #3573. Two check runs sharing one required name means the"
    echo "      ruleset cannot tell which conclusion gated the merge. Rename the"
    echo "      declaration that is NOT the required producer; renaming the"
    echo "      required one needs a ruleset edit and wedges the repo until it lands."
    failures=$((failures + 1))
  fi
done <<< "$REQUIRED"

if [ "$checked" -lt 1 ]; then
  echo "FAIL: the required-context snapshot for $REPO is empty"
  exit 1
fi
echo "ok: checked $checked required context(s) for $REPO"

# ---------------------------------------------------------------------------
# THE MIRROR ARM, checked from the enterprise tree because nothing runs this
# file in the mirror.
#
# The community repo's ruleset requires four contexts, and in that tree they
# have exactly one producer each. Three of the four files sync unchanged;
# build-community.yml and test-community.yml resolve their display name from
# github.repository, which is the thing this arm exists to verify.
# ---------------------------------------------------------------------------
if [ "$REPO" = "getaxonflow/axonflow-enterprise" ]; then
  mirror_required=$'Build Summary\tbuild-community.yml\nTest Summary\ttest-community.yml\nLint Summary\tlint.yml\nSecurity Scan Summary\tsecurity.yml'
  mirror_checked=0
  while IFS=$'\t' read -r ctx wf; do
    [ -n "$ctx" ] || continue
    if [ ! -f ".github/workflows/$wf" ]; then
      echo "FAIL: $wf is expected to produce the mirror-required context '$ctx' and is not in this tree"
      exit 1
    fi
    owners=$(census "getaxonflow/axonflow" "." | CTX="$ctx" python3 -c '
import json, os, sys
print(" ".join(json.load(sys.stdin)["producers"].get(os.environ["CTX"], [])))')
    case " $owners " in
      *" $wf "*) ;;
      *)
        echo "FAIL: resolved under the COMMUNITY repo, the required context '$ctx' is produced by [$owners],"
        echo "      and $wf is not among them. In the mirror that file is the only producer of that context,"
        echo "      so a rename here leaves ruleset 10855245 requiring a context nothing reports - every"
        echo "      mirror pull request pending forever."
        exit 1
        ;;
    esac
    mirror_checked=$((mirror_checked + 1))
  done <<< "$mirror_required"
  if [ "$mirror_checked" -ne 4 ]; then
    echo "FAIL: checked $mirror_checked mirror-required context(s), expected 4"
    exit 1
  fi
  echo "ok: all 4 community-required contexts resolve to their synced producer under repo=getaxonflow/axonflow"
fi

# ---------------------------------------------------------------------------
# Self-test on fixtures, both directions, so the matcher cannot rot silently.
# Each fixture drives the SAME resolver and census as the live run above.
# ---------------------------------------------------------------------------
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github/workflows"

wf() { # wf <file> <job-name>
  cat > "$tmp/.github/workflows/$1" <<Y
on:
  pull_request:
    branches: [main]
jobs:
  s:
    name: $2
    runs-on: ubuntu-latest
    steps: [{run: echo hi}]
Y
}

owners_of() { # owners_of <repo> <context>
  census "$1" "$tmp" | CTX="$2" python3 -c '
import json, os, sys
print(" ".join(json.load(sys.stdin)["producers"].get(os.environ["CTX"], [])))'
}

# (a) one producer -> exactly one owner
wf one.yml "Test Summary"
got=$(owners_of "getaxonflow/axonflow-enterprise" "Test Summary")
[ "$got" = "one.yml" ] || { echo "FAIL: single-producer fixture resolved to '$got'"; exit 1; }
echo "ok: fixture with one producer resolves to exactly that file"

# (b) two producers -> duplicate is SEEN (the #3573 shape)
wf two.yml "Test Summary"
got=$(owners_of "getaxonflow/axonflow-enterprise" "Test Summary")
[ "$got" = "one.yml two.yml" ] || { echo "FAIL: duplicate fixture resolved to '$got', expected both files"; exit 1; }
echo "ok: fixture with two producers IS detected as a duplicate"

# (c) zero producers -> the missing-producer arm is reachable
got=$(owners_of "getaxonflow/axonflow-enterprise" "Nonexistent Summary")
[ -z "$got" ] || { echo "FAIL: a context nothing declares resolved to '$got'"; exit 1; }
echo "ok: a context with no declaration resolves to zero producers"

# (d) the repo-conditional resolver actually flips, in both directions
rm -f "$tmp/.github/workflows/one.yml" "$tmp/.github/workflows/two.yml"
wf cond.yml "\${{ github.repository == 'getaxonflow/axonflow' && 'Test Summary' || 'Test Summary (Community)' }}"
mirror=$(owners_of "getaxonflow/axonflow" "Test Summary")
ent_bare=$(owners_of "getaxonflow/axonflow-enterprise" "Test Summary")
ent_sfx=$(owners_of "getaxonflow/axonflow-enterprise" "Test Summary (Community)")
[ "$mirror" = "cond.yml" ] || { echo "FAIL: conditional name did not resolve to 'Test Summary' in the mirror (got '$mirror')"; exit 1; }
[ -z "$ent_bare" ] || { echo "FAIL: conditional name still produced bare 'Test Summary' in the enterprise repo"; exit 1; }
[ "$ent_sfx" = "cond.yml" ] || { echo "FAIL: conditional name did not resolve to the (Community) suffix in the enterprise repo (got '$ent_sfx')"; exit 1; }
echo "ok: the repo-conditional job name resolves differently in each repo, both directions checked"

# (e) an expression name that COULD reduce to a required context must fail
#     loudly, never be skipped into invisibility.
wf collide.yml "Build \${{ matrix.thing }}"
if census "getaxonflow/axonflow-enterprise" "$tmp" >/dev/null 2>&1; then
  echo "FAIL: a job-name expression that can glob-match 'Build Summary' was accepted silently"
  exit 1
fi
echo "ok: an expression name that could collide with a required context fails the census loudly"

# (f) ...and the opposite: an expression name that cannot match any required
#     context is accepted, and is NOT recorded as a producer of one. Without
#     this arm the guard could be "fail on every expression", which would be
#     unusable and would tempt the next person to delete it.
rm -f "$tmp/.github/workflows/collide.yml"
wf harmless.yml "Deploy \${{ inputs.client }} to \${{ inputs.environment }}"
census "getaxonflow/axonflow-enterprise" "$tmp" >/dev/null 2>&1 \
  || { echo "FAIL: a non-colliding expression job name was rejected"; exit 1; }
for c in "Build Summary" "Test Summary" "Lint Summary" "Security Scan Summary"; do
  got=$(owners_of "getaxonflow/axonflow-enterprise" "$c")
  case " $got " in
    *" harmless.yml "*) echo "FAIL: a non-colliding expression name was credited with producing '$c'"; exit 1 ;;
  esac
done
echo "ok: a non-colliding expression name is accepted and credited with no required context"

# (g) the allow-list must be load-bearing, not decoration: with it emptied the
#     live tree has to go red. Run this arm only when at least one
#     allow-listed file is actually present - the community mirror does not
#     carry build-client-images.yml, and an entry that is inapplicable there
#     is correct rather than dead.
applicable=0
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  f="${entry%% :: *}"
  [ -f ".github/workflows/$f" ] && applicable=1
done <<< "$EXPR_ALLOWLIST"
if [ "$applicable" -eq 1 ]; then
  if ( EXPR_ALLOWLIST=""; census "$REPO" "." >/dev/null 2>&1 ); then
    echo "FAIL: the live tree passes the census with an EMPTY allow-list -"
    echo "      the allow-list entry is dead weight and its reason is unverified"
    exit 1
  fi
  echo "ok: emptying EXPR_ALLOWLIST turns the live census red, so the entry is load-bearing"
else
  echo "ok: no allow-listed workflow is present in this tree, so the entry is inapplicable here"
fi

if [ "$failures" -gt 0 ]; then
  echo "FAIL: $failures required status-check context(s) do not have exactly one producer"
  exit 1
fi
echo "PASS: every required status-check context has exactly one producing workflow"
