#!/usr/bin/env bash
# Regression guard: the push-to-main re-verification tier stays retired.
#
# THE BUG CLASS. The 2026-08-27 CI-cost change (#3537) removed the post-merge
# re-run tier: 34% of all workflow runs were re-verifying, on push to main,
# the exact tree the merge queue had verified seconds earlier. Within TWO
# HOURS of it merging, a new workflow (#3536, usbanking-compliance-e2e.yml)
# landed carrying `push: branches: [main]` again - copied from a pre-change
# template, red on nothing, and quietly re-opening the tier one file at a
# time. A convention that lives only in retired examples regrows from old
# templates; this pin is what makes the next copy fail on its own PR instead.
#
# WHAT IS ALLOWED ON PUSH-TO-MAIN, and why (the allow-list mirrors #3537's
# kept set; every entry is a producer or a last-line scan, not re-verification):
#   build.yml                  pushes the ECR images deployments consume
#   build-community.yml        seeds the gha layer cache PR builds restore
#   deploy-infrastructure.yml  deploys
#   security.yml               CodeQL default-branch baseline for alert diffing
#   gitleaks.yml               last secret scan before content is public
#   partner-name-denylist.yml  last partner-name scan before the public mirror
#   infra-validation.yml       its own pytest pins + the strict-on-push
#                              partner-preflight parity guard require it
#   cache-seed.yml             the module-cache seeder the retirement created
#
# TAG TRIGGERS ARE NOT THIS GUARD'S BUSINESS: `push: {tags: [...]}` with no
# `branches:` key fires on tag pushes only - release verification, kept
# deliberately - and is not matched here.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

ALLOW="build.yml build-community.yml deploy-infrastructure.yml security.yml gitleaks.yml partner-name-denylist.yml infra-validation.yml cache-seed.yml"

failures=0
checked=0
offenders=$(python3 - "$ALLOW" <<'PY'
import yaml, io, glob, sys
allow = set(sys.argv[1].split())
out = []
n = 0
for f in sorted(glob.glob('.github/workflows/*.yml')):
    d = yaml.safe_load(io.open(f, encoding='utf-8'))
    on = d.get('on') or d.get(True) or {}
    if not isinstance(on, dict) or 'push' not in on:
        continue
    p = on.get('push')
    b = (p or {}).get('branches') if isinstance(p, dict) else None
    t = (p or {}).get('tags') if isinstance(p, dict) else None
    # Fires on a push to main iff branches lists main, or the block names
    # neither branches nor tags (bare push = every branch).
    fires = ('main' in (b or [])) if b is not None else (t is None)
    n += 1
    if fires and f.split('/')[-1] not in allow:
        out.append(f.split('/')[-1])
print(n)
print('\n'.join(out))
PY
)
checked=$(printf '%s\n' "$offenders" | head -1)
offenders=$(printf '%s\n' "$offenders" | tail -n +2 | sed '/^$/d')

# Anti-vacuity: the census must actually have seen push blocks, or a parse
# change could turn this into a guard that checks nothing and passes.
if [ "${checked:-0}" -lt 5 ]; then
  echo "FAIL: only ${checked:-0} workflows with push triggers were seen - the census is not looking at the tree"
  exit 1
fi
echo "ok: censused ${checked} workflows carrying a push trigger"

if [ -n "$offenders" ]; then
  echo "FAIL: workflow(s) re-run on push to main outside the #3537 allow-list:"
  printf '%s\n' "$offenders" | sed 's/^/  /'
  echo ""
  echo "The merge queue already verified the exact tree that lands on main;"
  echo "a push-to-main re-run re-verifies it at full price. If this workflow"
  echo "genuinely PRODUCES something on main (an image, a cache, a scan of"
  echo "what just became public), add it to the allow-list in this test AND"
  echo "to the kept-set comment in the same diff, with the reason."
  exit 1
fi
echo "ok: no verification workflow re-runs on push to main"

# Self-test both directions on fixtures, so the matcher cannot rot silently.
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github/workflows"
cat > "$tmp/.github/workflows/sneak.yml" <<'Y'
on:
  push:
    branches: [main]
jobs:
  j:
    runs-on: ubuntu-latest
    steps: [{run: echo hi}]
Y
cat > "$tmp/.github/workflows/tagsonly.yml" <<'Y'
on:
  push:
    tags: ['v*']
jobs:
  j:
    runs-on: ubuntu-latest
    steps: [{run: echo hi}]
Y
bad=$(cd "$tmp" && python3 -c "
import yaml,io,glob
for f in glob.glob('.github/workflows/*.yml'):
    on=yaml.safe_load(io.open(f)).get('on') or yaml.safe_load(io.open(f)).get(True)
    p=on.get('push'); b=(p or {}).get('branches'); t=(p or {}).get('tags')
    fires=('main' in (b or [])) if b is not None else (t is None)
    if fires: print(f.split('/')[-1])
")
case "$bad" in
  *sneak.yml*) echo "ok: fixture with push:main IS detected" ;;
  *) echo "FAIL: the matcher missed the push:main fixture"; exit 1 ;;
esac
case "$bad" in
  *tagsonly.yml*) echo "FAIL: a tags-only push was misread as push-to-main"; exit 1 ;;
  *) echo "ok: a tags-only push trigger is correctly ignored" ;;
esac
echo "PASS: push-to-main tier remains retired"
