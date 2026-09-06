#!/usr/bin/env bash
# Regression guard: a DRAFT pull request runs only the cheap tier.
#
# THE RULE (operator, 2026-09-03). Workers open PRs as drafts and iterate; on
# 2026-09-01 the repository saw 62 pushes across ~12 PRs, so every PR paid for
# the full verification tier about five times. Now: a draft runs only the
# cheap gates; marking it ready runs the full tier once; pushes after that (R3
# fix rounds) run it again. Every expensive PR-tier job therefore carries
# `github.event.pull_request.draft != true` as a TOP-LEVEL `&&` CONJUNCT of its
# `if:` - or transitively needs a job that does and tests that job's result -
# and every such workflow lists `ready_for_review` in pull_request.types, or
# the flip to ready would start nothing until the next push.
#
# WHAT THIS PINS, and the mutants that shaped it (R3 round 1 on #3683):
#   1. The clause is checked as a CONJUNCT by parsing the expression, not as a
#      substring: `draft != true || event == 'pull_request'` and
#      `(A || B) || draft != true` both contain the text and both run on
#      drafts (H1).
#   2. Coverage is PER JOB, not per workflow: a job is expensive if any step
#      runs a build/test/container command or sets up a toolchain, or the job
#      declares `services:`; every expensive job must carry the clause itself
#      or transitively `needs:` a job that does, and a job whose `if:` uses
#      `always()` must read `needs.<x>.result` for a covered job, or it would
#      run when its gate was skipped (H2). Summaries are exempt only because
#      they are cheap by the same proxy - echo and exit - not by name.
#   3. The CHEAP list is policed by the same proxy: a cheap workflow may not
#      contain an expensive job at all (M1). A new gate that needs a toolchain
#      is not cheap and goes on the gated side.
#   4. Floors: >= 12 gated workflows, >= 8 cheap ones, >= 25 expensive jobs.
#      These were 60/10/40 until 2026-09-04, when the 62 stack-booting suites
#      lost their pull_request trigger outright (the label gate had cut
#      nothing: 129 billable minutes per push before, 133 after) and left the
#      PR tier. What remains is the base tier - unit lanes, lint, migrations,
#      build, security scans, portal modes - and the draft rule still applies
#      to it. Measured on this tree at the change: 14 / 10 / 30.
#
# KNOWN LIMITS OF THE COST PROXY, stated so the next reviewer does not have to
# derive them (R3 round 3 on #3683; real-tree exposure today: none):
#   - it reads `run:` text, so a repository script that builds or tests INSIDE
#     itself (`bash scripts/x.sh` where x.sh runs `go test`) is invisible; the
#     stack-booting suites are caught by their own census
#     (pr_tier_e2e_label_gated_test.sh), not by this proxy;
#   - the command list is an allow-list of build/test/container tools; a new
#     tool (a language this tree does not use yet) must be added here;
#   - `uses:` matching is a prefix list of toolchain/container actions; a new
#     third-party setup action must be added here;
#   - override functions recognised: always(), !cancelled(), failure().
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Each is a grep, a lint or a presence check with no toolchain set-up and no
# container; measured 2026-09-01 at ~1 billable minute per run. The proxy
# below re-verifies that on every run of this test.
CHEAP="suite-gate.yml commit-lint.yml gitleaks.yml check-forbidden-files.yml partner-name-denylist.yml lint-workflow-telemetry.yml validate-version-alignment.yml definition-of-done.yml check-protected-changes.yml tests-hygiene.yml guardrail-stale-model-ids.yml"

out=$(python3 - "$CHEAP" <<'PY'
import glob, io, re, sys, yaml
cheap = set(sys.argv[1].split())
CLAUSE = "github.event.pull_request.draft != true"

# A step is expensive if it sets up a toolchain, or a run line STARTS with a
# build/test/container command (a mention inside a comment or a grep pattern
# is not a cost).
USES_PROXY = re.compile(r"^actions/setup-(go|node|java|python|dotnet)\b|^docker/|^golangci/golangci-lint-action|^aws-actions/|^gradle/|^ruby/setup-ruby|^dtolnay/rust-toolchain|^astral-sh/setup-uv")
# A command counts at command position, also after a leading `(`, a
# `cd <dir> &&` prefix (any depth), `sudo`, `time`, or `env VAR=... `.
RUN_PROXY = re.compile(r"^\s*(?:\(\s*)?(?:cd\s+\S+\s*&&\s*)*(?:(?:sudo|time)\s+)?(?:env\s+(?:\S+=\S+\s+)*)?(docker|docker-compose|go|npm|npx|yarn|pnpm|mvn|gradle|pytest|python -m pytest|cargo|make|uv|pip|bazel)(\s|$)")
# Functions that make a job run even when a needed job was skipped.
OVERRIDE = re.compile(r"always\(\)|!\s*cancelled\(\)|failure\(\)")

def is_expensive(job):
    if job.get('services'):
        return True
    for s in job.get('steps') or []:
        s = s or {}
        if USES_PROXY.search(str(s.get('uses', ''))):
            return True
        for line in str(s.get('run', '')).split('\n'):
            if RUN_PROXY.match(line):
                return True
    return False

# --- expression parsing: is CLAUSE a top-level && conjunct? -----------------
def split_top(expr, op):
    parts, depth, cur, i, q = [], 0, [], 0, None
    while i < len(expr):
        c = expr[i]
        if q:
            cur.append(c)
            if c == q: q = None
        elif c in ("'", '"'):
            q = c; cur.append(c)
        elif c == '(':
            depth += 1; cur.append(c)
        elif c == ')':
            depth -= 1; cur.append(c)
        elif depth == 0 and expr.startswith(op, i):
            parts.append(''.join(cur)); cur = []; i += len(op); continue
        else:
            cur.append(c)
        i += 1
    parts.append(''.join(cur))
    return parts

def unwrap(e):
    e = e.strip()
    while e.startswith('(') and e.endswith(')'):
        # only strip if the outer parens match each other
        depth = 0
        for k, c in enumerate(e):
            if c == '(': depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0 and k != len(e) - 1:
                    return e
        e = e[1:-1].strip()
    return e

def conjuncts(expr):
    expr = unwrap(re.sub(r'\s+', ' ', expr.replace('\n', ' ')).strip())
    if expr.startswith('${{') and expr.endswith('}}'):
        expr = unwrap(expr[3:-2])
    if len(split_top(expr, '||')) > 1:
        return []            # top level is an OR: nothing is guaranteed
    out = []
    for part in split_top(expr, '&&'):
        part = unwrap(part)
        if len(split_top(part, '&&')) > 1:
            out.extend(conjuncts(part))
        else:
            out.append(part)
    return out

def has_clause(cond):
    return CLAUSE in conjuncts(cond)

def never_on_pull_request(cond):
    """A job whose if: excludes pull_request as a top-level conjunct is not a
    PR-tier job at all (CodeQL on schedule, the image scans on merge_group)."""
    for c in conjuncts(cond):
        c = re.sub(r'\s+', ' ', c)
        if c == "github.event_name != 'pull_request'":
            return True
        m = re.match(r"github.event_name == '([a-z_]+)'$", c)
        if m and m.group(1) != 'pull_request':
            return True
    return False

problems, gated, cheap_seen, expensive_seen = [], 0, 0, 0
for f in sorted(glob.glob('.github/workflows/*.yml')):
    base = f.split('/')[-1]
    d = yaml.safe_load(io.open(f, encoding='utf-8'))
    on = d.get('on') or d.get(True) or {}
    if not isinstance(on, dict) or 'pull_request' not in on:
        continue
    jobs = d.get('jobs') or {}
    exp = {jn for jn, j in jobs.items() if is_expensive(j or {})}
    if base in cheap:
        cheap_seen += 1
        for jn in sorted(exp):
            problems.append(f"{base}: on the CHEAP list but job '{jn}' sets up a toolchain, runs a build/test/container command or declares services - not cheap")
        if any(CLAUSE in str((j or {}).get('if', '')) for j in jobs.values()):
            problems.append(f"{base}: on the CHEAP list but carries the draft clause - cheap gates must run on drafts")
        continue
    gated += 1
    expensive_seen += len(exp)
    pr = on.get('pull_request') or {}
    types = pr.get('types') if isinstance(pr, dict) else None
    if not types or 'ready_for_review' not in types:
        problems.append(f"{base}: pull_request.types must include 'ready_for_review'")
    covered = {jn for jn, j in jobs.items() if has_clause(str((j or {}).get('if', '')))}
    # transitive coverage through needs:, with the always() rule
    changed = True
    while changed:
        changed = False
        for jn, j in jobs.items():
            if jn in covered: continue
            j = j or {}
            needs = j.get('needs') or []
            needs = [needs] if isinstance(needs, str) else list(needs)
            cov_needs = [n for n in needs if n in covered]
            if not cov_needs: continue
            cond = str(j.get('if', ''))
            if OVERRIDE.search(cond) and not any(f"needs.{n}.result" in cond for n in cov_needs):
                continue      # runs even when its gate was skipped
            covered.add(jn); changed = True
    for jn in sorted(exp):
        if jn not in covered and never_on_pull_request(str((jobs[jn] or {}).get('if', ''))):
            continue
        if jn not in covered:
            j = jobs[jn] or {}
            problems.append(f"{base}: expensive job '{jn}' is not draft-gated: its if: ({str(j.get('if',''))[:90]!r}) has no top-level `{CLAUSE}` conjunct and it does not transitively need a gated job whose result it tests")
print(gated); print(cheap_seen); print(expensive_seen); print('\n'.join(problems))
PY
)
gated=$(printf '%s\n' "$out" | sed -n 1p)
cheap_seen=$(printf '%s\n' "$out" | sed -n 2p)
expensive_seen=$(printf '%s\n' "$out" | sed -n 3p)
problems=$(printf '%s\n' "$out" | tail -n +4 | sed '/^$/d')

if [ "${gated:-0}" -lt 12 ] || [ "${cheap_seen:-0}" -lt 8 ] || [ "${expensive_seen:-0}" -lt 25 ]; then
  echo "FAIL: census saw ${gated:-0} gated workflows, ${cheap_seen:-0} cheap, ${expensive_seen:-0} expensive jobs (floors 12 / 8 / 25)"
  exit 1
fi
echo "ok: censused ${gated} draft-gated workflows (${expensive_seen} expensive jobs) and ${cheap_seen} cheap ones"
if [ -n "$problems" ]; then
  echo "FAIL: draft-PR cheap tier drifted:"
  printf '%s\n' "$problems" | sed 's/^/  /'
  echo ""
  echo "A draft runs only the cheap gates. An expensive job carries"
  echo "  if: github.event.pull_request.draft != true"
  echo "as a top-level && conjunct (or transitively needs a job that does and"
  echo "tests its result), and its workflow lists ready_for_review in"
  echo "pull_request.types. A workflow with no toolchain, no build/test/container"
  echo "command and no services may go on the CHEAP list in this test."
  exit 1
fi
echo "ok: every expensive pull_request job is draft-gated as a conjunct, every gated workflow is ready_for_review-triggered, every cheap one is cheap by the proxy"
