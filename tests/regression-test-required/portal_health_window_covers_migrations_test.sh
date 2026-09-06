#!/usr/bin/env bash
# Regression test for #3761: the customer portal's Docker health window must be
# wide enough to cover the agent's whole migration set on a loaded host.
#
# THE BUG. Two suites died in the 2026-09-05 merge-queue drain -
# 3441_policy_category_vocabulary and 3424_audit_latency_tile - with
#
#   Container wt34xx-portal  Error dependency axonflow-customer-portal failed to start
#
# The portal cannot report healthy until the agent has applied every migration:
# its owner bootstrap calls ensure_org_owner_assignment(), created by
# core/149-150. It knows that and retries 24 x 5s (#3004). Its depends_on is
# axonflow-agent:service_healthy, but the agent serves /health BEFORE its
# migrations finish (ee/platform/customer-portal/main.go:1127-1145 records
# exactly that), so the agent going healthy is not a signal that they are done.
#
# With start_period 30s + interval 10s + retries 3 the container was declared
# unhealthy at ~60s and compose's service_healthy dependency failed the stack.
# THE RETRY WAS NOT THE BINDING CONSTRAINT - the portal was on attempt 4 of 24
# with 80s of its own budget unspent. The window expired first.
#
# THE NUMBER, measured from those two entry logs rather than estimated: the
# migration runner applied at 0.39 and 0.62 s/migration on a loaded fleet (two
# concurrent suites, host load 255 on 16 vCPU), projecting the 201-migration
# set (155 core + 46 enterprise) at 78-124s, plus ~19s of agent boot before the
# first migration lands - so ~100-145s. The floor below is 150s: above the
# worst measured case, and under the 180s the files now carry, so a later
# tightening toward the old value fails here before it fails a drain.
#
# WHY A FLOOR AND NOT AN EQUALITY: the right value depends on host speed and
# migration count, both of which grow. Pinning 180 exactly would fail the day
# someone correctly raises it to 240. The claim worth defending is "at least as
# wide as the measured migration window", not one number.
#
# WHY THIS COULD NOT BE CAUGHT BY A NORMAL TEST: the failure needs several
# stacks migrating at once on one host. On a GitHub-hosted runner the set
# finishes inside even the old 30s window, so the race never fires there -
# which is why it survived to production CI. A static floor is the only check
# that runs everywhere.
#
# EXCLUDED, DELIBERATELY: axonflow-customer-portal-ui. Compose starts it only
# after the portal is healthy, so the migrations are already applied by the
# time its own window opens; its 30s is correct. And the agent/orchestrator,
# which go healthy early BY DESIGN - that is the premise of this bug, not a
# victim of it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

CHECKER=$(mktemp); TMP=$(mktemp -d)
trap 'rm -f "$CHECKER"; rm -rf "$TMP"' EXIT

cat > "$CHECKER" <<'PYEOF'
"""Assert every customer-portal healthcheck allows the migration set to finish."""
import glob, os, re, sys
import yaml


class Loader(yaml.SafeLoader):
    """Compose files here use `ports: !override`; SafeLoader alone rejects the tag."""


Loader.add_multi_constructor(
    '',
    lambda loader, suffix, node: (
        loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode)
        else loader.construct_mapping(node) if isinstance(node, yaml.MappingNode)
        else loader.construct_scalar(node)
    ),
)

FLOOR_S = int(os.environ.get('PORTAL_START_PERIOD_FLOOR', '150'))


def seconds(value):
    """Compose durations: '180s', '3m', '1m30s'. Returns None if unparseable,
    which is treated as a failure rather than as zero - an unreadable window is
    not a satisfied one."""
    if value is None:
        return None
    text = str(value).strip()
    if re.fullmatch(r'\d+', text):          # bare number = seconds
        return int(text)
    total = 0
    seen = False
    for amount, unit in re.findall(r'(\d+)\s*(h|m|s|ms)', text):
        seen = True
        total += int(amount) * {'h': 3600, 'm': 60, 's': 1, 'ms': 0}[unit]
    return total if seen else None


root = sys.argv[1]
floor_count = int(sys.argv[2])

# The service that must wait: the portal itself. NOT the portal-UI, which only
# starts once the portal is healthy, and not the agent, which is healthy early
# by design.
def is_portal(name):
    return 'portal' in name and 'portal-ui' not in name and not name.endswith('-ui')

checked, bad = [], []
for path in sorted(glob.glob(os.path.join(root, '**', '*compose*.y*ml'), recursive=True)):
    try:
        doc = yaml.load(open(path, errors='ignore'), Loader=Loader)
    except yaml.YAMLError as exc:
        print(f"FAIL: {path} is not parseable YAML: {exc}")
        sys.exit(2)
    if not isinstance(doc, dict):
        continue
    for name, svc in (doc.get('services') or {}).items():
        if not isinstance(svc, dict) or not is_portal(name):
            continue
        hc = svc.get('healthcheck')
        if not isinstance(hc, dict) or 'start_period' not in hc:
            continue          # no window declared: nothing this test can assert
        got = seconds(hc.get('start_period'))
        checked.append((path, name, hc.get('start_period'), got))
        if got is None or got < FLOOR_S:
            bad.append((path, name, hc.get('start_period')))

print(f"  checked {len(checked)} customer-portal healthcheck window(s) with a start_period")
for path, name, raw, got in checked:
    print(f"    {path} :: {name} = {raw} ({got}s)")

# ANTI-VACUITY. If the portal service were renamed, or the compose files moved,
# this would examine nothing and pass forever. The floor is on windows CHECKED.
if len(checked) < floor_count:
    print(f"FAIL: only {len(checked)} portal healthcheck(s) examined (floor {floor_count}). "
          f"The scan is not finding the portal service - has it been renamed?")
    sys.exit(2)

for path, name, raw in bad:
    print(f"VIOLATION [portal-health-window-too-tight] {path} :: {name} start_period={raw} "
          f"(needs >= {FLOOR_S}s)")
if bad:
    print(f"The portal cannot be healthy until the agent's migration set is applied;")
    print(f"measured at 100-145s on a loaded host. A window under {FLOOR_S}s fails the")
    print(f"whole stack with 'dependency axonflow-customer-portal failed to start'.")
    sys.exit(1)
print("  ok: every portal health window covers the measured migration time")
PYEOF

# 1. CONTROLS FIRST, so a real-tree failure is unambiguous.
mkdir -p "$TMP/wf" "$TMP/empty"
cat > "$TMP/wf/docker-compose.bad.yml" <<'YML'
services:
  axonflow-customer-portal:
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
      interval: 10s
      retries: 3
      start_period: 30s
YML
if python3 "$CHECKER" "$TMP/wf" 1 >"$TMP/out" 2>&1; then
  echo "FAIL: the rule did not fire on start_period: 30s"; cat "$TMP/out"; exit 1
fi
grep -q 'portal-health-window-too-tight' "$TMP/out" || {
  echo "FAIL: fired with the wrong finding"; cat "$TMP/out"; exit 1; }
echo "  ok: fires on the pre-fix value (30s)"

# The fixed value passes...
sed -i.bak 's/start_period: 30s/start_period: 180s/' "$TMP/wf/docker-compose.bad.yml"; rm -f "$TMP/wf"/*.bak
if ! python3 "$CHECKER" "$TMP/wf" 1 >"$TMP/out" 2>&1; then
  echo "FAIL: 180s was rejected"; cat "$TMP/out"; exit 1
fi
echo "  ok: accepts the fixed value (180s)"

# ...and so does an equivalent expressed in minutes, because compose accepts it.
sed -i.bak 's/start_period: 180s/start_period: 3m/' "$TMP/wf/docker-compose.bad.yml"; rm -f "$TMP/wf"/*.bak
if ! python3 "$CHECKER" "$TMP/wf" 1 >"$TMP/out" 2>&1; then
  echo "FAIL: '3m' was rejected; the duration parser is too narrow"; cat "$TMP/out"; exit 1
fi
echo "  ok: accepts an equivalent duration written as 3m"

# An unreadable window must FAIL, not be treated as satisfied.
sed -i.bak 's/start_period: 3m/start_period: soon/' "$TMP/wf/docker-compose.bad.yml"; rm -f "$TMP/wf"/*.bak
if python3 "$CHECKER" "$TMP/wf" 1 >"$TMP/out" 2>&1; then
  echo "FAIL: an unparseable start_period passed"; cat "$TMP/out"; exit 1
fi
echo "  ok: an unparseable window fails rather than passing"

# The anti-vacuity floor must itself be reachable.
if python3 "$CHECKER" "$TMP/empty" 2 >"$TMP/out" 2>&1; then
  echo "FAIL: an empty tree passed; the floor is not wired"; cat "$TMP/out"; exit 1
fi
grep -q 'floor' "$TMP/out" || { echo "FAIL: empty tree failed for the wrong reason"; cat "$TMP/out"; exit 1; }
echo "  ok: an empty scan fails on the floor rather than passing"

# 2. THE REAL TREE. Floor of 2: docker-compose.enterprise.yml and
#    docker-compose.test.yml both declare a portal window today.
if ! python3 "$CHECKER" . 2; then
  echo
  echo "FAIL: a customer-portal health window is too tight for the migration set."
  echo "See the header of $0 and #3761."
  exit 1
fi
echo "ok: portal health windows cover the measured migration time"
