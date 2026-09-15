#!/usr/bin/env bash
# decision_shadow_canary_probe_preconditions_test.sh
#
# THE BUG CLASS: A PROBE THAT CANNOT SUCCEED, PAGING FOREVER.
#
# The twelve-plane decision-shadow canary paged dev@ every five to ten minutes
# with `failed_step: coverage` naming map, openai_compatible and wcp. Two probes
# were structurally unable to evaluate, each for its own reason, and neither
# failure was about the deployment:
#
#   A. the openai probe sent a hard-coded placeholder provider key. On an
#      ALLOWED payload the handler forwards upstream
#      (openai_compat_handler.go:450) and the provider answers 401
#      `invalid_api_key`. Nothing an operator could act on.
#   B. the plan_execute probe sent no `plan_id`. executePlanHandler reads
#      `context.plan_id` and refuses without one at orchestrator/run.go:4925 -
#      126 lines BEFORE the wcp evaluation at :5051, and long before any step
#      executes, which is the only place the map plane's single call site
#      (map_hitl_adapter.go:50) is reached.
#
# WHAT THIS GUARD PINS, and why each is a rule rather than a fixture:
#
#   1. plan_execute supplies the field the ENDPOINT requires, driven rather
#      than grepped: the requirement is read out of run.go, and the probe is
#      run over a recording transport so the assertion is about the request it
#      MAKES.
#   2. A multi-request probe never credits its own precondition response. The
#      generate call is evaluated by the PROXY planes; returning it verbatim
#      would hand wcp and map an evaluation neither performed - the inference
#      defect this canary exists to refuse, manufactured by the canary itself.
#   3. A 429 on that first call still passes through, so the run's
#      rate-limited exit fires instead of hammering a refusing tenant.
#   4. No probe ships a credential the source itself marks non-functional.
#   5. The coverage DENOMINATOR is the same predicate as the run loop. A plane
#      demanded and unreachable is a coverage failure every run, forever, with
#      no operator remedy - which is what defect A produced.
#   6. A skip is unreachable when the credential IS present, and names the
#      parameter an operator must supply when it is not.
#   7. A configured-but-unreadable credential FAILS the run. Degrading to the
#      skip would report a plane as unconfigured while its configuration sits
#      in the stack parameters.
#
# Every row is re-run against a template broken in exactly that row's
# dimension; a mutant that reds an unrelated row is treated as VOID rather than
# as a kill, and every mutant is parse-checked before its result is believed.
#
# Run: bash tests/regression-test-required/decision_shadow_canary_probe_preconditions_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TPL="$REPO_ROOT/infrastructure/cloudformation/synthetic-monitoring-decision-shadow.yaml"
ORCH="$REPO_ROOT/platform/orchestrator/run.go"

echo "=== decision-shadow canary: probe preconditions (#3602) ==="

# THE MIRROR STRIPS infrastructure/ AND NOT THIS FILE. sync-community-repo.yml
# excludes `infrastructure/` wholesale and names no exclusion for
# tests/regression-test-required/*, so this guard ships to getaxonflow/axonflow
# where its subject does not exist. A community checkout SKIPS; an enterprise
# tree - identified by ee/, which the same sync strips - FAILS, so the guard
# cannot pass vacuously in the tree it is meant to bite.
if [ ! -f "$TPL" ]; then
  if [ -d "$REPO_ROOT/ee" ]; then
    echo "  FAIL: $TPL not found in an enterprise tree - this guard cannot vacuously pass"
    exit 1
  fi
  echo "  SKIP: community checkout (no infrastructure/); this guard runs in the enterprise repository"
  exit 0
fi

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "  FAIL: PyYAML is unavailable; a guard that cannot parse the template must not report success"
  exit 1
fi

PY_BODY="$(mktemp)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP" "$PY_BODY"' EXIT

cat > "$PY_BODY" <<'PY'
# Prints one `ROW <name> <PASS|FAIL> <detail>` line per rule and always exits 0:
# the CALLER decides the verdict, so a mutant that makes the harness itself
# raise is distinguishable from a mutant a row caught. `$?` after a pipe is the
# pipe's, so nothing here is read through one.
import io, json, os, sys, yaml

TPL, ORCH = sys.argv[1], sys.argv[2]
rows = []


def row(name, ok, detail=''):
    rows.append((name, 'PASS' if ok else 'FAIL', detail))


class L(yaml.SafeLoader):
    pass


L.add_multi_constructor('!', lambda loader, suffix, node: None)


def lift(path):
    doc = yaml.load(io.open(path, encoding='utf-8'), Loader=L)
    srcs = [v['Properties']['Code']['ZipFile']
            for v in (doc.get('Resources') or {}).values()
            if isinstance(v, dict)
            and isinstance((v.get('Properties') or {}).get('Code'), dict)
            and 'ZipFile' in v['Properties']['Code']]
    if len(srcs) != 1:
        raise SystemExit('LIFT_FAILED expected exactly one inline Lambda, found %d' % len(srcs))
    return doc, srcs[0]


class _Quiet(object):
    """The canary PRINTS its report; those lines are not this harness's rows."""

    def __enter__(self):
        self._saved = sys.stdout
        sys.stdout = io.StringIO()
        return self

    def __exit__(self, *a):
        sys.stdout = self._saved
        return False


def load(src, provider_arn=''):
    # AWS_DEFAULT_REGION: the lifted source builds a boto3 client at module
    # level and botocore raises NoRegionError at import where nothing supplies
    # one. The client is constructed, never called.
    os.environ.update({
        'AWS_DEFAULT_REGION': 'us-east-1',
        'BASE_URL': 'https://x.invalid', 'PROBE_MODE': 'community-saas',
        'VARIANTS_PER_PLANE': '2',
        'ALERT_TOPIC_ARN': 'not-an-arn-never-published-to-in-this-test',
        'ORG_ID': '', 'CREDENTIAL_SECRET_ARN': '', 'USER_TOKEN_SECRET_ARN': '',
        'MINTED_CREDENTIAL_SECRET_ARN': '',
        'PROVIDER_KEY_SECRET_ARN': provider_arn,
    })
    ns = {}
    exec(compile(src, 'canary', 'exec'), ns)
    return ns


doc, src = lift(TPL)
orch = io.open(ORCH, encoding='utf-8').read()

# --------------------------------------------------------------------------
# 1. plan_execute supplies the field the ENDPOINT requires.
#
# The requirement is read from the handler, not remembered: if the orchestrator
# stops demanding plan_id this row must stop demanding it too, and if the
# handler is gone the guard says so rather than asserting into a void.
# --------------------------------------------------------------------------
REQUIRES = 'plan_id is required in context'
READS = 'req.Context["plan_id"]'
endpoint_requires = REQUIRES in orch and READS in orch
row('endpoint_still_requires_plan_id', endpoint_requires,
    'orchestrator/run.go %s the refusal and %s the context read'
    % ('carries' if REQUIRES in orch else 'HAS LOST', 'carries' if READS in orch else 'HAS LOST'))

ns = load(src)
calls = []


def _recorder(status_seq):
    seq = list(status_seq)

    def _req(method, path, body=None, basic_auth=None, headers=None):
        calls.append({'method': method, 'path': path, 'body': body,
                      'headers': headers or {}})
        return seq.pop(0) if seq else (200, {'success': True}, {})
    return _req


del calls[:]
ns['_request'] = _recorder([
    # the generate call mints a plan, as /api/v1/plan does through the agent
    (200, {'success': True, 'plan_id': 'plan_1757000000_abcd1234'}, {}),
    (200, {'success': True, 'result': 'done', 'policy_info': {'matched_policies': []}}, {}),
])
got = ns['_probe_plan_execute'](('t', 's'), 'c', None, {'text': 'x', 'id': 'p'}, 'm')

two_calls = len(calls) == 2
row('plan_execute_mints_a_plan_first', two_calls,
    'the probe made %d request(s); /api/v1/plan/execute executes a STORED plan, '
    'so a plan must be minted for THIS tenant on THIS stack first' % len(calls))

if two_calls:
    exec_body = calls[1]['body'] or {}
    ctx = exec_body.get('context') or {}
    supplied = ctx.get('plan_id') == 'plan_1757000000_abcd1234'
    row('plan_execute_supplies_plan_id_in_context', supplied,
        'the execute request context carries plan_id=%r; the handler reads '
        'context.plan_id and refuses without it (run.go:4925)' % (ctx.get('plan_id'),))
    row('plan_execute_generates_with_the_flattening_request_type',
        (calls[0]['body'] or {}).get('request_type') == 'multi-agent-plan',
        'the first request_type is %r; both multi-agent-plan and generate-plan '
        'route to /api/v1/plan, but only multi-agent-plan reaches the block at '
        'agent/run.go:2972 that lifts plan_id to the top level of the response, '
        'so under generate-plan the id is returned and unreadable here'
        % (calls[0]['body'] or {}).get('request_type'))
    row('plan_execute_targets_the_execute_route',
        exec_body.get('request_type') == 'execute-plan',
        'the second request_type is %r; only execute-plan routes to '
        '/api/v1/plan/execute (agent/run.go:3262)' % exec_body.get('request_type'))
    ev, why = ns['_evaluated'](got[0], got[1])
    row('a_completed_plan_execution_is_evidence', ev,
        'a governed execute response scores evaluated=%s (%s)' % (ev, why))
else:
    for n in ('plan_execute_supplies_plan_id_in_context',
              'plan_execute_generates_with_the_flattening_request_type',
              'plan_execute_targets_the_execute_route',
              'a_completed_plan_execution_is_evidence'):
        row(n, False, 'not reached: the probe did not make two requests')

# --------------------------------------------------------------------------
# 2. The precondition response is never credited to this probe's planes.
#
# The generate call is evaluated by the PROXY planes. A 403 carrying policy_info
# is real evidence - about a plane this probe is not measuring. Returning it
# verbatim is how a plane gets reported covered while its own evaluator has
# never run, which is the reading this canary exists to refuse.
# --------------------------------------------------------------------------
BLOCKED = (403, {'success': False, 'blocked': True,
                 'block_reason': 'Blocked by static policy',
                 'policy_info': {'matched_policies': ['sys_pii_ssn']}}, {})
del calls[:]
ns['_request'] = _recorder([BLOCKED])
st, bd, _hd = ns['_probe_plan_execute'](('t', 's'), 'c', None, {'text': 'x', 'id': 'p'}, 'm')
ev, why = ns['_evaluated'](st, bd)
row('a_blocked_generate_is_not_evidence_for_wcp_or_map', not ev,
    'a probe whose plan was never minted scored evaluated=%s (%s)' % (ev, why))
row('and_the_report_says_what_it_saw',
    isinstance(bd, dict) and 'generate_status' in bd and bd.get('generate_status') == 403,
    'the wrapped body carries the response it could not use: %s'
    % json.dumps(bd)[:160] if isinstance(bd, dict) else repr(bd)[:160])

# --------------------------------------------------------------------------
# 3. A 429 on the first call passes through, so the rate-limited exit fires.
# --------------------------------------------------------------------------
del calls[:]
ns['_request'] = _recorder([(429, {'error': 'Rate limit exceeded (25 req/min).'},
                             {'retry-after': '60'})])
st, bd, hd = ns['_probe_plan_execute'](('t', 's'), 'c', None, {'text': 'x', 'id': 'p'}, 'm')
row('a_429_on_the_generate_call_is_passed_through',
    st == 429 and hd.get('retry-after') == '60',
    'the probe returned status %r headers %r; wrapping it would hide a limiter '
    'behind a precondition message and let the run keep spending calls' % (st, hd))

# --------------------------------------------------------------------------
# 4. No probe ships a credential the source itself marks non-functional.
# --------------------------------------------------------------------------
# STRING LITERALS ONLY, VIA THE AST. A presence check that greps text is
# satisfied by the comment explaining the rule; an ABSENCE check that greps text
# is DEFEATED by it, which is the same defect with the sign flipped - and it
# fired on the first run of this guard, against the comment above _probe_openai
# describing the very key it had removed. Docstrings are excluded for the same
# reason: prose is not a credential.
BAD_CREDENTIAL_MARKERS = ('not-a-real-key', 'not_a_real_key', 'placeholder-key',
                          'changeme', 'REPLACE_ME', 'sk-axonflow')


def _code_string_literals(source):
    import ast
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = (node.body or [None])[0]
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                docstrings.add(id(first.value))
    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in docstrings):
            out.append(node.value)
    return out


literals = _code_string_literals(src)
hits = sorted({m for m in BAD_CREDENTIAL_MARKERS
               if any(m in lit for lit in literals)})
row('no_probe_ships_a_known_non_functional_credential', not hits,
    'the canary source carries %s; a credential the tree itself calls '
    'non-functional cannot authenticate, and a probe that pages on its own '
    'placeholder pages unactionably' % (', '.join(repr(h) for h in hits) or 'none'))

# --------------------------------------------------------------------------
# 5. The coverage denominator is the run loop's own predicate.
#
# Driven, not grepped: `expected` is rebuilt by running the REAL handler with a
# transport that answers nothing, and every plane it demands must belong to an
# entry `_skip_reason` says runs.
# --------------------------------------------------------------------------
ns2 = load(src, provider_arn='')
ns2['_credentials'] = lambda run_id, results: ((('t', 's'), 't', None), None)
ns2['sns'] = type('S', (), {'publish': staticmethod(lambda **k: None)})()
ns2['_request'] = lambda *a, **k: (0, 'no transport in this harness', {})
with _Quiet():
    report = ns2['handler']({}, None)
# THE DENOMINATOR, READ FROM THE REPORT AND NEVER DEFAULTED TO EMPTY. The first
# version read planes_not_reached | planes_covered, which the COVERAGE FAILURE
# did not carry - so the run this harness always takes produced an empty set and
# both rows below passed vacuously against a template whose denominator had been
# reverted. An absent denominator is now a FAILURE of these rows, not a quiet
# zero.
#
# IT IS A UNION OF FOUR, AND TWO OF THEM WOULD BE A VACUITY BUG. #3555 publishes
# the coverage reading as plane SETS rather than as the denominator itself, and
# its stated contract is that every expected plane appears in at least one of the
# four non-structural ones. With this harness's transport nothing evaluates, so
# every plane that HAS a single-plane probe lands in planes_no_evidence - a field
# neither planes_covered nor planes_not_reached carries. Reading only those two
# would have re-created the same empty set this comment was written about.
DENOM_FIELDS = ('planes_covered', 'planes_inferred_only',
                'planes_no_evidence', 'planes_not_reached')
missing_fields = [f for f in DENOM_FIELDS if f not in report]
demanded = set()
for f in DENOM_FIELDS:
    demanded.update(report.get(f) or [])
denominator_readable = not missing_fields and bool(demanded)
row('the_run_report_publishes_the_denominator_it_judged_against', denominator_readable,
    'the report is missing %s and its plane sets union to %d plane(s) '
    '(failed_step=%r); a coverage page that does not say what it demanded '
    'cannot be audited, and every rule below it would pass on an empty set'
    % (missing_fields or 'no field', len(demanded), report.get('failed_step')))
runnable = set()
skipped_planes = set()
for e in ns2['PLANE_MAP']:
    (skipped_planes if ns2['_skip_reason'](e) else runnable).update(e['planes'])
orphans = sorted(demanded - runnable)
row('every_demanded_plane_has_a_probe_that_runs', denominator_readable and not orphans,
    'the coverage denominator demands %s, which no runnable probe can produce; '
    'a plane demanded and unreachable fails coverage on every run with no '
    'operator remedy' % (orphans or 'nothing unreachable'))
# THE SKIP MAP TRAVELS WITH THE REPORT. Without it a run that covers ten planes
# and skips two reads identically to one that covers twelve, on every exit
# including ok=True - and the plane an operator has to act on is the one that is
# not there.
reported_skips = report.get('planes_skipped')
row('the_run_report_names_the_planes_it_did_not_probe',
    isinstance(reported_skips, dict) and set(reported_skips) == skipped_planes
    and all(reported_skips.values()),
    'the report names %r as skipped and the predicate skips %r, each with a '
    'stated reason' % (sorted(reported_skips or []), sorted(skipped_planes)))
row('openai_compatible_leaves_the_denominator_when_unconfigured',
    denominator_readable and 'openai_compatible' not in demanded
    and 'openai_compatible' in skipped_planes,
    'with no provider key configured the plane is skipped=%s and demanded=%s'
    % ('openai_compatible' in skipped_planes, 'openai_compatible' in demanded))

# --------------------------------------------------------------------------
# 6. The skip is unreachable when the credential IS present.
# --------------------------------------------------------------------------
oa = [e for e in ns2['PLANE_MAP'] if e['probe'] == 'openai']
if len(oa) != 1:
    row('the_skip_is_unreachable_when_a_key_is_configured', False,
        'expected exactly one openai entry in PLANE_MAP, found %d' % len(oa))
    row('the_skip_names_the_parameter_an_operator_must_supply', False, 'not reached')
else:
    unconfigured = ns2['_skip_reason'](oa[0])
    ns3 = load(src, provider_arn='a-configured-secret-reference')
    configured = ns3['_skip_reason']([e for e in ns3['PLANE_MAP'] if e['probe'] == 'openai'][0])
    row('the_skip_is_unreachable_when_a_key_is_configured',
        bool(unconfigured) and configured == '',
        'unconfigured -> %r, configured -> %r' % (unconfigured[:60], configured))
    row('the_skip_names_the_parameter_an_operator_must_supply',
        'DecisionShadowProviderKeySecretArn' in unconfigured,
        'the skip reason is %r' % unconfigured[:120])

# --------------------------------------------------------------------------
# 7. A configured-but-unreadable credential FAILS the run.
# --------------------------------------------------------------------------
ns4 = load(src, provider_arn='a-configured-secret-reference')
ns4['_credentials'] = lambda run_id, results: ((('t', 's'), 't', None), None)
ns4['sns'] = type('S', (), {'publish': staticmethod(lambda **k: None)})()
ns4['_request'] = lambda *a, **k: (0, '', {})


def _boom(arn):
    raise RuntimeError('AccessDeniedException')


ns4['_secret'] = _boom
with _Quiet():
    rep4 = ns4['handler']({}, None)
row('an_unreadable_configured_key_fails_rather_than_skipping',
    rep4.get('failed_step') == 'read-provider-key',
    'the run reported failed_step=%r; degrading to the skip path would report '
    'the plane as unconfigured while its configuration sits in the stack '
    'parameters' % rep4.get('failed_step'))

ns5 = load(src, provider_arn='a-configured-secret-reference')
ns5['_credentials'] = lambda run_id, results: ((('t', 's'), 't', None), None)
ns5['sns'] = type('S', (), {'publish': staticmethod(lambda **k: None)})()
ns5['_request'] = lambda *a, **k: (0, '', {})
ns5['_secret'] = lambda arn: '   '
with _Quiet():
    rep5 = ns5['handler']({}, None)
row('an_empty_configured_key_fails_too', rep5.get('failed_step') == 'read-provider-key',
    'an empty secret reported failed_step=%r' % rep5.get('failed_step'))

for name, verdict, detail in rows:
    print('ROW %s %s %s' % (name, verdict, detail.replace('\n', ' ')))
PY

run_rows() {
  # NO PIPE. `$?` after a pipeline is the pipeline's, and the rows are the
  # verdict anyway - a harness that raised prints no rows, which the caller
  # detects as a missing row rather than as a pass.
  python3 "$PY_BODY" "$1" "$ORCH" > "$2" 2> "$2.err"
  return $?
}

parse_ok() {
  python3 - "$1" <<'PY' >/dev/null 2>&1
import io, sys, yaml
class L(yaml.SafeLoader): pass
L.add_multi_constructor('!', lambda l, s, n: None)
doc = yaml.load(io.open(sys.argv[1], encoding='utf-8'), Loader=L)
srcs = [v['Properties']['Code']['ZipFile']
        for v in (doc.get('Resources') or {}).values()
        if isinstance(v, dict)
        and isinstance((v.get('Properties') or {}).get('Code'), dict)
        and 'ZipFile' in v['Properties']['Code']]
assert len(srcs) == 1
compile(srcs[0], 'canary', 'exec')
PY
}

PASS=0
FAIL=0
ok() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

BASE="$TMP/base.rows"
if ! parse_ok "$TPL"; then
  bad "the template does not parse, or its inline Lambda does not compile; nothing below could be trusted"
  echo ""; echo "FAILED: $FAIL check(s), $PASS passed"; exit 1
fi
run_rows "$TPL" "$BASE"
rc=$?
if [ ! -s "$BASE" ]; then
  bad "the harness produced no rows (exit $rc): $(head -3 "$BASE.err" 2>/dev/null | tr '\n' ' ')"
  echo ""; echo "FAILED: $FAIL check(s), $PASS passed"; exit 1
fi

# ONLY `ROW ` LINES ARE ROWS. The canary PRINTS its own report, and the first
# version of this loop read those lines as verdicts - fourteen "failures" whose
# names were fragments of a JSON payload.
grep '^ROW ' "$BASE" > "$BASE.rows" 2>/dev/null
if [ ! -s "$BASE.rows" ]; then
  bad "the harness emitted no ROW lines (exit $rc): $(head -3 "$BASE.err" 2>/dev/null | tr '\n' ' ')"
  echo ""; echo "FAILED: $FAIL check(s), $PASS passed"; exit 1
fi
ROW_NAMES="$(awk '{print $2}' "$BASE.rows")"
while read -r _tag name verdict detail; do
  if [ "$verdict" = "PASS" ]; then ok "$name"; else bad "$name - $detail"; fi
done < "$BASE.rows"

# ---------------------------------------------------------------------------
# THE GUARD'S OWN FALSIFIABILITY.
#
# Four ways a control lies, all four addressed here: the plant is asserted to
# LAND (its anchor must be present, and the mutant must differ); the mutant is
# PARSE-CHECKED before its rows are believed; the exit code is never read
# through a pipe; and the named row is asserted to EXIST in the baseline before
# its absence can be mistaken for a kill. A mutant that reds a row other than
# its own is VOID, not a kill - a plant that breaks everything proves nothing.
# ---------------------------------------------------------------------------
echo ""
echo "=== the guard's own falsifiability ==="

mutate() {
  # mutate <name> "<row ...>" <old> <new>
  #
  # The second argument is the EXPECTED FAILING SET, not a single row. Some
  # defects legitimately red more than one row - removing the mint step takes
  # every row downstream of it with it - and a rule of "exactly one" would have
  # forced those rows to be weakened until they stopped noticing. The assertion
  # is therefore on the SHAPE of the diff: the observed failing set must EQUAL
  # the declared one. A mutant that reds more is VOID (it broke the harness, not
  # the rule) and one that reds fewer is a detector that cannot fire.
  local name="$1" want="$2" old="$3" new="$4"
  local f="$TMP/mutant.yaml" out="$TMP/mutant.rows"
  local r
  for r in $want; do
    if ! printf '%s\n' "$ROW_NAMES" | grep -Fxq "$r"; then
      bad "mutation '$name': the row '$r' does not exist in the baseline; its absence cannot be a kill"
      return
    fi
  done
  OLD="$old" NEW="$new" python3 - "$TPL" "$f" <<'PY'
import io, os, sys
src, dst = sys.argv[1], sys.argv[2]
old, new = os.environ['OLD'], os.environ['NEW']
text = io.open(src, encoding='utf-8').read()
if old not in text:
    sys.stderr.write('anchor not present\n')
    raise SystemExit(3)
out = text.replace(old, new, 1)
if out == text:
    sys.stderr.write('replacement changed nothing\n')
    raise SystemExit(4)
io.open(dst, 'w', encoding='utf-8').write(out)
PY
  if [ $? -ne 0 ]; then
    bad "mutation '$name': the plant did not land; its anchor is no longer in the template"
    return
  fi
  if ! parse_ok "$f"; then
    bad "mutation '$name': the mutant does not parse/compile, so its rows say nothing (VOID)"
    return
  fi
  run_rows "$f" "$out"
  grep '^ROW ' "$out" > "$out.rows" 2>/dev/null
  if [ ! -s "$out.rows" ]; then
    bad "mutation '$name': the harness emitted no ROW lines on the mutant (VOID): $(head -2 "$out.err" 2>/dev/null | tr '\n' ' ')"
    return
  fi
  local got_set want_set
  got_set="$(awk '$3 == "FAIL" {print $2}' "$out.rows" | sort | tr '\n' ' ')"
  want_set="$(printf '%s\n' $want | sort | tr '\n' ' ')"
  if [ "$got_set" = "$want_set" ]; then
    ok "mutation '$name' reds exactly [ ${want_set}]"
  else
    bad "mutation '$name': reds [ ${got_set:-nothing}] but should red [ ${want_set}]"
  fi
}

mutate "the execute request stops carrying plan_id" \
  "plan_execute_supplies_plan_id_in_context" \
  "'context': {'canary': marker, 'plan_id': plan_id}}" \
  "'context': {'canary': marker}}"

mutate "the probe stops minting a plan and posts execute-plan alone" \
  "plan_execute_mints_a_plan_first plan_execute_supplies_plan_id_in_context plan_execute_generates_with_the_flattening_request_type plan_execute_targets_the_execute_route a_completed_plan_execution_is_evidence a_blocked_generate_is_not_evidence_for_wcp_or_map and_the_report_says_what_it_saw" \
  "              g_status, g_body, g_headers = _request('POST', '/api/request', body=gen,
                                                     basic_auth=auth)" \
  "              g_status, g_body, g_headers = (200, {'plan_id': 'x'}, {})"

mutate "the precondition response is returned verbatim" \
  "a_blocked_generate_is_not_evidence_for_wcp_or_map and_the_report_says_what_it_saw" \
  "              if not plan_id:
                  return 0, {PROBE_PRECONDITION_KEY:" \
  "              if not plan_id:
                  return g_status, g_body, g_headers
              if not plan_id:
                  return 0, {PROBE_PRECONDITION_KEY:"

mutate "a 429 on the generate call is wrapped instead of passed through" \
  "a_429_on_the_generate_call_is_passed_through" \
  "              if g_status == 429:" \
  "              if g_status == -1:"

mutate "the generate call uses the request_type whose plan_id never surfaces" \
  "plan_execute_generates_with_the_flattening_request_type" \
  "              gen = {'client_id': client_id, 'request_type': 'multi-agent-plan'," \
  "              gen = {'client_id': client_id, 'request_type': 'generate-plan',"

mutate "the placeholder provider key comes back" \
  "no_probe_ships_a_known_non_functional_credential" \
  "              headers = {'X-Provider-Key': PROVIDER_KEY}" \
  "              headers = {'X-Provider-Key': 'sk-axonflow-canary-not-a-real-key-000000000000'}"

mutate "the denominator goes back to its own copy of the edition test" \
  "every_demanded_plane_has_a_probe_that_runs openai_compatible_leaves_the_denominator_when_unconfigured" \
  "              for entry in PLANE_MAP:
                  if not _skip_reason(entry):
                      expected.extend(entry['planes'])" \
  "              for entry in PLANE_MAP:
                  if PROBE_MODE in entry['editions']:
                      expected.extend(entry['planes'])"

mutate "the coverage failure stops publishing the denominator it judged against" \
  "the_run_report_publishes_the_denominator_it_judged_against every_demanded_plane_has_a_probe_that_runs the_run_report_names_the_planes_it_did_not_probe openai_compatible_leaves_the_denominator_when_unconfigured" \
  "                  return _fail('coverage', 0, '', run_id, results, '; and '.join(parts), cov)" \
  "                  return _fail('coverage', 0, '', run_id, results, '; and '.join(parts))"

mutate "the skip map stops travelling with the report" \
  "the_run_report_names_the_planes_it_did_not_probe" \
  "                  'planes_skipped': cov['skipped']," \
  "                  'planes_skipped': [],"

mutate "the skip is keyed on the key VALUE instead of the configuration" \
  "the_skip_is_unreachable_when_a_key_is_configured" \
  "              if entry['probe'] == 'openai' and not PROVIDER_KEY_SECRET_ARN:" \
  "              if entry['probe'] == 'openai' and not PROVIDER_KEY:"

mutate "a configured key is never read, so an unreadable one cannot fail the run" \
  "an_unreadable_configured_key_fails_rather_than_skipping an_empty_configured_key_fails_too" \
  "              global PROVIDER_KEY
              if PROVIDER_KEY_SECRET_ARN:" \
  "              global PROVIDER_KEY
              if False:"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "FAILED: $FAIL check(s), $PASS passed"
  exit 1
fi
echo ""
echo "PASS: $PASS check(s) - both probes can reach their own endpoint, the denominator matches the run loop, and no skip hides a configured credential"
