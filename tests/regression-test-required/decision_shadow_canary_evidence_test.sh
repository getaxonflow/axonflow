#!/usr/bin/env bash
# decision_shadow_canary_evidence_test.sh - the twelve-plane canary's evidence
# predicate, exercised against the response shapes the live stack actually
# returns (#3602).
#
# WHY THIS EXISTS
#
# The canary went live on community-SaaS and could not pass. The
# openai_compatible probe sent no X-Provider-Key, so /v1/chat/completions
# refused it at the presence check BEFORE any evaluation
# (openai_compat_handler.go:273) on every payload, and one failed probe ended
# the whole run - so eleven other planes recorded nothing either, every five
# minutes, into the alert topic.
#
# Two defects, and the second is the one a text assertion would miss:
#
#   1. the probe did not send the header at all;
#   2. the evidence predicate could not have scored the plane even with it.
#      A policy DENIAL on that route is HTTP 400 with `code: policy_denied` -
#      the same status the same handler uses for `missing_provider_key`, which
#      really is a pre-evaluation refusal. `400` was in NOT_EVALUATED_STATUSES,
#      so the plane's strongest evidence and its weakest were indistinguishable
#      by status. The rule now reads the CODE.
#
# This test runs the REAL predicate, lifted out of the template's inline
# Lambda, against the four shapes measured against the live stack plus two
# controls. A template-text assertion would have pinned the header and still
# let (2) ship.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

TPL='infrastructure/cloudformation/synthetic-monitoring-decision-shadow.yaml'

# THE SYNC STRIPS infrastructure/ FROM THE COMMUNITY MIRROR AND DOES NOT STRIP
# THIS FILE, so on a mirror checkout the template under test does not exist.
# The unconditional `exit 1` above made this test - and therefore
# tests/regression-test-required/run-all.sh, which is fail-closed by design and
# runs every *.sh in this directory - RED on the community mirror, on main,
# with nothing in the enterprise repository able to show it.
#
# The skip is gated on `ee/`, NOT on the template's absence, and the difference
# is the whole point: a bare `[ -f "$TPL" ] || exit 0` would also swallow the
# case this test exists for, a template deleted or renamed in the ENTERPRISE
# tree, and a guard that passes when its subject vanishes is worse than no
# guard. `ee/` is present in every enterprise checkout and stripped from every
# mirror one, so it distinguishes the two trees rather than the two failures.
# Same shape and same reasoning as community_workflow_twin_parity_test.sh.
if [ ! -f "$TPL" ]; then
  if [ -d ee ]; then
    echo "FAIL: $TPL not found in an enterprise tree - this test cannot vacuously pass"
    exit 1
  fi
  echo "SKIP: community checkout (the sync strips infrastructure/); this guard runs in the enterprise repository"
  exit 0
fi

echo "=== decision-shadow canary: the evidence predicate (#3602) ==="
python3 - "$TPL" <<'PY'
import json, os, re, sys, yaml

class L(yaml.SafeLoader):
    pass

L.add_multi_constructor('!', lambda loader, suffix, node: None)

doc = yaml.load(open(sys.argv[1]), Loader=L)
srcs = [v['Properties']['Code']['ZipFile']
        for v in (doc.get('Resources') or {}).values()
        if isinstance(v, dict)
        and isinstance((v.get('Properties') or {}).get('Code'), dict)
        and 'ZipFile' in v['Properties']['Code']]
if len(srcs) != 1:
    raise SystemExit(f"FATAL: expected exactly one inline Lambda, found {len(srcs)}; "
                     "the extraction is broken, not the template")
src = srcs[0]

# The probe must SEND the header, checked by driving the probe rather than by
# searching the source. A substring test passes on the COMMENT that explains
# the header - which is exactly what happened when this test was first written,
# and the planted removal went undetected.

# AWS_DEFAULT_REGION IS SET HERE BECAUSE THE LIFTED SOURCE CONSTRUCTS A BOTO3
# CLIENT AT MODULE LEVEL (`sns = boto3.client('sns')`).
#
# In Lambda the runtime supplies a region, so the original never needs one. On
# a CI runner nothing does, and botocore raises NoRegionError at IMPORT - before
# the predicate under test is ever reached. This passed locally and failed on
# CI, and the only difference was that this machine has a region in its AWS
# config. Same class as the digest tool that existed on macOS and not on the
# runner: a harness runs somewhere the original never runs.
#
# THE CLIENT IS CONSTRUCTED, NEVER CALLED. Nothing in this test publishes; the
# canary only reaches `sns.publish` on a failure path the harness does not take.
# The region is a value botocore demands to build an endpoint, not a target.
#
# Reproduce the runner's environment before trusting a green run here:
#   env -u AWS_DEFAULT_REGION -u AWS_REGION -u AWS_PROFILE \
#       AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
#       bash tests/regression-test-required/decision_shadow_canary_evidence_test.sh
# Unsetting the variables alone is NOT enough - ~/.aws/config still supplies a
# region, which is why the first attempt to reproduce this locally passed.
#
# Lifting only the predicate would avoid the client entirely, and is rejected:
# a copy drifts from the template, and this test exists because the template's
# real behaviour is what matters.

# THE ALERT TOPIC VALUE IS DELIBERATELY NOT ARN-SHAPED.
#
# The tests hygiene scan (repository-gates.yml) refuses ANY line under tests/ carrying an AWS ARN prefix -
# not
# just one with a 12-digit account, which is what the first version here tripped
# on. It cannot tell a placeholder from a real ARN and should not try, since its
# failure mode is leaking one.
#
# The right fix is not a cleverer placeholder that slips past the pattern -
# evading a secret scanner is the wrong move whatever the string. It is that
# THIS VALUE IS NEVER USED AS AN ARN HERE: the canary reads it at import and
# passes it to `TopicArn=` only when publishing a failure, a path this harness
# never takes. It needs the key to exist, nothing more.
# EVERY KEY HERE IS ONE THE LAMBDA READS, and the check below keeps it that way
# (R3 round 4, F12). Four of the nine were invented - VARIANTS, SECRET_ARN,
# LICENSE_SECRET_ARN, JWT_SECRET_ARN - against a Lambda that reads
# VARIANTS_PER_PLANE, CREDENTIAL_SECRET_ARN and USER_TOKEN_SECRET_ARN. Harmless
# only by accident: the runs took the defaults. `VARIANTS` in particular reads
# as the knob controlling the driven runs and is not one, so the next person
# tuning the 429 fixture reaches for a name nothing consumes.
_HARNESS_ENV = {'BASE_URL': 'https://x.invalid', 'PROBE_MODE': 'community-saas',
                'VARIANTS_PER_PLANE': '6', 'TIMEOUT_SECONDS': '20',
                'ALERT_TOPIC_ARN': 'not-an-arn-never-published-to-in-this-test',
                'ORG_ID': 'o', 'CREDENTIAL_SECRET_ARN': '',
                'MINTED_CREDENTIAL_SECRET_ARN': '', 'USER_TOKEN_SECRET_ARN': '',
                # DELIBERATELY EMPTY: the openai probe is SKIPPED here, which is
                # the state every driven row below is written against. Setting it
                # would make the handler read a secret this harness has no
                # transport for, and the skip path is the one an unconfigured
                # stack takes.
                'PROVIDER_KEY_SECRET_ARN': ''}
# AWS_DEFAULT_REGION is read by boto3, not by the Lambda source, so it is set
# outside the checked set rather than exempted inside it.
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
os.environ.update(_HARNESS_ENV)

ns = {}
exec(compile(src, 'canary', 'exec'), ns)
evaluated = ns['_evaluated']

# ---- the probe really sends X-Provider-Key -------------------------------
# _request is replaced with a recorder, so this observes the call the probe
# MAKES rather than the text around it.
sent = {}


def _recording_request(method, path, body=None, headers=None, basic_auth=None):
    sent.update({'method': method, 'path': path, 'headers': headers or {}})
    # THREE VALUES since #3865: the probe returns the response HEADERS too,
    # because which limiter refused a 429 is carried there and nowhere in the
    # status. A stub still returning two would make every probe raise at
    # unpacking, which is the point of updating it here rather than loosening
    # the caller.
    return 400, {"error": {"code": "policy_denied"}}, {}


# THE REAL ONE IS KEPT AND PUT BACK. A later row drives it over a socket, and
# a recorder left installed would silently answer that row instead - which is
# exactly what happened while writing it: the transport row passed against the
# stub and its own planted mutation could not red it.
_real_request = ns['_request']
ns['_request'] = _recording_request
# THE KEY IS NOW A SECRET, so the probe is driven with one installed. Before
# this it was a module constant and this row passed with no setup - which is
# exactly what let a key that could never authenticate ship: the row asserted
# the header was SENT and nothing asserted the value could work.
ns['PROVIDER_KEY'] = 'test-provider-key-never-transmitted-in-this-test'
ns['_probe_openai'](('t', 's'), 'c', None, {'text': 'x', 'id': 'p'}, 'm')
ns['_request'] = _real_request

if sent.get('path') != '/v1/chat/completions':
    print(f"  FAIL: the openai probe posted to {sent.get('path')!r}, not /v1/chat/completions")
    raise SystemExit(1)
if not sent['headers'].get('X-Provider-Key'):
    print("  FAIL: the openai probe sends no X-Provider-Key. /v1/chat/completions refuses the "
          "request at the presence check BEFORE any evaluation, so the openai_compatible plane "
          "produces no evidence on any payload (openai_compat_handler.go:273).")
    raise SystemExit(1)
print("  PASS: the openai probe sends X-Provider-Key on the request it makes")

# The four shapes were MEASURED against try.getaxonflow.com, not invented.
cases = [
    ("a policy denial on the openai route is EVIDENCE", 400,
     {"error": {"message": "Request blocked by policy: sqli", "type": "policy_violation",
                "code": "policy_denied"}}, True),
    ("a missing provider key is NOT evidence", 400,
     {"error": {"message": "X-Provider-Key header is required.",
                "code": "missing_provider_key"}}, False),
    ("an upstream auth failure is NOT counted, though the evaluation happened", 401,
     {"error": {"message": "Incorrect API key provided", "code": "invalid_api_key"}}, False),
    ("a JSON-RPC method-not-found served 200 is NOT evidence", 200,
     {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}}, False),
    ("a governed 2xx is evidence", 200, {"allowed": True, "policy_info": {}}, True),
    ("a bare 400 with no code is NOT evidence", 400,
     {"error": {"message": "bad request"}}, False),
    # THE ORDINARY GOVERNED DENY SHAPE (R3 round 2, F4). A 403 whose body
    # carries `error` AND `policy_info` is the strongest evidence this canary
    # can collect, and the predicate scored it NOT evaluated - the JSON-RPC
    # branch matched on `error` alone and ran first, printing a reason that
    # claimed a 2xx status the response did not have. Eight of thirteen corpus
    # payloads expect a deny.
    ("a governed 403 carrying policy_info IS evidence", 403,
     {"error": "Request blocked by policy: sqli", "policy_info": {"policy": "sys_sqli"}}, True),
    ("a governed 403 with only an error string IS evidence - a deny is an evaluation", 403,
     {"error": "Request blocked by policy"}, True),
    # And the branch that used to swallow them still refuses what it exists for:
    # a JSON-RPC error served 200, with no governance field and no denial.
    ("a JSON-RPC error served 200 is still NOT evidence", 200,
     {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}}, False),
]
fail = 0

_env_read = set(re.findall(r"os\.environ(?:\.get)?[\[(]'([A-Z0-9_]+)'", src))
_env_dead = sorted(k for k in _HARNESS_ENV if k not in _env_read)
if _env_dead:
    fail += 1
    print(f"  FAIL: the harness sets {_env_dead}, which the Lambda never reads. A dead key reads "
          "as a knob controlling these runs and is not one; use the name the source uses, or "
          "drop it.")
else:
    print(f"  PASS: all {len(_HARNESS_ENV)} environment keys this harness sets are read by the "
          "Lambda source")
for name, status, body, want in cases:
    got, why = evaluated(status, body)
    if got == want:
        print(f"  PASS: {name}")
    else:
        fail += 1
        print(f"  FAIL: {name}: evaluated={got}, want={want} (reason: {why})")

# AND THE REFUSAL MESSAGE MUST NAME THE STATUS IT SAW. The branch this row
# exists for printed "served with a 2xx status" for any error body, which is an
# instrument describing a response it did not receive.
#
# IT MUST BE DRIVEN AT A STATUS THAT REACHES THAT BRANCH (R3 round 4, F3). The
# row used to pass 404, which is in NOT_EVALUATED_STATUSES and returns three
# branches earlier from the status table - so the JSON-RPC reason was fully
# re-plantable with this row green. 409 is not in that table, carries no
# governance field and no policy denial, and so lands exactly where the fix
# lives. The 404 case is kept beside it: the two reasons come from different
# branches and both must name their status.
for _st in (404, 409):
    _, _why = evaluated(_st, {"error": {"message": "nope"}})
    if str(_st) in _why and '2xx' not in _why:
        print(f"  PASS: the refusal reason for a {_st} names the status actually received")
    else:
        fail += 1
        print(f"  FAIL: a {_st} was refused with the reason {_why!r}, which does not name {_st} "
              "or still claims a 2xx")

# The two 400s must not be scored the same way, which is the whole point.
denied, _ = evaluated(400, {"error": {"code": "policy_denied"}})
nokey, _ = evaluated(400, {"error": {"code": "missing_provider_key"}})
if denied and not nokey:
    print("  PASS: the two HTTP 400s are told apart by code, not status")
else:
    fail += 1
    print("  FAIL: the openai route's policy denial and its missing-key refusal are both HTTP 400 "
          "and this predicate scores them the same; the plane's strongest evidence and its "
          "weakest are indistinguishable")

# ---- a 429 says WHICH limiter, or says it does not know (#3865) ----------
#
# The canary used to print "the canary tenant reached its community-SaaS quota"
# from `status == 429` alone. At least three limiters answer 429 on this agent
# and they are enforced in different places, so that sentence was a claim the
# instrument could not have observed. Two people built two wrong readings on it
# while closing the ADR-065 window, in opposite directions.
#
# THE SHAPES BELOW ARE THE PLATFORM'S OWN, not invented:
#   daily quota  writeRateLimitError, community_saas_ratelimit_response.go:118
#                -> X-Axonflow-Tier-Limit: daily_quota + limit_type in the body
#   per minute   enforceCommunitySaasDailyCap, proxy.go:110 -> Retry-After: 60,
#                a bare {"error": "..."} body, and NO limit_type anywhere
#   per minute   the pre-bcrypt ceiling, auth.go:349 through writeJSONError
#                -> {"error": {"code": 429, "message": ...}}, Retry-After: 60
rl = ns['_rate_limit_evidence']
sentence = ns['_rate_limit_sentence']
headers_of = ns['_headers']

DAILY_HDRS = {'x-axonflow-tier-limit': 'daily_quota',
              'x-axonflow-upgrade-url': 'https://getaxonflow.com/pricing/',
              'retry-after': '52341'}
DAILY_BODY = {"error": "Daily request limit reached. Resets at midnight UTC.",
              "limit_type": "daily_quota", "tier": "Free", "limit": 200,
              "remaining": 0, "window": "daily_utc",
              "resets_at": "2026-09-09T00:00:00Z"}

ev = rl(429, DAILY_BODY, DAILY_HDRS)
if ev['cause'] == 'daily_quota' and ev['cause_source'] == 'header':
    print("  PASS: a real daily-quota 429 is named daily_quota, from the header")
else:
    fail += 1
    print(f"  FAIL: the daily-quota 429 was read as {ev['cause']!r} "
          f"(source {ev['cause_source']!r})")
if ev['limit_detail'].get('limit') == 200 and ev['limit_detail'].get('window') == 'daily_utc':
    print("  PASS: the limit, tier and window are carried into the report")
else:
    fail += 1
    print(f"  FAIL: the envelope's own numbers were dropped: {ev['limit_detail']}")

# ---- THE FIXTURE THIS ISSUE EXISTS FOR -----------------------------------
# A 429 that names a DIFFERENT limiter must not be reported as the daily quota.
OTHER_HDRS = {'x-axonflow-tier-limit': 'hitl_approvals_window', 'retry-after': '600'}
OTHER_BODY = {"error": "HITL approval limit reached for the last 7 days.",
              "limit_type": "hitl_approvals_window", "tier": "Free", "limit": 2,
              "window": "rolling_7d"}
ev_other = rl(429, OTHER_BODY, OTHER_HDRS)
if ev_other['cause'] == 'hitl_approvals_window':
    print("  PASS: a 429 naming a different limiter is reported as THAT limiter")
else:
    fail += 1
    print(f"  FAIL: a 429 whose body and header both say hitl_approvals_window was "
          f"reported as {ev_other['cause']!r}")
if 'daily_quota' not in sentence(ev_other) and 'daily' not in sentence(ev_other):
    print("  PASS: and the sentence does not mention the daily quota at all")
else:
    fail += 1
    print(f"  FAIL: the sentence for a non-daily limiter still says: {sentence(ev_other)}")

# ---- the per-minute shapes: NOT DETERMINED, and it says so ---------------
for name, body, hdrs in [
    ("the tier per-minute burst (proxy.go:110)",
     {"error": "Rate limit exceeded (25 req/min). Try again shortly."},
     {'retry-after': '60'}),
    ("the pre-bcrypt ceiling (auth.go:349 via writeJSONError)",
     {"error": {"code": 429, "message": "Rate limit exceeded (200 req/min). Try again shortly."}},
     {'retry-after': '60'}),
    ("an upstream 429 with a non-JSON body", "Too Many Requests", {'retry-after': '1'}),
]:
    e = rl(429, body, hdrs)
    s = sentence(e)
    if e['cause'] == 'not_determined' and 'NOT DETERMINED' in s:
        print(f"  PASS: {name} is reported as not_determined, and says so")
    else:
        fail += 1
        print(f"  FAIL: {name} was reported as {e['cause']!r}: {s}")
    if e['observed_headers'].get('retry-after') != hdrs['retry-after']:
        fail += 1
        print(f"  FAIL: {name}: the Retry-After header was not recorded")

# The sentence must never state the old claim, whatever the shape.
banned = 'reached its community-SaaS quota'
if all(banned not in sentence(rl(429, b, h)) for b, h in
       [(DAILY_BODY, DAILY_HDRS), (OTHER_BODY, OTHER_HDRS),
        ({"error": "Rate limit exceeded (25 req/min). Try again shortly."}, {'retry-after': '60'})]):
    print("  PASS: no shape produces the old unobserved claim")
else:
    fail += 1
    print(f"  FAIL: the report still asserts {banned!r} for some shape")

# ---- the body alone is enough when the header is absent ------------------
ev_body_only = rl(429, DAILY_BODY, {'retry-after': '52341'})
if ev_body_only['cause'] == 'daily_quota' and ev_body_only['cause_source'] == 'body':
    print("  PASS: with no X-Axonflow-Tier-Limit header the body's limit_type is used, "
          "and the report says the name came from the body")
else:
    fail += 1
    print(f"  FAIL: header-less daily quota read as {ev_body_only['cause']!r} "
          f"(source {ev_body_only['cause_source']!r})")

# ---- AN UNREADABLE BODY MUST NOT PRODUCE A DIFFERENT CONFIDENT SENTENCE ----
#
# The defect this change closes is a confident sentence assembled from something
# the tool never read. The failure mode of the FIX is the same shape one step
# along: substituting a different confident sentence when the cause cannot be
# read. So every shape of unreadable body is asserted to reach exactly one
# place - `not_determined`, said out loud - and never a named limiter.
for name, body in [
    ("an EMPTY body (what _decode returns for a zero-length response)", ""),
    ("a body that is None", None),
    ("a JSON ARRAY body", []),
    ("an HTML error page from a proxy in front of the platform", "<html>429</html>"),
    ("a dict with NO limit_type at all", {"error": "something"}),
    ("a dict whose limit_type is not a string", {"limit_type": 429}),
    ("a dict whose limit_type is empty", {"limit_type": ""}),
]:
    e = rl(429, body, {})
    s_ = sentence(e)
    if e['cause'] == 'not_determined' and e['cause_source'] == 'none' and 'NOT DETERMINED' in s_:
        print(f"  PASS: {name} -> not_determined, and the report says so")
    else:
        fail += 1
        print(f"  FAIL: {name} produced cause={e['cause']!r} source={e['cause_source']!r}: {s_[:120]}")

# And the header still wins when the BODY is unreadable: an unreadable body is
# not a reason to discard evidence that did arrive.
e = rl(429, "<html>429</html>", {'x-axonflow-tier-limit': 'daily_quota', 'retry-after': '60'})
if e['cause'] == 'daily_quota' and e['cause_source'] == 'header':
    print("  PASS: an unreadable body does not discard a limiter the HEADER named")
else:
    fail += 1
    print(f"  FAIL: a header-named limiter was lost to an unreadable body: {e['cause']!r}")

# ---- THE HEADER AND THE BODY DISAGREE: nobody wins ------------------------
#
# A precedence rule not written down is one that got invented by accident. The
# platform writes both from ONE value (writeRateLimitError sets the header and
# limit_type from the same limitType), so a disagreement means one of them was
# rewritten in transit - and a proxy rewrites headers far more readily than
# bodies, which makes the header the LESS trustworthy side exactly when they
# differ. Picking either would be this canary's original defect with a tidier
# rule behind it: two sources naming different limiters is a contradiction, not
# knowledge.
e = rl(429, {"limit_type": "hitl_approvals_window", "tier": "Free"},
       {'x-axonflow-tier-limit': 'daily_quota', 'retry-after': '60'})
if e['cause'] == 'not_determined' and e['cause_source'] == 'conflict':
    print("  PASS: a header and body naming DIFFERENT limiters is not_determined, not a winner")
else:
    fail += 1
    print(f"  FAIL: a conflict resolved to {e['cause']!r} (source {e['cause_source']!r}) - a "
          "precedence rule was applied where there is no ground for one")
if e.get('cause_header') == 'daily_quota' and e.get('cause_body') == 'hitl_approvals_window':
    print("  PASS: and BOTH values are recorded, so the reader sees what it was")
else:
    fail += 1
    print(f"  FAIL: the conflicting values were not both recorded: {e!r}")
s_ = sentence(e)
if 'NAMED TWO DIFFERENT limiters' in s_ and 'NOT DETERMINED' in s_:
    print("  PASS: and the sentence says the response named two different limiters")
else:
    fail += 1
    print(f"  FAIL: the conflict sentence does not say so: {s_[:140]}")

# AND THE NUMBERS MUST NOT BE COMPOSED EITHER. `limit_detail` is collected from
# the BODY, so carrying it on a conflict glues the body limiter's tier and window
# onto a report whose NAME is undetermined - one limiter's numbers filed under
# another's story, with an honest label on top. Fixing the cause and leaving the
# detail composed is the defect surviving in the half nobody looked at.
if e['limit_detail'] == {} and 'compose two limiters' in e.get('limit_detail_withheld', ''):
    print("  PASS: a conflict carries NO composed numbers, and says why they were withheld")
else:
    fail += 1
    print(f"  FAIL: a conflict still composes the body's numbers into the record: "
          f"{e['limit_detail']!r} / {e.get('limit_detail_withheld')!r}")
# Nothing is LOST by withholding them: the whole body is still in the report.
if 'hitl_approvals_window' in e['response_body'] and e['cause_body'] == 'hitl_approvals_window':
    print("  PASS: and the raw body survives, so a reader can compose it and know that they did")
else:
    fail += 1
    print("  FAIL: withholding the detail also lost the evidence it came from")

# AGREEMENT is not a conflict: the ordinary case must be unaffected.
e = rl(429, {"limit_type": "daily_quota"}, {'x-axonflow-tier-limit': 'daily_quota'})
if e['cause'] == 'daily_quota' and e['cause_source'] == 'header':
    print("  PASS: header and body AGREEING is still daily_quota, from the header")
else:
    fail += 1
    print(f"  FAIL: agreement was treated as a conflict: {e['cause']!r}/{e['cause_source']!r}")

# ---- a transport failure carries no headers and must not name a cause ----
ev_none = rl(0, "URLError(...)", {})
if ev_none['cause'] == 'not_determined' and ev_none['cause_source'] == 'none':
    print("  PASS: a response that never arrived names no limiter")
else:
    fail += 1
    print(f"  FAIL: a transport failure was read as {ev_none['cause']!r}")

# ---- the header normaliser is what makes the lookups one spelling --------
#
# urllib returns an HTTPMessage whose .get is case-insensitive; a dict's is not.
# If the normalisation were left to the lookups, the classifier would pass
# against a live response and fail against a fixture differing only in case -
# the shape where a green test proves nothing about production.
class _Msg(object):
    def __init__(self, pairs):
        self._p = pairs

    def items(self):
        return self._p


norm = headers_of(_Msg([('X-Axonflow-Tier-Limit', 'daily_quota'), ('Retry-After', '60')]))
if norm == {'x-axonflow-tier-limit': 'daily_quota', 'retry-after': '60'}:
    print("  PASS: response headers are lowercased at the boundary")
else:
    fail += 1
    print(f"  FAIL: the header normaliser produced {norm!r}")
if rl(429, {}, norm)['cause'] == 'daily_quota':
    print("  PASS: and a mixed-case live response classifies the same as a fixture")
else:
    fail += 1
    print("  FAIL: a mixed-case header set does not classify as daily_quota")

# ---- THE TRANSPORT really returns headers, over a real socket ------------
#
# WHY A SERVER AND NOT A STUB. The handler row below replaces `_request`
# wholesale, so it proves handler -> classifier and says NOTHING about
# transport -> handler. Gutting the real `_request` back to two values was
# planted while writing this and the suite stayed GREEN: every row that could
# have seen it was downstream of the stub. This row is the one that reds.
#
# Port 0: the kernel assigns an ephemeral port, so this borrows nothing from
# the runtime-e2e host-port registry and cannot collide with a concurrent run.
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _RateLimited(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        payload = json.dumps(DAILY_BODY).encode()
        self.send_response(429)
        self.send_header('Content-Type', 'application/json')
        # Mixed case on the wire, as a real server sends it.
        self.send_header('X-Axonflow-Tier-Limit', 'daily_quota')
        self.send_header('Retry-After', '52341')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):
        pass


# THREE RETURN STATEMENTS, THREE ROWS. `_request` returns from the 2xx path, the
# HTTPError path and the transport-failure path, and the row below only ever
# receives a 429 - so it exercises the HTTPError branch alone. Gutting either of
# the other two back to a 2-tuple left this whole suite GREEN, and production
# unpacks THREE values on every probe, so either regression raises ValueError on
# the first non-429 response: the entire canary dead, with NO SNS alert because
# an unhandled exception never reaches the failure path.
#
# **A control is scoped by what its FIXTURE can produce, not by what the function
# contains.** Counting the return statements is the check that finds this.
class _Governed(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        payload = json.dumps({"allowed": True, "policy_info": {}}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Some-Header', 'Mixed-Case')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):
        pass


def _drive(handler_cls, path='/api/v1/decide'):
    srv = HTTPServer(('127.0.0.1', 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    saved = ns['BASE_URL']
    ns['BASE_URL'] = 'http://127.0.0.1:%d' % srv.server_address[1]
    try:
        return ns['_request']('POST', path, body={'x': 1})
    finally:
        ns['BASE_URL'] = saved
        srv.shutdown()


# (a) the 2xx branch
ok200 = _drive(_Governed)
if isinstance(ok200, tuple) and len(ok200) == 3 and ok200[0] == 200:
    print("  PASS: the 2xx branch of _request returns three values over a socket")
    if ok200[2].get('x-some-header') == 'Mixed-Case':
        print("  PASS: and the 2xx branch lowercases its headers like the error branch")
    else:
        fail += 1
        print(f"  FAIL: the 2xx branch's headers are wrong: {ok200[2]!r}")
else:
    fail += 1
    print(f"  FAIL: the 2xx branch returned {ok200!r}; production unpacks three values on "
          "every probe, so this is the whole canary dead on the first non-429 response - "
          "and silently, because an unhandled exception never reaches the SNS path")

# (b) the transport-failure branch. Port 0 is not connectable by construction, so
# this needs no fixture server.
saved_base = ns['BASE_URL']
ns['BASE_URL'] = 'http://127.0.0.1:0'
try:
    dead = ns['_request']('POST', '/api/v1/decide', body={'x': 1})
finally:
    ns['BASE_URL'] = saved_base
if isinstance(dead, tuple) and len(dead) == 3 and dead[0] == 0 and dead[2] == {}:
    print("  PASS: the transport-failure branch returns three values, status 0, no headers")
else:
    fail += 1
    print(f"  FAIL: the transport-failure branch returned {dead!r}")

# (c) the HTTPError branch, which is what the rate-limit classification rides on
got = _drive(_RateLimited)

if not (isinstance(got, tuple) and len(got) == 3):
    fail += 1
    print(f"  FAIL: _request returned {len(got) if isinstance(got, tuple) else type(got)} "
          "value(s); the response headers are dropped at the transport, so the "
          "classifier below is correct and can never be reached with real input")
else:
    st, bd, hd = got
    if st == 429 and hd.get('x-axonflow-tier-limit') == 'daily_quota':
        print("  PASS: _request returns the real response's headers, lowercased, over a socket")
    else:
        fail += 1
        print(f"  FAIL: _request returned status={st} headers={hd!r}")
    if rl(st, bd, hd)['cause'] == 'daily_quota':
        print("  PASS: and a genuinely-received 429 classifies as daily_quota end to end")
    else:
        fail += 1
        print("  FAIL: a real 429 off the wire did not classify as daily_quota")

# ---- THE WIRING, driven rather than asserted -----------------------------
#
# Everything above exercises the classifier in isolation, which would pass just
# as well if `handler` never handed it the response headers. So this drives the
# REAL handler over a stubbed transport and reads the report it returns. The
# defect being guarded is not "the classifier is wrong" - it is "the instrument
# reports a cause it did not observe", and only the whole path can show that.
ns['_credentials'] = lambda run_id, results: ((('t', 's'), 't', None), None)


def _rate_limited_transport(method, path, body=None, basic_auth=None, headers=None):
    # The tier per-minute burst, verbatim from proxy.go:110-116: Retry-After,
    # a bare error body, and no limit_type anywhere.
    return (429, {"error": "Rate limit exceeded (25 req/min). Try again shortly."},
            {'retry-after': '60'})


ns['_request'] = _rate_limited_transport
report = ns['handler']({}, None)

if report.get('rate_limited') is True and report.get('ok') is False:
    print("  PASS: a rate-limited run still reports rate_limited=True and ok=False")
else:
    fail += 1
    print(f"  FAIL: the rate-limited exit changed shape: "
          f"ok={report.get('ok')!r} rate_limited={report.get('rate_limited')!r}")

if report.get('rate_limit_cause') == 'not_determined':
    print("  PASS: the handler's own report says the cause was not determined")
else:
    fail += 1
    print(f"  FAIL: the handler reported rate_limit_cause="
          f"{report.get('rate_limit_cause')!r} for a response naming no limiter")

if report.get('rate_limit_headers', {}).get('retry-after') == '60':
    print("  PASS: the response headers reach the report through the handler, "
          "not only through the classifier")
else:
    fail += 1
    print("  FAIL: the handler dropped the response headers - the classifier is "
          "correct and unreachable, which is the defect this test exists for")

# AND, NOT OR. The first version was `'quota' not in detail or 'NOT DETERMINED' in detail`,
# and `detail` ALWAYS contains the word "quota" - the not-determined sentence lists the
# daily quota as one of the candidates - so the first clause is permanently False and the
# row collapsed to "contains NOT DETERMINED". Restoring the exact banned sentence to
# `detail` kept it GREEN. A guard whose halves are joined by `or` is satisfied by
# whichever half is trivially true.
_d = report.get('detail', '')
if 'NOT DETERMINED' in _d and banned not in _d:
    print("  PASS: the handler's detail says NOT DETERMINED and does not carry the banned claim")
else:
    fail += 1
    print(f"  FAIL: the handler's detail is wrong: {_d[:200]}")

# THE BANNED SENTENCE, CHECKED WHERE IT WOULD ACTUALLY APPEAR. The earlier `banned` row
# only ever read `_rate_limit_sentence`; the string that reaches an operator is
# `report['detail']`, which is the sentence PLUS a prefix, and nothing asserted over it.
if banned not in _d:
    print("  PASS: the report's own detail never carries the old unobserved claim")
else:
    fail += 1
    print(f"  FAIL: report['detail'] carries {banned!r}")

# THE RAW EVIDENCE THE HONEST SENTENCE POINTS AT. `detail` tells the reader to read the
# body rather than assume the quota, so a report whose body is empty makes that sentence
# an instruction to look at nothing. Neutering _clip was green before this row.
_b = report.get('rate_limit_body', '')
if isinstance(_b, str) and 'req/min' in _b:
    print("  PASS: rate_limit_body carries the response the detail tells the reader to read")
else:
    fail += 1
    print(f"  FAIL: rate_limit_body is not the response body: {_b!r}")

if report.get('rate_limited_probe') and report.get('stopped_at'):
    print("  PASS: the report names the probe and payload that was refused")
else:
    fail += 1
    print("  FAIL: the report does not say which probe was refused")

# ---- TEARDOWN, and a row that proves it ----------------------------------
#
# The suite ended with `_request` and `_credentials` still stubbed. Appending any
# row after the wiring block got the STUB's answer - which is the exact trap this
# file already records paying for once, when a leftover recorder answered the
# socket row. A lesson recorded in a comment and not enforced in the fixture gets
# paid for a third time.
ns['_request'] = _real_request
del ns['_credentials']

probe = _drive(_Governed)
if isinstance(probe, tuple) and probe[0] == 200:
    print("  PASS: teardown restored the real _request - a row added after this one "
          "reaches the network, not a stub")
else:
    fail += 1
    print(f"  FAIL: _request is still stubbed after teardown: {probe!r}")
if '_credentials' not in ns:
    print("  PASS: teardown removed the _credentials stub")
else:
    fail += 1
    print("  FAIL: the _credentials stub outlived the test that installed it")


# ═════════════════════════════════════════════════════════════════════════
# COVERAGE: AN INFERENCE IS NOT EVIDENCE (#3555)
# ═════════════════════════════════════════════════════════════════════════
#
# `_coverage` had NO test at all, and it is the function that decides whether a
# plane counts as covered. Both exits summed evidenced|inferred into
# `planes_covered` and the coverage gate was read off that sum, so a plane
# reached ONLY by a multi-plane probe satisfied the gate. The map plane was
# reported covered seventeen times in one day against a counter that has never
# left zero.
#
# The rows below drive the REAL lifted functions, never a re-implementation.

coverage = ns['_coverage']
evidenceable = ns['_evidenceable']
inference_sources = ns['_inference_sources']
plane_map = ns['PLANE_MAP']

# ANTI-VACUITY FIRST. Every row below is a statement about PLANE_MAP, and a
# lifted table that came back empty or single-shaped would make them all
# vacuously true.
_single = [e for e in plane_map if len(e['planes']) == 1]
_multi = [e for e in plane_map if len(e['planes']) > 1]
if len(plane_map) >= 8 and _single and _multi:
    print(f"  PASS: the lifted plane map has {len(plane_map)} entries, "
          f"{len(_single)} single-plane and {len(_multi)} multi-plane")
else:
    fail += 1
    print(f"  FAIL: the lifted plane map is {plane_map!r}; the rows below would examine nothing")

# THE PLANE THIS EXISTS FOR IS PICKED FROM THE TABLE, NOT NAMED (R3 round 1, F6).
# Six rows used to hard-code `map`. The single most likely legitimate future
# change - giving map its own single-plane probe, which closing #3886 enables -
# would have reddened five of them with messages that were FALSE, sending the
# next engineer after a regression that did not exist. These rows are about the
# CLASS "a plane with no single-plane probe", so they follow the table.
_ent_expected = set()
for _e in plane_map:
    if 'enterprise' in _e['editions']:
        _ent_expected.update(_e['planes'])
_never_ent = sorted(_ent_expected - evidenceable('enterprise'))
_cs_expected = set()
for _e in plane_map:
    if 'community-saas' in _e['editions']:
        _cs_expected.update(_e['planes'])
_never_cs = sorted(_cs_expected - evidenceable('community-saas'))
if _never_cs:
    INFERRED_ONLY_PLANE = _never_cs[0]
    print(f"  PASS: the never-evidenceable class is non-empty in the community-saas posture; "
          f"these rows follow the table and use {INFERRED_ONLY_PLANE!r}")
else:
    INFERRED_ONLY_PLANE = None
    fail += 1
    print("  FAIL: every plane is evidenceable in the community-saas posture, so the rows below "
          "have no subject. If a single-plane probe was genuinely added for every plane, these "
          "rows are stale rather than broken - but say so deliberately instead of passing.")

# ---- a single-plane probe EVIDENCES; a multi-plane probe does NOT --------
#
# THE FIXTURE PLANES COME FROM THE TABLE, like INFERRED_ONLY_PLANE above. Named
# literals here would go stale on the same change that makes them stale there,
# and a stale literal in one row used to disable the row nested inside it.
# AND IT MUST BE A PLANE THIS RUN ACTUALLY PROBES. _evidenceable reads the
# table; _skip_reason decides what is sent. Selecting a skipped plane here would
# starve a probe that never ran and assert a class it can never be in.
_skipped_cs = set()
for _e in plane_map:
    if ns['_skip_reason'](_e):
        _skipped_cs.update(_e['planes'])
_SINGLE_PLANE = sorted(evidenceable('community-saas') - _skipped_cs)[0]
_MULTI_PAIR = None
_cs_evidenceable = evidenceable('community-saas')
for _e in plane_map:
    if 'community-saas' not in _e['editions'] or len(_e['planes']) < 2:
        continue
    # BOTH members must be inference-only, or the fixtures below assert the
    # wrong class: a plane that ALSO has its own probe belongs in no_evidence,
    # not in not_reached. Selecting on the property the rows depend on is what
    # keeps them correct when a plane gains a single-plane probe - which is
    # exactly what closing #3886 enables.
    if set(_e['planes']) & _cs_evidenceable:
        continue
    _MULTI_PAIR = sorted(_e['planes'])
    _MULTI_PROBE = _e['probe']
    break
if _MULTI_PAIR is None:
    fail += 1
    print("  FAIL: no two-plane probe in the community-saas posture; the rows below have no "
          "subject and would examine nothing")
    _MULTI_PAIR, _MULTI_PROBE = ['a', 'b'], 'none'

_c1 = coverage('community-saas', [_SINGLE_PLANE] + list(_MULTI_PAIR), [
    {'probe': 'p', 'planes': [_SINGLE_PLANE], 'evaluated': True},
    {'probe': _MULTI_PROBE, 'planes': list(_MULTI_PAIR), 'evaluated': True},
])
if _c1['covered'] == [_SINGLE_PLANE] and sorted(_c1['inferred_only']) == sorted(_MULTI_PAIR):
    print("  PASS: a single-plane probe evidences its plane; a two-plane probe evidences neither")
else:
    fail += 1
    print(f"  FAIL: _coverage returned covered={_c1['covered']}, "
          f"inferred_only={sorted(_c1['inferred_only'])}; want [{_SINGLE_PLANE!r}] and "
          f"{_MULTI_PAIR}")

# THE POSITIVE TWIN for the negative above: an UNEVALUATED probe must
# contribute to neither set, or "inferred" would just mean "was attempted".
_c2 = coverage('community-saas', list(_MULTI_PAIR),
               [{'probe': _MULTI_PROBE, 'planes': list(_MULTI_PAIR), 'evaluated': False}])
if not _c2['covered'] and not _c2['inferred_only'] and _c2['not_reached'] == _MULTI_PAIR:
    print("  PASS: a probe that was not evaluated contributes to neither set and is not_reached")
else:
    fail += 1
    print(f"  FAIL: an unevaluated probe produced {_c2!r}")

# THE PARTITION ROW IS NOT NESTED INSIDE THE ONE ABOVE (R3 round 2). It used to
# be, so a stale literal in the sibling silently DISABLED it rather than failing
# it - a check that disappears is worse than one that reds.
_c3 = coverage('community-saas', [_SINGLE_PLANE] + list(_MULTI_PAIR), [])
if _c3['no_evidence'] == [_SINGLE_PLANE] and _c3['not_reached'] == sorted(_MULTI_PAIR):
    print("  PASS: and the two failure sets PARTITION - a plane with its own probe appears "
          "in the sharper list only, never in both")
else:
    fail += 1
    print(f"  FAIL: no_evidence={_c3['no_evidence']} not_reached={_c3['not_reached']}; "
          "the two sets overlap, so the alert names a plane twice")

# ---- the inference source is read from RESULTS, not from the table ------
#
# R3 round 1, F5: the first version walked PLANE_MAP and took the first entry
# naming the plane, so with two multi-plane probes over one plane it reported
# whichever came first in the TABLE rather than whichever actually evaluated -
# an instrument reporting a conclusion it did not observe, which is the exact
# defect this change removes, one layer out.
_src = inference_sources([
    {'probe': 'plan_execute', 'planes': ['wcp', 'map'], 'evaluated': True},
], {'map'})
if _src.get('map', {}).get('probe') == 'plan_execute' and _src['map']['shared_with'] == ['wcp']:
    print("  PASS: an inferred plane is reported with the probe that reached it and what it "
          "shares that probe with, so the inference can be judged rather than trusted")
else:
    fail += 1
    print(f"  FAIL: the inference source is {_src!r}; want probe=plan_execute, shared_with=['wcp']")

# A probe that did NOT evaluate must not be credited as the source.
_src2 = inference_sources([
    {'probe': 'never_ran', 'planes': ['wcp', 'map'], 'evaluated': False},
    {'probe': 'plan_execute', 'planes': ['wcp', 'map'], 'evaluated': True},
], {'map'})
if _src2.get('map', {}).get('probe') == 'plan_execute':
    print("  PASS: an unevaluated probe is not credited as the source of an inference")
else:
    fail += 1
    print(f"  FAIL: the inference source is {_src2!r}; a probe that produced nothing was named "
          "as the one that reached the plane")

# TWO probes over one plane are BOTH reported, rather than one chosen quietly.
_src3 = inference_sources([
    {'probe': 'probe_a', 'planes': ['wcp', 'map'], 'evaluated': True},
    {'probe': 'probe_b', 'planes': ['map', 'decide'], 'evaluated': True},
], {'map'})
if _src3.get('map', {}).get('probe') == ['probe_a', 'probe_b'] and \
        _src3['map']['shared_with'] == ['decide', 'wcp']:
    print("  PASS: a plane reached by two multi-plane probes reports BOTH, rather than whichever "
          "the table happened to list first")
else:
    fail += 1
    print(f"  FAIL: two probes over one plane produced {_src3!r}")

# ---- the synthetic-probe header, which nothing controlled ---------------
#
# The template's header calls this "thing #1 a reader must know": without
# X-Axonflow-Synthetic-Probe every comparison this canary drives is filed as
# ORGANIC tenant traffic and the ADR-065 volume floor is read off our own
# probes. Removing it left this whole suite AND the Go corpus tests green
# (R3 round 2). The openai probe's header is proven by driving the probe and
# recording the call; this is the same technique one header over.
# OBSERVED AT THE SOCKET, not at _request's arguments. The header is added
# INSIDE _request, below the layer a recorder replacing _request can see - so
# the technique the X-Provider-Key row uses (record what the PROBE passed) is
# the wrong layer here and would pass against a version that sent nothing.
_hdr_seen = {}


class _HeaderRecorder(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        _hdr_seen.update({k.lower(): v for k, v in self.headers.items()})
        payload = json.dumps({"allowed": True, "policy_info": {}}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):
        pass


_drive(_HeaderRecorder)
_hdr_lower = _hdr_seen
if _hdr_lower.get('x-axonflow-synthetic-probe'):
    print("  PASS: every request carries X-Axonflow-Synthetic-Probe on the wire, so these "
          "comparisons are filed synthetic rather than counted toward the organic floor")
else:
    fail += 1
    print(f"  FAIL: no synthetic-probe header arrived on the wire ({sorted(_hdr_seen)}). Every "
          "comparison this canary drives would be filed as ORGANIC tenant traffic, and the "
          "gate-18 volume floor would be read off our own probes - the exact failure #3817 "
          "added the label to prevent.")

# ---- `inferred -= evidenced`, the line #3886 activates -------------------
#
# A plane that is BOTH evidenced by its own probe and named by a multi-plane one
# must not appear in inferred_only: it has evidence, and listing it as an
# inference would understate what the run proved. No plane is in both kinds of
# entry today, so the line is a no-op on the live table and had no control.
_c_both = coverage('community-saas', [_SINGLE_PLANE] + list(_MULTI_PAIR), [
    {'probe': 'own', 'planes': [_SINGLE_PLANE], 'evaluated': True},
    {'probe': 'shared', 'planes': [_SINGLE_PLANE] + list(_MULTI_PAIR), 'evaluated': True},
])
if _SINGLE_PLANE in _c_both['covered'] and _SINGLE_PLANE not in _c_both['inferred_only']:
    print("  PASS: a plane with BOTH its own probe and a shared one is covered, not inferred - "
          "evidence outranks inference for the same plane")
else:
    fail += 1
    print(f"  FAIL: {_SINGLE_PLANE!r} is covered={_SINGLE_PLANE in _c_both['covered']} "
          f"inferred={_SINGLE_PLANE in _c_both['inferred_only']}; a plane with real evidence must "
          "not also be reported as an inference")

# ---- the derived class agrees with the table ----------------------------
#
# The COUNT is deliberately not pinned (R3 round 1, F6): it is posture-relative
# and a literal beside a table is the defect this PR is about. What is pinned is
# that the derivation and the table agree.
# THE MODEL IS "planes with NO single-plane entry", NOT "planes appearing in a
# multi-plane entry" (R3 round 2). The two are the same set only while no plane
# is in both kinds of entry - and giving `map` its own probe, which is exactly
# what closing #3886 enables, makes them differ. The earlier version would then
# have reddened with "the derivation disagrees with the table", which is FALSE:
# _evidenceable is right and the row's model was wrong. A control that lies
# about which side is broken sends the next engineer after a regression that
# does not exist.
_multi_members = set()
_single_members = set()
for _e in plane_map:
    if 'enterprise' not in _e['editions']:
        continue
    if len(_e['planes']) == 1:
        _single_members.add(_e['planes'][0])
    else:
        _multi_members.update(_e['planes'])
_by_hand = _multi_members - _single_members
if set(_never_ent) == _by_hand:
    print(f"  PASS: the never-evidenceable set is exactly the multi-plane members "
          f"({', '.join(sorted(_never_ent))}), derived from the table rather than restated")
else:
    fail += 1
    print(f"  FAIL: never-evidenceable is {_never_ent} and the multi-plane members are "
          f"{sorted(_by_hand)}; the derivation disagrees with the table")

# ---- THE GATE, DRIVEN THROUGH THE REAL HANDLER --------------------------
#
# THE FIRST VERSION OF THIS ROW COMPUTED `sorted(evidenced)` ITSELF AND WAS
# USELESS. Restoring the exact defect - `covered = sorted(evidenced | inferred)`
# - left it GREEN, because it re-implemented the line it was about and then
# agreed with itself. A re-implementation that agrees with the real thing is
# indistinguishable from a correct one.
#
# So this drives `handler` end to end and reads `planes_covered` OUT OF THE
# REPORT THE CANARY BUILDS. That is the field an operator reads as coverage and
# the field gate 18 is closed against.
_saved_request = ns.get('_request')
ns['_credentials'] = lambda run_id, results: ((('t', 's'), 't', None), None)


class _RecordingSNS:
    def __init__(self):
        self.published = []

    def publish(self, **kw):
        self.published.append(kw)
        return {'MessageId': 'recorded'}


_real_sns = ns['sns']


class _ForbiddenSNS:
    """The default client for the whole test: publishing is a HARNESS BUG.

    THE HEADER OF THIS FILE CLAIMED "nothing in this test publishes" AND THAT
    WAS TRUE BY LUCK. The all-governed run below was driven with the REAL boto3
    client still installed, because it was the one driven run that did not
    install a recorder first - and on a machine whose credentials resolve, the
    handler's failure path reached sns.publish and left the process. The
    observed result was an InvalidParameterException traceback on a TopicArn,
    which is an UNHANDLED EXCEPTION rather than a named FAIL: it aborted the
    interpreter and took roughly 35 later assertions with it - the exact mode
    the comment at the top of this file warns about.

    A claim about what a test does not do belongs in the harness, not in a
    comment. Any publish now raises here, naming the missing install, and can
    never reach AWS.
    """

    def __init__(self):
        self.violations = []

    def publish(self, **kw):
        # RECORDS, NEVER RAISES. Raising here would abort the interpreter and
        # take every later assertion with it - which is the same failure mode
        # as the live call it replaces, minus the network. The whole point is
        # to turn this into a NAMED failure that leaves the suite running, so
        # one harness bug costs one row instead of the back half of the file.
        self.violations.append(kw.get('TopicArn'))
        return {'MessageId': 'forbidden'}


_forbidden_sns = _ForbiddenSNS()
ns['sns'] = _forbidden_sns


# ONE GOVERNED BODY, AND IT CARRIES A plan_id.
#
# `allowed` and `policy_info` are governance fields, so _evaluated scores this
# as evidence of an evaluation. The plan_id is not decoration: plan_execute
# mints a plan before it can execute one, and a transport that answers every
# probe must answer THAT request too. Without it the probe stops at its own
# precondition and wcp/map are starved by the FIXTURE while the rows below
# blame the code - a control that fails for a reason it does not name.
_GOVERNED_BODY = {"allowed": True, "policy_info": {},
                  "plan_id": "plan_0000000000_fixture0"}


def _all_governed(method, path, body=None, basic_auth=None, headers=None):
    return 200, dict(_GOVERNED_BODY), {}


ns['_request'] = _all_governed
# A RECORDER, like every other driven row. Without it this run held the real
# boto3 client (see _ForbiddenSNS).
_sns_full = _RecordingSNS()
ns['sns'] = _sns_full
full = ns['handler']({}, None)
ns['sns'] = _forbidden_sns

# AND A SUCCESSFUL RUN MUST NOT PAGE. This is the assertion the missing install
# was hiding: if the all-governed transport ever stops producing a complete run,
# the row below still reports ok=False, but nothing said whether the canary had
# also woken someone up about it.
if not _sns_full.published:
    print("  PASS: the complete run published NOTHING to SNS - success is silent, which is what "
          "makes a page from this canary mean something")
else:
    fail += 1
    print(f"  FAIL: a run that completed successfully published {len(_sns_full.published)} SNS "
          f"message(s): {str(_sns_full.published)[:200]}")

if full.get('ok') is True:
    print("  PASS: the all-governed transport drives a complete run to the end-of-run exit")
else:
    fail += 1
    print(f"  FAIL: the driven run did not complete: {str(full)[:300]}")

_covered = full.get('planes_covered', [])
_inferred = full.get('planes_inferred_only', {})
_never = full.get('planes_never_evidenceable', [])

# THE ASSERTION THE CHANGE EXISTS FOR. Every plane was evaluated in this run, so
# the OLD code would have listed every one of them in planes_covered.
if INFERRED_ONLY_PLANE and INFERRED_ONLY_PLANE not in _covered:
    print(f"  PASS: on a run where every probe evaluated, planes_covered still excludes "
          f"{INFERRED_ONLY_PLANE!r}, which only a multi-plane probe reached")
else:
    fail += 1
    print(f"  FAIL: planes_covered is {_covered}; a plane reached only by inference is still "
          "counted as covered, which is the defect this change exists to remove")

# THE POSITIVE TWIN. Without it the row above passes against a handler that
# reports planes_covered=[] always, which would be a worse instrument.
if _covered and set(_covered) <= evidenceable('community-saas'):
    print(f"  PASS: and the planes a single-plane probe DID evidence are present ({_covered})")
else:
    fail += 1
    print(f"  FAIL: planes_covered is {_covered}; the evidenced planes are missing or are not "
          "evidenceable, so the row above passed by reporting nothing rather than by telling "
          "evidence from inference")

# WHAT AN INFERENCE MUST SAY ABOUT ITSELF (R3 round 4, F1)
#
# planes_inferred_only maps each inferred plane to the probe that reached it and
# what it shared that probe with. Until now every row checked only MEMBERSHIP,
# while the PASS text, the CHANGELOG bullet and the public docs page all
# described the structure - so replacing _inference_sources with
# `{p: {} for p in inferred}` left the suite green and emptied the one field
# whose content is the reason an inference can be judged rather than trusted.
#
# The expectation is DERIVED FROM THE TABLE, which is a different source than
# the run results _inference_sources walks. That makes this a cross-check
# rather than a second copy of the same derivation.
def _expected_inference(plane, mode):
    probes, shared = [], set()
    for e in plane_map:
        if mode not in e['editions'] or len(e['planes']) < 2 or plane not in e['planes']:
            continue
        probes.append(e['probe'])
        shared.update(set(e['planes']) - {plane})
    return sorted(probes), sorted(shared)


def _assert_inference_shape(field, plane, shape):
    global fail
    entry = (field or {}).get(plane)
    want_probes, want_shared = _expected_inference(plane, 'community-saas')
    if not isinstance(entry, dict):
        fail += 1
        print(f"  FAIL: the {shape} report's planes_inferred_only[{plane!r}] is {entry!r}. A bare "
              "list, or a mapping to an empty dict, says an inference HAPPENED without saying "
              "why it is worth nothing for this plane - which is the entire content of the field "
              "and is what the CHANGELOG and the operations page promise an operator.")
        return
    got = entry.get('probe')
    got_probes = [got] if isinstance(got, str) else sorted(got or [])
    if sorted(got_probes) == want_probes and entry.get('shared_with') == want_shared:
        print(f"  PASS: and the {shape} report says {plane!r} was reached by {got!r}, sharing "
              f"that probe with {entry.get('shared_with')} - matching the table, which is not "
              "the source the report was built from")
    else:
        fail += 1
        print(f"  FAIL: the {shape} report's planes_inferred_only[{plane!r}] is {entry!r}; the "
              f"plane map says probe(s) {want_probes} shared with {want_shared}")


if INFERRED_ONLY_PLANE and INFERRED_ONLY_PLANE in _inferred:
    print(f"  PASS: the run says in its own output that {INFERRED_ONLY_PLANE!r} was INFERRED, "
          "and by which probe")
else:
    fail += 1
    print(f"  FAIL: planes_inferred_only is {_inferred!r}; a run that inferred a plane must say "
          "so rather than leaving the reader to notice an absence")
if INFERRED_ONLY_PLANE:
    _assert_inference_shape(_inferred, INFERRED_ONLY_PLANE, "full")

if INFERRED_ONLY_PLANE and INFERRED_ONLY_PLANE in _never:
    print(f"  PASS: and it states that {INFERRED_ONLY_PLANE!r} can NEVER be evidenced by this "
          "canary, so its absence from planes_covered is permanent, not a regression")
else:
    fail += 1
    print(f"  FAIL: planes_never_evidenceable is {_never}; without it a reader cannot tell a "
          "structural gap from a broken probe")

# THE SUCCESS REPORT'S FIELD SET, asserted explicitly (R3 round 1, F8). A row
# that read `not full.get('planes_not_reached')` was always true, because the
# success report has no such key - it asserted nothing while reading as though
# it asserted the run reached every plane.
# THE FIELD SET IS ONE EXPECTATION CHECKED ON EVERY REPORT SHAPE (R3 round 2).
# The three shapes - success, rate-limited and coverage-failure - used to
# hand-write their own key lists, and the rate-limited one shipped MISSING
# planes_no_evidence. Because the two failure sets partition, that made a plane
# with its own probe that produced nothing appear in NO field at all, on the
# exit community-SaaS takes every run. A per-shape assertion would have caught
# it only where somebody thought to write one.
WANT_PLANE_KEYS = sorted(['planes_covered', 'planes_inferred_only',
                          'planes_never_evidenceable', 'planes_no_evidence',
                          'planes_not_reached', 'planes_skipped'])


def _assert_plane_fields(report, shape):
    global fail
    got = sorted(k for k in report if k.startswith('planes_'))
    if got == WANT_PLANE_KEYS:
        print(f"  PASS: the {shape} report carries exactly the coverage field set")
    else:
        fail += 1
        print(f"  FAIL: the {shape} report's coverage fields are {got}, want {WANT_PLANE_KEYS}. "
              "A field missing from one shape and present in another is a plane that vanishes "
              "from whichever report an operator happens to be reading.")


# AND NO PLANE VANISHES. Every expected plane must appear in at least one of
# the four non-structural fields - the property the operations page states for
# every report shape.
#
# ONE CHECK, APPLIED TO EVERY DRIVEN SHAPE (R3 round 4, F5). It was written for
# the rate-limited exit alone, where both failure sets are empty by fixture
# construction, so it could only ever exercise covered/inferred_only - a third
# of the property it was named for. AT LEAST one, deliberately, not exactly one:
# a plane with its own single-plane probe that also rides a shared probe is
# reported in inferred_only AND no_evidence, which are two different true
# statements about it. Only the two FAILURE sets partition each other.
def _assert_no_plane_vanishes(report, shape):
    global fail
    # THE DENOMINATOR, NOT THE TABLE. A plane whose entry is skipped is not
    # expected of this run - it left `expected` through the same predicate the
    # loop runs on - so demanding it here would fail the report for honouring
    # its own skip. _skip_reason is read rather than restated, so this row
    # cannot disagree with the code about which planes were asked for.
    want = set()
    for e in plane_map:
        if 'community-saas' in e['editions'] and not ns['_skip_reason'](e):
            want.update(e['planes'])
    accounted = (set(report.get('planes_covered', []))
                 | set(report.get('planes_inferred_only', []))
                 | set(report.get('planes_no_evidence', []))
                 | set(report.get('planes_not_reached', [])))
    missing = sorted(want - accounted)
    if not missing:
        print(f"  PASS: every expected plane appears in one of the {shape} report's fields - "
              "none vanishes between the partition and the field list")
    else:
        fail += 1
        print(f"  FAIL: {missing} appear in NO field of the {shape} report. The two failure sets "
              "partition each other, so a plane dropped from the field list is invisible rather "
              "than merely uncounted.")


_assert_plane_fields(full, "success")
_assert_no_plane_vanishes(full, "success")

# ---- THE RATE-LIMITED EXIT, WHICH IS THE ONE PRODUCTION TAKES -----------
#
# R3 round 1, F2: this is the exit community-SaaS takes on EVERY run, and it had
# no driven coverage assertion. Planting the old sum HERE ALONE left the whole
# suite green - the defect re-plantable, undetected, on the only exit that runs.
# The pre-existing 429 row above returns 429 to every request, so nothing is
# ever evidenced and planes_covered is [] whatever the code does; this one
# evaluates first and rate-limits after.
# THE THRESHOLD IS DERIVED. It must let the whole first breadth pass through
# and rate-limit only after it, or the run depends on the plane order the
# handler rotates on a random run_id. It was a literal 8 against 7 community
# entries, pinned by nothing, so adding entries would have moved the fixture
# out from under it silently.
#
# THE MARGIN IS ONE ENTRY, NOT TWO, AND THE BEHAVIOUR IS DETERMINISTIC - both
# corrections from the independent round, and both measured here rather than
# taken: 6 runs at each of 8/7/6/5 gave 6-0 green at 8, 6-0 green at 7, and
# 0-6 green at 6 and at 5. Minimum safe is 7 and the fixture is 8.
#
# An earlier version of this comment claimed "8 runs at half the value gave 6
# reds and 2 greens on identical code" and that does not reproduce. What I had
# actually observed was the NUMBER OF FAILING ROWS varying (3, 1, 3) across
# runs that all failed - variation inside a verdict, read as variation of the
# verdict. The change is still right; the evidence I published for it was not.
# COUNTED BY RUNNING THE PROBES, NOT BY COUNTING THE TABLE. An entry is not a
# request: plan_execute makes TWO (mint, then execute) and a skipped entry makes
# none, so `len(PLANE_MAP)` over-counts one way and under-counts the other, and
# the threshold it produced would cut the round at a place no row here names.
def _requests_in_one_round():
    n = {'i': 0}

    def _count(method, path, body=None, basic_auth=None, headers=None):
        n['i'] += 1
        return 200, dict(_GOVERNED_BODY), {}

    _saved = ns['_request']
    ns['_request'] = _count
    try:
        for _e in plane_map:
            if ns['_skip_reason'](_e):
                continue
            ns['PROBES'][_e['probe']](('u', 'p'), 'cid', None, {'text': 'x'}, 'm')
    finally:
        ns['_request'] = _saved
    return n['i']


_cs_entries = _requests_in_one_round()
_GOVERNED_CALLS = _cs_entries + 1
_calls = {'n': 0}


def _governed_then_429(method, path, body=None, basic_auth=None, headers=None):
    _calls['n'] += 1
    if _calls['n'] <= _GOVERNED_CALLS:
        return 200, dict(_GOVERNED_BODY), {}
    return 429, {"error": "Rate limit exceeded (25 req/min). Try again shortly."}, \
        {'retry-after': '60'}


ns['_request'] = _governed_then_429
partial_rl = ns['handler']({}, None)

if partial_rl.get('rate_limited') is True and partial_rl.get('ok') is False:
    print("  PASS: the 200-then-429 transport drives the rate-limited exit")
else:
    fail += 1
    print(f"  FAIL: expected the rate-limited exit, got {str(partial_rl)[:200]}")

_rl_covered = partial_rl.get('planes_covered', [])
_rl_inferred = partial_rl.get('planes_inferred_only', {})
if INFERRED_ONLY_PLANE and INFERRED_ONLY_PLANE not in _rl_covered:
    print(f"  PASS: the RATE-LIMITED exit also excludes {INFERRED_ONLY_PLANE!r} from "
          "planes_covered - the exit community-SaaS takes every run")
else:
    fail += 1
    print(f"  FAIL: the rate-limited exit reported planes_covered={_rl_covered}; the defect is "
          "re-plantable on the one exit that runs in production")

# The twin again, on this exit: it must have evidenced SOMETHING, or the row
# above passes because the run reached nothing at all.
if _rl_covered:
    print(f"  PASS: and the rate-limited exit evidenced {_rl_covered}, so the row above is about "
          "telling evidence from inference rather than about an empty run")
else:
    fail += 1
    print("  FAIL: the rate-limited exit evidenced nothing, so the exclusion above proves nothing")

if INFERRED_ONLY_PLANE and INFERRED_ONLY_PLANE in _rl_inferred:
    print(f"  PASS: and it reports {INFERRED_ONLY_PLANE!r} as inferred, with its probe")
else:
    fail += 1
    print(f"  FAIL: the rate-limited exit's planes_inferred_only is {_rl_inferred!r}")
if INFERRED_ONLY_PLANE:
    _assert_inference_shape(_rl_inferred, INFERRED_ONLY_PLANE, "rate-limited")

_assert_plane_fields(partial_rl, "rate-limited")

# THE FIXTURE'S OWN PROPERTY, ASSERTED. The comment below relies on both failure
# sets being empty on this shape; if the threshold above ever cut into the first
# breadth pass they would not be, and the "no plane vanishes" row would be
# exercising a different question than the one it names.
if not partial_rl.get('planes_no_evidence') and not partial_rl.get('planes_not_reached'):
    print("  PASS: the rate-limited fixture evaluated every community entry before the 429, so "
          "both failure sets are empty and the row below is about covered/inferred_only alone")
else:
    fail += 1
    print(f"  FAIL: the rate-limited run reported no_evidence="
          f"{partial_rl.get('planes_no_evidence')!r} not_reached="
          f"{partial_rl.get('planes_not_reached')!r}; the 429 threshold has cut into the first "
          "breadth pass, which makes this run depend on the handler's randomised plane order.")

_assert_no_plane_vanishes(partial_rl, "rate-limited")

# ---- the no_evidence gate, driven, and it must ALERT --------------------


# REFUSES BOTH CLASSES' SUBJECTS, so this one run has a non-empty
# planes_no_evidence AND a non-empty planes_not_reached - the only driven shape
# where the two failure fields can be told apart, which is what their value
# assertions on it need (R3 round 3).
#
# WHICH request to refuse is ASKED OF THE PROBE, not guessed from its name:
# THREE probes post request_type='llm_chat' and two post to /api/request, so any
# hand-written discriminator starves a probe the assertion does not name and
# fails for the wrong reason. Drive the selected probe against a capture
# transport and refuse exactly the shape it produced.
def _probe_signature(probe_name):
    seen = {}

    def _capture(method, path, body=None, basic_auth=None, headers=None):
        seen.update(method=method, path=path,
                    request_type=(body or {}).get('request_type')
                    if isinstance(body, dict) else None)
        return 200, dict(_GOVERNED_BODY), {}

    _saved = ns['_request']
    ns['_request'] = _capture
    try:
        ns['PROBES'][probe_name](('u', 'p'), 'cid', None, {'text': 'x'}, 'm')
    finally:
        ns['_request'] = _saved
    return (seen.get('method'), seen.get('path'), seen.get('request_type'))


# BOTH sides are derived. _SINGLE_PLANE already came from the table; its probe's
# REQUEST did not, and was a hardcoded `'decide' in path`. Renaming that route -
# behaviour unchanged, plane still single and still evidenceable - made three
# rows red with messages blaming the Lambda for a fixture that had stopped
# starving anything (R3 round 4, F6). Same class as the literals this PR removed
# from the code, one file over.
_SINGLE_PROBE = None
for _e in plane_map:
    if 'community-saas' in _e['editions'] and _e['planes'] == [_SINGLE_PLANE]:
        _SINGLE_PROBE = _e['probe']
        break
if _SINGLE_PROBE is None:
    fail += 1
    print(f"  FAIL: no community-saas entry has planes == [{_SINGLE_PLANE!r}], yet that plane was "
          "selected as evidenceable. The table disagrees with itself and every row below that "
          "starves a single-plane probe has no subject.")

_MULTI_SIG = _probe_signature(_MULTI_PROBE)
_SINGLE_SIG = _probe_signature(_SINGLE_PROBE) if _SINGLE_PROBE else (None, None, None)
_sig_sharers = sorted(n for n in ns['PROBES']
                      if n not in (_MULTI_PROBE, _SINGLE_PROBE)
                      and _probe_signature(n) in (_MULTI_SIG, _SINGLE_SIG))
if _sig_sharers or _MULTI_SIG == _SINGLE_SIG:
    fail += 1
    print(f"  FAIL: the coverage-failure drivers starve {_SINGLE_PROBE!r} {_SINGLE_SIG} and "
          f"{_MULTI_PROBE!r} {_MULTI_SIG}, but {_sig_sharers or 'the two signatures collide and'} "
          "send an indistinguishable request. The run would then report planes these assertions "
          "do not name, so every expectation below would be wrong even when the code is right - "
          "give the fixtures a sharper discriminator.")


def _refuses(*sigs):
    """A transport that refuses exactly the named probe signatures.

    ONE BUILDER for all three coverage-failure drivers (R3 round 4, F9): the
    both-classes driver was the literal union of the other two, written out a
    third time, which is a second system for a fixture whose whole job is to
    starve a set of probes.
    """
    want = set(sigs)

    def _transport(method, path, body=None, basic_auth=None, headers=None):
        _rt = body.get('request_type') if isinstance(body, dict) else None
        if (method, path, _rt) in want:
            return 401, {"error": {"message": "no", "code": "invalid_api_key"}}, {}
        return 200, dict(_GOVERNED_BODY), {}

    return _transport


_both_classes_refused = _refuses(_SINGLE_SIG, _MULTI_SIG)


_sns = _RecordingSNS()
ns['sns'] = _sns
ns['_request'] = _both_classes_refused
partial = ns['handler']({}, None)
ns['sns'] = _forbidden_sns
_detail = str(partial.get('detail', ''))
if partial.get('ok') is not True and 'decide' in _detail:
    print("  PASS: a plane with a single-plane probe that produced no evidence fails the run "
          "and is named in the failure")
else:
    fail += 1
    print(f"  FAIL: the run reported ok={partial.get('ok')} detail={_detail[:200]!r}")

# THE SUBSTRING IS THE DISTINCTIVE ONE, AND THE OBVIOUS CHOICE WAS WRONG.
# "single-plane probe" appears in BOTH failure messages, so asserting on it left
# the planted removal of the whole no_evidence gate GREEN.
if 'produced no EVIDENCE in this run' in _detail:
    print("  PASS: the failure names the SHARPER cause - the plane had its own probe and "
          "produced no evidence - rather than only the blunt 'never reached'")
else:
    fail += 1
    print(f"  FAIL: the coverage failure said {_detail[:160]!r}; the no_evidence branch is "
          "unreachable, which makes it a claim nothing can violate")

# THE STEP IS NAMED (R3 round 1, F4). 'decision-shadow' is in the Subject of
# EVERY failure this canary can raise, so asserting on it let a coverage failure
# relabelled `config` ship green - and a mislabelled failure routes to the wrong
# runbook.
if partial.get('failed_step') == 'coverage':
    print("  PASS: the failure is labelled failed_step=coverage, not merely 'a failure'")
else:
    fail += 1
    print(f"  FAIL: failed_step is {partial.get('failed_step')!r}, want 'coverage'")
if _sns.published and 'step=coverage' in str(_sns.published[0].get('Subject', '')):
    print("  PASS: and it alerts with the step in the Subject - a gate that fails silently, or "
          "under another step's name, is the same silence it was written to remove")
else:
    fail += 1
    print(f"  FAIL: the coverage failure published {_sns.published!r}")

# THE COVERAGE FIELDS TRAVEL WITH THE FAILURE (R3 round 1, F3). The runbook
# tells an operator to read three fields; the failure report carried none.
_assert_plane_fields(partial, "coverage-failure")
_assert_no_plane_vanishes(partial, "coverage-failure")

# THE TWO FAILURE FIELDS GET VALUE ASSERTIONS, NOT ONLY A KEY CHECK
# (R3 round 3). Swapping them in the builder, or emptying either, left the
# whole suite green - and the comment on the "vanish" row claimed IT would have
# caught a missing planes_no_evidence, which is false: the 200-then-429 fixture
# evaluates every community entry before the 429, so both failure sets are
# empty there and that row can only ever see covered and inferred_only.
#
# This run is the one where BOTH are non-empty, so it is the only place the two
# can be told apart. Derived from the table: `decide` has its own probe and was
# refused; the multi-plane pair was never reached.
_pne = sorted(partial.get('planes_no_evidence', []))
_pnr = sorted(partial.get('planes_not_reached', []))
if _pne == [_SINGLE_PLANE]:
    print(f"  PASS: the coverage failure reports planes_no_evidence={_pne} - the plane with its "
          "own probe that produced nothing")
else:
    fail += 1
    print(f"  FAIL: planes_no_evidence is {_pne}, want [{_SINGLE_PLANE!r}]. A refused single-plane "
          "probe belongs in the SHARPER class; reporting it elsewhere routes an operator to the "
          "wrong fix, which is the whole reason the two classes are separate.")
if _pnr == sorted(_MULTI_PAIR):
    print(f"  PASS: and planes_not_reached={_pnr} - the planes no evaluated probe touched")
else:
    fail += 1
    print(f"  FAIL: planes_not_reached is {_pnr}, want {sorted(_MULTI_PAIR)}.")
# AND THE TWO ARE NOT THE SAME LIST. Swapping them in the builder satisfies
# neither row above only because the two expectations differ; assert the
# disjointness directly so a future fixture where they coincide cannot hide it.
if set(_pne) & set(_pnr):
    fail += 1
    print(f"  FAIL: planes_no_evidence and planes_not_reached share {sorted(set(_pne) & set(_pnr))}; "
          "the two failure sets must partition or the alert names a plane twice")

# AND ITS planes_covered IS EVIDENCE ONLY. A key-PRESENCE check was all this
# report had, so the old evidenced|inferred sum was still plantable here with a
# green suite (R3 round 2) - in the one report an operator actually reads when
# the gate fires.
_cf_covered = partial.get('planes_covered', [])
if INFERRED_ONLY_PLANE and INFERRED_ONLY_PLANE not in _cf_covered:
    print("  PASS: and its planes_covered is evidence only, like every other report shape")
else:
    fail += 1
    print(f"  FAIL: the coverage failure's planes_covered is {_cf_covered}; it claims an inferred "
          "plane as covered, in the report the gate's own alert carries")
# THE POSITIVE TWIN, which this shape alone did not have (R3 round 3). The
# other two reports each got one in round 2 precisely because the negative
# passes against a handler that reports planes_covered=[] always - and setting
# it to [] in _fail was green.
if _cf_covered and set(_cf_covered) <= evidenceable('community-saas'):
    print(f"  PASS: and it is non-empty and all evidenceable ({_cf_covered}), so the row above is "
          "about telling evidence from inference rather than about an empty list")
else:
    fail += 1
    print(f"  FAIL: the coverage failure's planes_covered is {_cf_covered}; empty or carrying a "
          "plane no single-plane probe can reach, so the exclusion above proves nothing")

# ---- BOTH classes are named when BOTH are present (R3 round 1, F3) ------




_sns3 = _RecordingSNS()
ns['sns'] = _sns3
ns['_request'] = _both_classes_refused
both = ns['handler']({}, None)
ns['sns'] = _forbidden_sns
_bothd = str(both.get('detail', ''))
# ASSERTED STRUCTURALLY, not by naming a plane. An earlier version named
# INFERRED_ONLY_PLANE, which is derived - so the row broke on a table change
# that did not break the behaviour it checks. Both SENTENCES must be present;
# which planes land in which class is the other rows' business.
_both_sharper = 'produced no EVIDENCE in this run' in _bothd
_both_blunt = 'no evaluated probe in this run at all' in _bothd
if _both_sharper and _both_blunt:
    print("  PASS: when BOTH coverage classes are non-empty the alert names BOTH; returning on "
          "the sharper one alone told an operator about half the outage")
else:
    fail += 1
    print(f"  FAIL: with both classes present the detail carried sharper={_both_sharper} "
          f"blunt={_both_blunt}: {_bothd[:250]!r}")

# AND THE SHARPER SENTENCE LEADS. The template orders the two deliberately and
# the operations page states it, and reversing the join left the suite green
# (R3 round 4, F4): both rows above check only that the sentences are PRESENT.
# The order is the actionable half - an operator reads the first clause.
if _both_sharper and _both_blunt:
    if _bothd.index('produced no EVIDENCE in this run') < \
            _bothd.index('no evaluated probe in this run at all'):
        print("  PASS: and the SHARPER sentence leads, which is what makes the pair actionable "
              "rather than merely complete")
    else:
        fail += 1
        print(f"  FAIL: the blunt sentence leads: {_bothd[:250]!r}. A plane with its own probe "
              "that produced nothing is the more actionable finding, so it goes first.")

# ---- the BLUNT gate alone is still reachable ----------------------------


# THE BLUNT GATE ALONE, and its driver is the probe ALREADY SELECTED for the
# property this row needs: _MULTI_PROBE is the first community entry whose
# planes are ALL inference-only, so refusing it cannot fire the sharper gate.
#
# IT USED TO BE KEYED ON THE LITERAL 'plan_execute' (R3 round 4, F2). A rename
# of that probe - behaviour identical, planes identical - made the lookup find
# nothing, and the empty set took the else branch: a SKIP, no assertion counted,
# suite green, announcing a reason ("its planes are no longer all
# inference-only") that was not the reason. A stated gap is never re-checked, so
# that is the most expensive shape a passing test can take. There is no SKIP
# path now: the selection above already FAILS when no such probe exists, and
# this row simply uses what it selected.
_blunt_refused = _refuses(_MULTI_SIG)

_sns2 = _RecordingSNS()
ns['sns'] = _sns2
ns['_request'] = _blunt_refused
blunt = ns['handler']({}, None)
ns['sns'] = _forbidden_sns
_bd = str(blunt.get('detail', ''))
if blunt.get('ok') is not True and 'no evaluated probe' in _bd and \
        'produced no EVIDENCE in this run' not in _bd:
    print("  PASS: a plane with NO single-plane probe that was never reached fails through the "
          "not_reached branch ALONE - both gates are reachable and distinguishable")
else:
    fail += 1
    print(f"  FAIL: refusing the {_MULTI_PROBE!r} probe reported ok={blunt.get('ok')} "
          f"detail={_bd[:200]!r}. Its planes {_MULTI_PAIR} were selected because none of them "
          "has a single-plane probe, so only the blunt gate can fire here.")

# ---- the ENTERPRISE posture is DRIVEN, not only computed (R3 round 1, F7)
#
# Every row above runs under PROBE_MODE=community-saas, which is read once at
# module scope. So the enterprise gate paths, the enterprise `expected` (twelve
# planes, including policy_simulation and cowork_ingest) and the enterprise
# no-quota behaviour were never driven - and replacing every
# _evidenceable(PROBE_MODE) in the handler with a hardcoded 'enterprise' left
# the whole suite green.
_ent_ns = {}
os.environ['PROBE_MODE'] = 'enterprise'
exec(compile(src, 'canary', 'exec'), _ent_ns)
os.environ['PROBE_MODE'] = 'community-saas'
_ent_ns['_credentials'] = lambda run_id, results: ((('t', 's'), 't', None), None)
_ent_ns['_request'] = _all_governed
_ent_ns['sns'] = _RecordingSNS()
ent = _ent_ns['handler']({}, None)

if ent.get('ok') is True and ent.get('probe_mode') == 'enterprise':
    print("  PASS: the enterprise posture drives a complete run through the real handler")
else:
    fail += 1
    print(f"  FAIL: the enterprise run reported {str(ent)[:250]}")

# The two enterprise-only planes must be EVIDENCED there and absent entirely
# from the community posture - the property a hardcoded mode would break.
if 'policy_simulation' in ent.get('planes_covered', []) and \
        'cowork_ingest' in ent.get('planes_covered', []):
    print("  PASS: and the two enterprise-only planes are evidenced in that posture")
else:
    fail += 1
    print(f"  FAIL: the enterprise run's planes_covered is {ent.get('planes_covered')}; the "
          "enterprise-only planes are missing, so the posture is not reaching them")
# THE ROW ABOVE CANNOT SEE A HARDCODED MODE, AND AN EARLIER VERSION CLAIMED IT
# COULD (R3 round 2). planes_covered is decided by `evidenced`, which is filtered
# by each entry's `editions` - not by _evidenceable(mode). So hardcoding the mode
# inside _coverage, in EITHER direction, left the whole suite green while the
# enterprise report named two planes as both covered and never-evidenceable.
#
# planes_never_evidenceable is the field _evidenceable(mode) actually decides, so
# it is the one to assert. Derived from the table under the enterprise posture
# rather than listed.
# ONE DIRECTION OF THIS MUTANT IS UNOBSERVABLE BY CONSTRUCTION, AND THAT IS A
# DIFFERENT FACT FROM A GAP IN THE TEST. Hardcoding the mode to 'enterprise'
# changes NOTHING on this table: the community posture's never-evidenceable set
# is `community_expected - evidenceable(mode)`, and the two enterprise-only
# single-plane probes are not in community_expected at all, so subtracting the
# larger evidenceable set gives the same four planes (five until #4253 retired
# proxy_tier). Verified directly:
#
#   community expected - evidenceable('community-saas') -> map, orchestrator_response,
#                                                          proxy_request, wcp
#   community expected - evidenceable('enterprise')     -> the same four
#
# The 'community-saas' direction IS observable and reds the row below, because
# the enterprise posture then reports its two enterprise-only planes as never
# evidenceable while also reporting them covered. A mutant that produces
# byte-identical output is not a hole; claiming to catch it would be the
# overclaim this file keeps finding elsewhere.
_ent_never_want = sorted(_ent_expected - evidenceable('enterprise'))
if ent.get('planes_never_evidenceable') == _ent_never_want:
    print(f"  PASS: the enterprise run's never-evidenceable set is the enterprise one "
          f"({', '.join(_ent_never_want)}), so the posture reaches _evidenceable and is not "
          "hardcoded")
else:
    fail += 1
    print(f"  FAIL: the enterprise run reported planes_never_evidenceable="
          f"{ent.get('planes_never_evidenceable')}, want {_ent_never_want}. The mode is not "
          "reaching _evidenceable, so the two postures share one answer.")

# AND THE TWO REPORTS MUST NOT CONTRADICT THEMSELVES. A hardcoded mode produced
# a run naming cowork_ingest and policy_simulation as covered AND as never
# coverable; no report may do that in either posture.
for _label, _r in (("enterprise", ent), ("community-saas", full)):
    _both = sorted(set(_r.get('planes_covered', [])) & set(_r.get('planes_never_evidenceable', [])))
    if _both:
        fail += 1
        print(f"  FAIL: the {_label} run reports {_both} as BOTH covered and never-evidenceable; "
              "a report that contradicts itself is worse than one that is merely wrong")
if not (set(ent.get('planes_covered', [])) & set(ent.get('planes_never_evidenceable', []))) and \
        not (set(full.get('planes_covered', [])) & set(full.get('planes_never_evidenceable', []))):
    print("  PASS: neither posture's report names a plane as both covered and never-evidenceable")

if 'policy_simulation' not in _covered and 'cowork_ingest' not in _covered:
    print("  PASS: and neither enterprise-only plane appears in the community-saas planes_covered")
else:
    fail += 1
    print(f"  FAIL: an enterprise-only plane appears in the community-saas planes_covered "
          f"{_covered}")

# ---- teardown for the rows above, and a row that proves it --------------
ns['_request'] = _saved_request
ns['sns'] = _real_sns
del ns['_credentials']
if ns['_request'] is _saved_request and ns['sns'] is _real_sns and '_credentials' not in ns:
    print("  PASS: the coverage rows restored _request and sns and removed the _credentials stub")
else:
    fail += 1
    print("  FAIL: the coverage rows left their stubs installed")

# AND NOTHING PUBLISHED THROUGH THE DEFAULT CLIENT. The file's header claims
# this test never publishes; before this row that claim rested on which path
# each driven run happened to take, and one run was driven with the REAL boto3
# client installed. It is now a checked property rather than a sentence.
if not _forbidden_sns.violations:
    print("  PASS: no driven run reached sns.publish without a recorder - the header's claim that "
          "nothing here publishes is enforced, not assumed")
else:
    fail += 1
    print(f"  FAIL: {len(_forbidden_sns.violations)} publish(es) reached the default SNS client "
          f"(TopicArns {_forbidden_sns.violations}). A driven run is missing its _RecordingSNS "
          "install; with the real client in place that call leaves the process.")


raise SystemExit(1 if fail else 0)
PY
rc=$?
echo ""
if [ "$rc" -eq 0 ]; then echo "All tests passed!"; else echo "FAILED"; fi
exit $rc
