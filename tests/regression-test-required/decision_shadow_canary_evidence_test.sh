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
[ -f "$TPL" ] || { echo "FATAL: $TPL not found"; exit 1; }

echo "=== decision-shadow canary: the evidence predicate (#3602) ==="
python3 - "$TPL" <<'PY'
import json, os, sys, yaml

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
# tests-hygiene.yml refuses ANY line under tests/ carrying an AWS ARN prefix -
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
os.environ.update({'AWS_DEFAULT_REGION': 'us-east-1',
                   'BASE_URL': 'https://x.invalid', 'PROBE_MODE': 'community-saas',
                   'VARIANTS': '6',
                   'ALERT_TOPIC_ARN': 'not-an-arn-never-published-to-in-this-test',
                   'ORG_ID': 'o', 'SECRET_ARN': '', 'MINTED_CREDENTIAL_SECRET_ARN': '',
                   'LICENSE_SECRET_ARN': '', 'JWT_SECRET_ARN': ''})
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
]
fail = 0
for name, status, body, want in cases:
    got, why = evaluated(status, body)
    if got == want:
        print(f"  PASS: {name}")
    else:
        fail += 1
        print(f"  FAIL: {name}: evaluated={got}, want={want} (reason: {why})")

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

raise SystemExit(1 if fail else 0)
PY
rc=$?
echo ""
if [ "$rc" -eq 0 ]; then echo "All tests passed!"; else echo "FAILED"; fi
exit $rc
