#!/usr/bin/env bash
# Regression test: NO JOB ON THE SELF-HOSTED FLEET MAY MUTATE HOST-GLOBAL STATE.
#
# THE CLASS, and it has now produced a dozen findings on this repo. GitHub gives
# every job its own machine. The fleet gives 8 runner slots ONE machine and ONE
# Docker daemon, so the question that finds every member is:
#
#     What does GitHub give each job PRIVATELY that one host makes GLOBAL?
#
# Instances found so far: host ports (5432), `~/.m2`, `GOCACHE`, fixed `/tmp`
# paths, leaked containers, testcontainers' Ryuk singleton, the dpkg lock,
# `/usr/bin` binaries, and the Docker daemon's whole image + volume store.
#
# THE WORST MEMBER, which this test exists for. `unit-tests-enterprise-realpg`
# reaped between arms with
#     docker ps -aq | xargs -r sudo docker rm -fv
#     sudo docker system prune -af --volumes
# which was correct while that lane had a private daemon and 14 GB of disk. On
# the fleet it force-removed the LIVE compose stacks of up to 7 concurrent
# sibling jobs and deleted every image and all build cache the fleet had. The
# victims failed with connection-refused and container-not-found, in their own
# logs, with nothing pointing back at the lane that did it. Measured on the
# host: 182 GB free of 290 GB and a build cache of 0 B - it was buying disk we
# already had with rebuild time we pay GitHub for.
#
# WHAT IT PINS (each rule has a positive control below, because a guard that
# cannot fire is a comment):
#   1. No fleet job runs `docker system prune` with `-a`/`--all`/`--volumes`.
#   2. No fleet job pipes an unfiltered `docker ps -a[q]` into `docker
#      rm/kill/stop` - that DESTROYS siblings' live containers.
#   3. No fleet job enumerates containers unfiltered at all, even read-only:
#      four suites dumped every slot's logs into their own, which buries the
#      assertion you opened the log to find. Evaluated per STEP, because the
#      scoping that makes an enumeration safe sits inside the loop body.
#   4. Every `apt-get` on a fleet job carries `DPkg::Lock::Timeout` - one dpkg
#      lock for 8 slots means a concurrent install fails outright.
#   5. No fleet job runs a system-wide `pip install`. This is a SECOND AXIS -
#      not sharing, but host image parity: stock Ubuntu 24.04 enforces PEP 668
#      and refuses what ubuntu-latest permits. Deterministic, so a census finds
#      the whole class at once. Fix with a per-job venv under $RUNNER_TEMP, not
#      --break-system-packages.
#   6. No fleet job runs `go` without `actions/setup-go` - the host has no
#      system-wide Go (measured), so such a job dies at exit 127 every time.
#   7. No fleet job downloads onto an absolute system path (`wget -O /usr/...`)
#      - `-O` truncates before it fills, so a concurrent slot can exec half a
#      binary. Download to `$RUNNER_TEMP` and `mv` it in; a rename is atomic.
#
# SCOPING NOTE: the same commands are FINE on `ubuntu-latest`, where the
# machine is thrown away afterwards. The defect is the shared host, so the rule
# is scoped to fleet jobs rather than banning the idiom everywhere - a rule
# that fires on legitimate hosted usage would be wrong and would be ignored.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

CHECKER=$(mktemp); trap 'rm -f "$CHECKER"' EXIT
cat > "$CHECKER" <<'PYEOF'
"""Report host-global mutations performed by jobs on the self-hosted fleet.

Prints one line per violation and a census line, then exits 1 if any.
Takes a workflows directory so the real tree and the fixtures below run
through EXACTLY the same code path.
"""
import glob, os, re, sys
import yaml

RULES = [
    ("docker-wipe-prune",
     lambda c: re.search(r'docker\s+system\s+prune', c) and re.search(r'(?<![\w-])(-a|-af|-fa|--all|--volumes)(?![\w-])', c),
     "global `docker system prune -a/--volumes` deletes siblings' images and volumes"),
    # TWO RULES, NOT ONE, because they have different consequences and a
    # diagnostic must name only what it can observe. An unfiltered enumeration
    # feeding `docker rm` DESTROYS siblings' work; the same enumeration feeding
    # `docker logs` only reads it. Reporting the first message for the second
    # case would be a false accusation, and four of this repo's five hits are
    # the read-only kind.
    ("docker-wipe-rm-all",
     lambda c: re.search(r'docker\s+ps\s+-a\w*', c) and not re.search(r'--filter', c)
               and re.search(r'docker\s+(?:rm|kill|stop)\b', c),
     "unfiltered `docker ps -a` into `docker rm/kill/stop` destroys siblings' live containers"),
    ("apt-no-lock-timeout",
     lambda c: re.search(r'\bapt-get\b', c) and 'DPkg::Lock::Timeout' not in c,
     "`apt-get` without DPkg::Lock::Timeout: one dpkg lock serves 8 slots"),
    # A SECOND AXIS, not a sharing problem. The nine findings above are all
    # "one host makes private things global". This one is: what does the
    # ubuntu-latest IMAGE provide, or permit, that this host does not? Nothing
    # is shared and nothing collides - the machine is simply different. Stock
    # Ubuntu 24.04 ships Python 3.12 with /usr/lib/python3.12/EXTERNALLY-MANAGED,
    # so a system-wide `pip install` that succeeds on ubuntu-latest is REFUSED
    # here with "externally-managed-environment" (PEP 668). Deterministic, so
    # it fails every time rather than on a coincidence.
    #
    # The fix is a per-job venv under $RUNNER_TEMP, NOT --break-system-packages:
    # the flag overrides PEP 668 on every run and drifts again on the next
    # image, while $RUNNER_TEMP is private per job on both runner types.
    ("pip-install-outside-a-venv",
     lambda c: re.search(r'(?:\bpip3?\b|python3?\s+-m\s+pip)[^\n]*\binstall\b', c)
               and 'venv' not in c and 'VIRTUAL_ENV' not in c,
     "system-wide `pip install` is refused on this host by PEP 668; "
     "install into a per-job venv under $RUNNER_TEMP"),
    ("download-onto-system-path",
     lambda c: re.search(r'\b(?:wget|curl)\b[^\n]*\s-[Oo]\s+/(?:usr|bin|sbin|opt|etc)/', c),
     "download truncates a host-global path in place; use $RUNNER_TEMP then mv"),
]

def strip_comment(line):
    """Drop shell comments. A guard that matches raw file text is satisfied by
    the prose beside it - the comment explaining THIS rule contains the very
    command it forbids, and an earlier version of this check failed on it."""
    out, q = [], None
    for ch in line:
        if q:
            out.append(ch)
            if ch == q: q = None
            continue
        if ch in "'\"": q = ch; out.append(ch); continue
        if ch == '#': break
        out.append(ch)
    return ''.join(out)

def scan(wf_dir):
    violations, fleet_jobs = [], 0
    for f in sorted(glob.glob(os.path.join(wf_dir, '*.yml'))):
        try:
            doc = yaml.safe_load(open(f))
        except yaml.YAMLError as e:
            print(f"FAIL: {f} is not parseable YAML: {e}"); sys.exit(2)
        if not isinstance(doc, dict): continue
        for jn, job in (doc.get('jobs') or {}).items():
            if not isinstance(job, dict): continue
            ro = job.get('runs-on')
            if not (isinstance(ro, list) and 'self-hosted' in ro): continue
            fleet_jobs += 1
            for step in job.get('steps') or []:
                if not isinstance(step, dict): continue
                for raw in (step.get('run') or '').splitlines():
                    code = strip_comment(raw).strip()
                    if not code: continue
                    for name, pred, why in RULES:
                        if pred(code):
                            violations.append((os.path.basename(f), jn, name, why, code[:110]))
                # PER-STEP, not per-line. An enumeration and the scoping that
                # makes it safe are necessarily on DIFFERENT lines - the id
                # list is built on one and filtered inside the loop body - so a
                # line-by-line rule cannot see the fix and would condemn it.
                body = '\n'.join(strip_comment(l) for l in (step.get('run') or '').splitlines())
                if re.search(r'docker\s+ps\s+-a\w*', body) and '--filter' not in body \
                   and 'com.docker.compose.project' not in body:
                    line = next((l.strip() for l in body.splitlines()
                                 if re.search(r'docker\s+ps\s+-a\w*', l)), '')
                    violations.append((
                        os.path.basename(f), jn, "enumerate-all-containers",
                        "unfiltered `docker ps -a` reaches every slot's containers; scope it "
                        "to this job (a --filter, or the compose working_dir label under "
                        "$GITHUB_WORKSPACE) or your own assertion is buried in siblings' logs",
                        line[:110]))
    return violations, fleet_jobs

wf_dir = sys.argv[1]
floor = int(sys.argv[2])
violations, fleet_jobs = scan(wf_dir)

# ANTI-VACUITY ON THE CENSUS, NOT ON THE FINDINGS. A clean report is only
# meaningful if the scan actually reached the fleet: if `runs-on` were ever
# refactored to an expression or a matrix, this would silently examine zero
# jobs and pass forever. The floor is on jobs EXAMINED.
print(f"censused {fleet_jobs} job(s) on [self-hosted …] across {len(glob.glob(os.path.join(wf_dir,'*.yml')))} workflow file(s)")
if fleet_jobs < floor:
    print(f"FAIL: only {fleet_jobs} fleet jobs censused (floor {floor}). The scan is "
          f"not reaching the fleet - check whether `runs-on` moved to an expression.")
    sys.exit(2)

for wf, jn, name, why, code in violations:
    print(f"VIOLATION [{name}] {wf} :: {jn}\n    {code}\n    -> {why}")
print(f"{len(violations)} violation(s)")
sys.exit(1 if violations else 0)
PYEOF

# 1. THE REAL TREE ---------------------------------------------------------
# Floor was 100 against 157 fleet jobs. The release-window pin (#3791) moved
# the 66 runtime-e2e suite jobs to ubuntu-latest, leaving 35, so 100 fails on a
# correct tree. 25 still fails loudly if the scan stops seeing the fleet, which
# is the only thing this floor is for. THE REVERT RESTORES BOTH TOGETHER.
if ! out=$(python3 "$CHECKER" .github/workflows 25 2>&1); then
  echo "$out"
  echo
  # ONLY name the mutation when the checker actually found one. This branch is
  # also taken when the anti-vacuity floor is not met, and the old message
  # asserted a host-global mutation in that case too - naming a cause it had
  # not observed, which cost a reader minutes on the pin PR.
  if printf '%s' "$out" | grep -q 'floor'; then
    echo "FAIL: the fleet census did not reach its floor, so no verdict was reached."
    echo "Nothing above is a mutation finding - check whether the fleet population"
    echo "changed (a pin to ubuntu-latest) before changing any rule."
  else
    echo "FAIL: a job on the self-hosted fleet mutates host-global state."
    echo "8 slots share one machine and one Docker daemon. See the header of"
    echo "$0 and the limitations list in infrastructure/ci-runners/README.md."
  fi
  exit 1
fi
echo "$out" | sed 's/^/  /'
echo "ok: no fleet job mutates host-global state"

# 1b. ROOT COMPOSE FILES PUBLISH FIXED HOST PORTS -------------------------
# The root docker-compose*.yml publish 127.0.0.1:5432, 6379, 8080, 8081, 8082.
# The 62 suite workflows each ship an overlay that remaps those with
# `ports: !override` to ports unique to the suite - that is the pattern, and it
# is why 60 suites can share one host. A job that boots a ROOT compose file
# with no such overlay binds the base ports as-is, so any two of them
# overlapping fail with "Bind for 127.0.0.1:5432 failed: port is already
# allocated".
#
# HONEST LIMIT OF THIS CHECK, because a guard that oversells its coverage is
# worse than one that admits a gap: it decides only the SYNTACTICALLY visible
# cases - a literal `-f <root file>` or a bare `docker compose up` at the repo
# root. Several suites pass their file list through a shell array
# (`docker compose -p "$p" "${COMPOSE_FILES[@]}" up`), which no static reading
# of the workflow can resolve. Those are NOT covered here - tracked on #3757,
# with the 13 suites named - so do not read a pass as proof that the whole
# fleet is port-safe.
python3 - <<'PYEOF'
import glob, os, re, sys
import yaml

ROOT = {'docker-compose.yml', 'docker-compose.enterprise.yml', 'docker-compose.test.yml',
        'docker-compose.portal-ui.yml', 'docker-compose.scaled.yml',
        'docker-compose.community-saas.yml'}
OVERLAY = {os.path.basename(f) for f in glob.glob('**/*.y*ml', recursive=True)
           if re.search(r'ports:\s*!override', open(f, errors='ignore').read())}

def boots_root(job):
    """Compose files a `docker compose ... up` in this job resolves to, counting
    only what is decidable: an explicit -f, or the default file in the step's
    working directory."""
    hits = set()
    for st in job.get('steps') or []:
        if not isinstance(st, dict): continue
        wd = st.get('working-directory') or '.'
        for line in (st.get('run') or '').splitlines():
            ls = line.strip()
            # An ECHOED command is documentation, not a boot. build-community's
            # summary job prints the command a reader should run; flagging it
            # would train people to ignore this check.
            if ls.startswith('#') or 'docker compose' not in ls: continue
            if re.match(r'(echo|printf)\b', ls): continue
            if not re.search(r'\b(up|start)\b', ls): continue
            fs = re.findall(r'-f\s+([-\w./]*docker-compose[\w.-]*\.ya?ml)', ls)
            if fs:
                # JOIN THE WORKING DIRECTORY. `-f docker-compose.yml` inside
                # `working-directory: runtime-e2e/cross-system-hitl` names that
                # suite's OWN compose file (host ports 15432/16379/18080), not
                # the root one. Reading the flag without the cwd reports a
                # correctly isolated suite as a violation.
                for tok in fs:
                    p2 = os.path.normpath(os.path.join(wd, tok))
                    if p2 in ROOT: hits.add(p2)
            elif '"${' not in ls and "'${" not in ls and '$' not in ls.split('up')[0]:
                if os.path.normpath(os.path.join(wd, 'docker-compose.yml')) == 'docker-compose.yml':
                    hits.add('docker-compose.yml')
    return hits

WF_DIR = os.environ.get('WF_DIR', '.github/workflows')
# 100 -> 25: the #3791 release-window pin moved the 66 runtime-e2e suite jobs
# to ubuntu-latest, leaving 35 fleet jobs. Revert restores both together.
FLOOR = int(os.environ.get('WF_FLOOR', '25'))

bad, censused = [], 0
for f in sorted(glob.glob(os.path.join(WF_DIR, '*.yml'))):
    try: doc = yaml.safe_load(open(f))
    except yaml.YAMLError: continue
    if not isinstance(doc, dict): continue
    for jn, job in (doc.get('jobs') or {}).items():
        if not isinstance(job, dict): continue
        ro = job.get('runs-on')
        if not (isinstance(ro, list) and 'self-hosted' in ro): continue
        censused += 1
        hits = boots_root(job)
        if not hits: continue
        blob = '\n'.join((st.get('run') or '') for st in (job.get('steps') or []) if isinstance(st, dict))
        refs = {os.path.basename(m) for m in re.findall(r'[-\w.]*docker-compose[\w.-]*\.ya?ml', blob)}
        if refs & OVERLAY: continue
        bad.append((os.path.basename(f), jn, sorted(hits)))

print(f"  censused {censused} fleet job(s); {len(OVERLAY)} port-overlay file(s) in tree")
if censused < FLOOR:
    print(f"FAIL: only {censused} fleet jobs censused; the scan is not reaching the fleet")
    sys.exit(2)
for wf, jn, h in bad:
    print(f"VIOLATION [root-compose-fixed-ports] {wf} :: {jn} boots {h} with no `ports: !override` overlay")
if bad:
    print("A root compose file publishes fixed host ports (5432/6379/8080/8081/8082).")
    print("Either give the job a port overlay, or run it on ubuntu-latest.")
    sys.exit(1)
print("  ok: no fleet job boots a root compose file without a port overlay")
PYEOF
if [ $? -ne 0 ]; then echo "FAIL: see above"; exit 1; fi

# POSITIVE CONTROL for the rule above. Without it, a pass is indistinguishable
# from a rule that resolves nothing - and this one has been rewritten three
# times to fix its own path resolution, so it is exactly the check most likely
# to be silently inert.
ctl=$(mktemp -d)
mkdir -p "$ctl/wf"
cat > "$ctl/wf/offender.yml" <<'YML'
name: Boots root compose on the fleet
on: [workflow_dispatch]
jobs:
  bad:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: docker compose -f docker-compose.yml up -d postgres redis
YML
cat > "$ctl/wf/fine.yml" <<'YML'
name: Boots with a port overlay
on: [workflow_dispatch]
jobs:
  good:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: docker compose -f docker-compose.yml -f runtime-e2e/3363_audit_date_range/docker-compose.wt3363ui.yml up -d
YML
# Re-run the SAME embedded checker against a fixture directory - extracted from
# this file rather than copied, so the control cannot drift from the rule.
# Extract ONLY the first PYEOF block. A second heredoc sharing this
# delimiter made `sed` concatenate both blocks into invalid Python -
# so the go check below uses GOEOF, and this range is pinned with `0,`
# to stop at the first match rather than repeating for every range.
# Extract ONLY the root-compose checker. There are three heredocs in this
# file, so a `sed` RANGE is ambiguous in two ways at once: it stops at an
# earlier PYEOF belonging to a different block, and with two blocks sharing
# a delimiter it concatenates them into invalid Python. awk from the opening
# line to the next PYEOF, then stop, is unambiguous.
awk "/^python3 - <<.PYEOF.\$/{f=1;next} f&&/^PYEOF\$/{exit} f" "$0" > "$ctl/check.py"
if WF_DIR="$ctl/wf" WF_FLOOR=1 python3 "$ctl/check.py" >"$ctl/o" 2>&1; then
  echo "FAIL: the root-compose rule did not fire on a job that boots docker-compose.yml with no overlay"
  cat "$ctl/o"; rm -rf "$ctl"; exit 1
fi
grep -q 'root-compose-fixed-ports' "$ctl/o" || {
  echo "FAIL: it failed, but not with the root-compose finding"; cat "$ctl/o"; rm -rf "$ctl"; exit 1; }
grep -q 'offender.yml' "$ctl/o" || {
  echo "FAIL: the offender was not named"; cat "$ctl/o"; rm -rf "$ctl"; exit 1; }
grep -q 'fine.yml' "$ctl/o" && {
  echo "FAIL: a job WITH a port overlay was flagged"; cat "$ctl/o"; rm -rf "$ctl"; exit 1; }
echo "  ok: the root-compose rule fires on an unoverlaid boot and spares an overlaid one"
rm -rf "$ctl"

# 1c. A FLEET JOB MUST NOT INVOKE A BINARY NOTHING PROVIDES -----------------
# The parity axis again, from the other side. The install census (rule 5) looks
# at commands that INSTALL something. A job that merely USES a binary it never
# installs is invisible to it - and that is how `Compliance report facade` died
# at exit 127 with `go: command not found` on its first ever fleet run, having
# passed for months on ubuntu-latest where the image ships Go system-wide.
#
# Measured on the host, `command -v` for each: node, java, mvn, jq, yq, psql,
# aws and docker are all PRESENT (the bootstrap installs them); **go is
# ABSENT**. Go reaches a fleet job only per-slot, through `actions/setup-go`
# writing $GITHUB_PATH. So a fleet job that runs `go` without setup-go cannot
# work, deterministically, every time.
#
# The rule is deliberately narrow - one binary, the one measured to be missing
# - rather than a list of everything a job might call. Widening it to tools the
# host does provide would fire on working jobs and be deleted within a week.
python3 - <<'GOEOF'
import glob, os, re, sys
import yaml

def strip_comment(line):
    out, q = [], None
    for ch in line:
        if q:
            out.append(ch)
            if ch == q: q = None
            continue
        if ch in "'\"": q = ch; out.append(ch); continue
        if ch == '#': break
        out.append(ch)
    return ''.join(out)

GO_DIR = os.environ.get('GO_WF_DIR', '.github/workflows')
# 100 -> 25, same reason as WF_FLOOR above.
GO_FLOOR = int(os.environ.get('GO_FLOOR', '25'))

bad, censused = [], 0
for f in sorted(glob.glob(os.path.join(GO_DIR, '*.yml'))):
    try: doc = yaml.safe_load(open(f))
    except yaml.YAMLError: continue
    if not isinstance(doc, dict): continue
    for jn, job in (doc.get('jobs') or {}).items():
        if not isinstance(job, dict): continue
        ro = job.get('runs-on')
        if not (isinstance(ro, list) and 'self-hosted' in ro): continue
        censused += 1
        steps = job.get('steps') or []
        provides = any('actions/setup-go' in (st.get('uses') or '')
                       for st in steps if isinstance(st, dict))
        if provides: continue
        for st in steps:
            if not isinstance(st, dict): continue
            for raw in (st.get('run') or '').splitlines():
                code = strip_comment(raw)
                if re.search(r'(?:^|[;&|(\s])go\s+(?:run|build|test|vet|install|mod|env)\b', code):
                    bad.append((os.path.basename(f), jn, code.strip()[:90]))
                    break
            else:
                continue
            break

print(f"  censused {censused} fleet job(s) for a `go` invocation with no setup-go")
if censused < GO_FLOOR:
    print(f"FAIL: only {censused} fleet jobs censused; the scan is not reaching the fleet")
    sys.exit(2)
for wf, jn, code in bad:
    print(f"VIOLATION [go-without-setup-go] {wf} :: {jn}\n    {code}")
if bad:
    print("The fleet host has NO system-wide Go (measured); it arrives only via")
    print("actions/setup-go writing $GITHUB_PATH. Add a setup-go step, or move")
    print("the job to ubuntu-latest, whose image ships Go.")
    sys.exit(1)
print("  ok: every fleet job that runs `go` also sets it up")
GOEOF
if [ $? -ne 0 ]; then echo "FAIL: see above"; exit 1; fi

# POSITIVE CONTROL for the go rule, both directions.
gctl=$(mktemp -d); mkdir -p "$gctl/wf"
cat > "$gctl/wf/offender.yml" <<'YML'
name: Runs go with nothing providing it
on: [workflow_dispatch]
jobs:
  bad:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: go run -tags enterprise .
YML
cat > "$gctl/wf/fine.yml" <<'YML'
name: Sets Go up first
on: [workflow_dispatch]
jobs:
  good:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: go run -tags enterprise .
YML
awk "/^python3 - <<.GOEOF.\$/{f=1;next} f&&/^GOEOF\$/{exit} f" "$0" > "$gctl/check.py"
if GO_WF_DIR="$gctl/wf" GO_FLOOR=1 python3 "$gctl/check.py" >"$gctl/o" 2>&1; then
  echo "FAIL: the go rule did not fire on a fleet job running go with no setup-go"
  cat "$gctl/o"; rm -rf "$gctl"; exit 1
fi
grep -q 'go-without-setup-go' "$gctl/o" || { echo "FAIL: wrong finding"; cat "$gctl/o"; rm -rf "$gctl"; exit 1; }
grep -q 'offender.yml' "$gctl/o" || { echo "FAIL: offender not named"; cat "$gctl/o"; rm -rf "$gctl"; exit 1; }
grep -q 'fine.yml' "$gctl/o" && { echo "FAIL: a job WITH setup-go was flagged"; cat "$gctl/o"; rm -rf "$gctl"; exit 1; }
echo "  ok: the go rule fires without setup-go and spares a job that has it"

# PROVENANCE, verified once against the real artefact rather than only this
# fixture: run against `git show 5f775a2a1:.github/workflows/
# compliance-report-facade-e2e.yml` - the exact file that died at exit 127 with
# `go: command not found` - this rule reports
#     VIOLATION [go-without-setup-go] compliance-report-facade-e2e.yml ::
#       compliance-report-facade    go run -tags enterprise . \
# It is NOT wired to git here on purpose: a shallow CI checkout may not have
# that object, and a test that needs one commit to exist is a test that starts
# failing for a reason unrelated to what it checks.
#
# Worth recording WHY main's copy is not the known-broken case: there the job
# is `runs-on: ubuntu-latest`, where Go ships with the image, so the rule
# correctly ignores it. The defect exists only in the COMBINATION - fleet
# runner plus no setup-go - which is why a control has to be built from the
# state that actually broke, not from the file that contains the bug's code.
rm -rf "$gctl"

# 2. POSITIVE CONTROLS, ONE PER RULE --------------------------------------
# Without these the whole file could be inert - four predicates that never
# match read exactly like four rules that hold. Each fixture is a fleet job
# containing one violation, run through the same scan().
tmp=$(mktemp -d); trap 'rm -f "$CHECKER"; rm -rf "$tmp"' EXIT
mkdir -p "$tmp/wf"

# Pad the fixture directory to clear the anti-vacuity floor, so a control that
# fails proves the RULE fired and not the floor.
pad() {
  for i in $(seq 1 "$1"); do
    cat > "$tmp/wf/pad-$i.yml" <<YML
name: pad $i
on: [workflow_dispatch]
jobs:
  a:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: echo hello
YML
  done
}
pad 6

control() {   # $1 rule-name, $2 run-line
  cat > "$tmp/wf/offender.yml" <<YML
name: Offender
on: [workflow_dispatch]
jobs:
  bad:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: $2
YML
  if python3 "$CHECKER" "$tmp/wf" 5 >"$tmp/o" 2>&1; then
    echo "FAIL: rule '$1' did not fire on a job that violates it: $2"; cat "$tmp/o"; exit 1
  fi
  grep -q "VIOLATION \[$1\]" "$tmp/o" || {
    echo "FAIL: a violation was reported but not as '$1': $2"; cat "$tmp/o"; exit 1; }
  echo "  ok: '$1' fires on $2"
}
control docker-wipe-prune        'sudo docker system prune -af --volumes || true'
control docker-wipe-prune        'docker system prune --all'
control docker-wipe-rm-all       'docker ps -aq | xargs -r sudo docker rm -fv || true'
control enumerate-all-containers 'for c in $(docker ps -aq); do docker logs "$c"; done'
control apt-no-lock-timeout      'sudo apt-get install -y jq'
control download-onto-system-path 'sudo wget -q https://example.invalid/yq -O /usr/bin/yq'
control pip-install-outside-a-venv 'pip install cfn-lint --quiet'
control pip-install-outside-a-venv 'python3 -m pip install --quiet bcrypt'
control pip-install-outside-a-venv 'pip install --break-system-packages ruff'
rm -f "$tmp/wf/offender.yml"
echo "ok: all 6 rules fire on a constructed violation"

# 3. THE SHAPES THAT MUST *NOT* FIRE --------------------------------------
# A rule that also condemns the correct fix would be reverted within a week.
ok_shape() {   # $1 label, $2 run-line
  cat > "$tmp/wf/fine.yml" <<YML
name: Fine
on: [workflow_dispatch]
jobs:
  good:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: $2
YML
  if ! python3 "$CHECKER" "$tmp/wf" 5 >"$tmp/o" 2>&1; then
    echo "FAIL: a legitimate shape was flagged ($1): $2"; cat "$tmp/o"; exit 1
  fi
  echo "  ok: '$1' is allowed"
  rm -f "$tmp/wf/fine.yml"
}
ok_shape "scoped container reap"  'docker ps -aq --filter label=axonflow.test.ephemeral=1 --filter status=exited'
ok_shape "dangling-only prune"    'docker image prune -f'
ok_shape "apt with lock timeout"  'sudo apt-get -o DPkg::Lock::Timeout=300 install -y jq'
ok_shape "download to RUNNER_TEMP" 'wget -q https://example.invalid/yq -O "$RUNNER_TEMP/yq"'
ok_shape "read-only dump, filtered"  'for c in $(docker ps -aq --filter name=af3435); do docker logs "$c"; done'
# Unquoted on purpose: ok_shape splices its argument straight into `run: $2`,
# so a leading double-quote makes the fixture invalid YAML and the helper then
# reports a PARSE failure as a flagged shape. The quoted real-world form
# ("$RUNNER_TEMP/pyvenv/bin/pip") is covered by the real-tree scan above, which
# passes with six such call sites in it.
ok_shape "pip into a per-job venv"   '$RUNNER_TEMP/pyvenv/bin/pip install --quiet cfn-lint'

# The multi-line fix shape: the enumeration is unfiltered on its own line and
# is scoped inside the loop body. A per-LINE rule would flag this, which is
# why the enumeration rule is evaluated per STEP.
cat > "$tmp/wf/fine.yml" <<'YML'
name: Fine multiline
on: [workflow_dispatch]
jobs:
  good:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: |
          for c in $(docker ps -aq); do
            wd=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$c")
            case "$wd" in "${GITHUB_WORKSPACE}"*) ;; *) continue ;; esac
            docker logs --tail 120 "$c" || true
          done
YML
if ! python3 "$CHECKER" "$tmp/wf" 5 >"$tmp/o" 2>&1; then
  echo "FAIL: the workspace-scoped log dump was flagged; the enumeration rule must be per-step"
  cat "$tmp/o"; exit 1
fi
echo "  ok: an enumeration scoped inside the loop body is allowed"
rm -f "$tmp/wf/fine.yml"

# A hosted runner keeps the idiom: the machine is discarded after the job, so
# there is nothing shared to protect. If this ever fires, the rule has stopped
# being scoped to the fleet and has become a blanket ban.
cat > "$tmp/wf/hosted.yml" <<'YML'
name: Hosted is exempt
on: [workflow_dispatch]
jobs:
  h:
    runs-on: ubuntu-latest
    steps:
      - run: docker ps -aq | xargs -r docker rm -fv; sudo docker system prune -af --volumes
YML
if ! python3 "$CHECKER" "$tmp/wf" 5 >"$tmp/o" 2>&1; then
  echo "FAIL: the rule fired on a GITHUB-HOSTED job; it must be scoped to the fleet"
  cat "$tmp/o"; exit 1
fi
echo "  ok: an identical command on ubuntu-latest is not flagged"
echo "ok: legitimate shapes and hosted runners are not flagged"
