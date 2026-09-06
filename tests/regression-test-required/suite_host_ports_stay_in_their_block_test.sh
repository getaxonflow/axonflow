#!/usr/bin/env bash
# Regression test: EVERY runtime-e2e HOST PORT LIES INSIDE ITS SUITE'S REGISTRY
# BLOCK, AND NOTHING ALLOCATES A PORT AT RUN TIME.
#
# Replaces the pairwise "no two suites share a port" check. That property is
# EMERGENT - it has to be recomputed over 63x63 pairs, it reports a pair rather
# than a file, and it tempts you to lower a floor. Containment is STRUCTURAL:
# four local checks against one registry, each failing on the first wrong port
# with the file that holds it.
#
# WHY ANY OF THIS EXISTS. Eight runner slots share one Docker daemon on the
# self-hosted fleet, so a host port is a GLOBAL resource. Merge-queue drain 9
# was ejected by
#   Bind for 0.0.0.0:15432 failed: port is already allocated
# where one suite's `pick_port 15432` took the port and another, which bound
# 15432 statically from its own compose file, lost it 60 seconds later.
#
# WHY `pick_port` HAD TO GO RATHER THAN BE RENUMBERED. It probed and RETURNED -
# compose bound the port minutes later, after an image build, so the answer was
# stale before use - and it walked N..N+99, which made a suite a 100-port
# RESERVATION rather than a claim. 150 of the 170 colliding pairs involved it;
# deleting it resolved those before a single port was renumbered.
#
# THE FOUR CHECKS:
#   1. every suite that declares a host port has a row in the registry
#   2. registry blocks are 16-aligned and disjoint
#   3. every declared host port lies inside its own suite's block
#   4. `pick_port` appears nowhere in runtime-e2e/ except the rule's prose
#
# FIVE DECLARATION FORMS are recognised, each found the hard way:
#   compose  "127.0.0.1:22001:6379"            literal
#   compose  "${REDIS_HOST_PORT:-22001}:6379"  variable with a default
#   script   REDIS_HOST_PORT=22001             literal
#   script   REDIS_HOST_PORT="${X:-22001}"     variable with a default
#   script   pick_port 22001                   forbidden outright by check 4
# Root-compose host ports are excluded: a job that boots the root files
# unoverlaid is a different class, kept off the fleet instead.
#
# A NOTE ON ROLE ATTRIBUTION, because it produced a wrong answer once: a port
# can be published under a service that is not its own. 2963 publishes
# Keycloak's port on the `axonflow-agent` service, because Keycloak runs in
# that container's network namespace. The VARIABLE name is authoritative; the
# service name is only a fallback.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

REGISTRY=runtime-e2e/lib/host-ports.tsv
CHECKER=$(mktemp); TMP=$(mktemp -d)
trap 'rm -f "$CHECKER"; rm -rf "$TMP"' EXIT

cat > "$CHECKER" <<'PYEOF'
"""Assert host-port containment against the registry. Args: <root> <registry> <floor>."""
import glob, os, re, sys
import yaml


class Loader(yaml.SafeLoader):
    """Suite overlays use `ports: !override`; SafeLoader alone rejects the tag."""


Loader.add_multi_constructor(
    '',
    lambda loader, suffix, node: (
        loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode)
        else loader.construct_mapping(node) if isinstance(node, yaml.MappingNode)
        else loader.construct_scalar(node)
    ),
)

ROOT, REG_PATH = sys.argv[1], sys.argv[2]
FLOOR = int(sys.argv[3])
# THE UNDECIDABLE BUCKET IS RATCHETED, not merely printed. Optional so the
# fixture controls can still exercise the bucket deliberately; the real-tree
# invocation passes 0 and that is what makes a green run mean something.
EXCLUDED_MAX = int(sys.argv[4]) if len(sys.argv) > 4 else None
BLOCK = 16
failures = []


def fail(msg):
    failures.append(msg)
    print(f"VIOLATION {msg}")


# ---- the registry ---------------------------------------------------------
registry = {}
for lineno, raw in enumerate(open(REG_PATH), 1):
    if raw.startswith('#') or not raw.strip():
        continue
    parts = raw.rstrip('\n').split('\t')
    if len(parts) != 2 or parts[0] == 'suite':
        continue
    suite, base = parts[0], parts[1]
    if not base.isdigit():
        fail(f"[registry-malformed] {REG_PATH}:{lineno} base {base!r} is not a number")
        continue
    registry[suite] = int(base)

print(f"  registry: {len(registry)} suite(s) from {REG_PATH}")

# CHECK 2 - blocks 16-aligned and disjoint.
seen = {}
for suite, base in sorted(registry.items()):
    if (base - 22000) % BLOCK != 0:
        fail(f"[block-misaligned] {suite} base {base} is not {BLOCK}-aligned from 22000")
    for other, obase in seen.items():
        if abs(base - obase) < BLOCK:
            fail(f"[blocks-overlap] {suite} ({base}) overlaps {other} ({obase})")
    seen[suite] = base

# ---- declarations ---------------------------------------------------------
root_files = ('docker-compose.yml', 'docker-compose.enterprise.yml',
              'docker-compose.portal-ui.yml', 'docker-compose.test.yml',
              'docker-compose.scaled.yml', 'docker-compose.community-saas.yml')
root_ports = set()
for name in root_files:
    path = os.path.join(ROOT, name)
    if not os.path.isfile(path):
        continue
    doc = yaml.load(open(path, errors='ignore'), Loader=Loader) or {}
    for svc in (doc.get('services') or {}).values():
        if isinstance(svc, dict):
            for spec in (svc.get('ports') or []):
                m = re.match(r'^(?:[\d.]+:)?(\d+):\d+', str(spec))
                if m:
                    root_ports.add(int(m.group(1)))


def strip_sh(line):
    """Everything BEFORE the first '#' that opens a comment.

    The start-of-word rule is not cosmetic here, and this function is the more
    dangerous of the two places it was missing. `comment_of` decides whether an
    annotation is honoured; `strip_sh` decides what the EVIDENCE scan and the
    DECLARATION scan get to see at all, so a '#' mistaken for a comment does not
    weaken a claim, it deletes the rest of the line:

        docker run -d -e PGPASSWORD=aXb -p 15432:5432 alpine   -> a violation
        docker run -d -e PGPASSWORD=a#b -p 15432:5432 alpine   -> silence

    Not a violation, not even "undecidable" - nothing at all, on the exact port
    that ejected merge-queue drain 9. Two definitions of where a bash comment
    starts used to live in this file and the looser one guarded the scan.
    """
    out, quote = [], None
    for i, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            continue
        if ch == '#' and (i == 0 or line[i - 1].isspace()):
            break
        out.append(ch)
    return ''.join(out)


def suite_of(path):
    rel = os.path.relpath(path, ROOT)
    parts = os.path.normpath(rel).split(os.sep)
    return parts[1] if len(parts) > 2 and parts[0] == 'runtime-e2e' else None


declared = []          # (suite, port, where)
bound_vars = {}        # suite -> {variables that back a real compose bind}
excluded = []          # (where, value, variable) - undecidable, see #3765
for path in sorted(glob.glob(os.path.join(ROOT, 'runtime-e2e', '**', '*compose*.y*ml'),
                             recursive=True)):
    suite = suite_of(path)
    if not suite:
        continue
    try:
        doc = yaml.load(open(path, errors='ignore'), Loader=Loader)
    except yaml.YAMLError as exc:
        print(f"FAIL: {path} is not parseable YAML: {exc}")
        sys.exit(2)
    if not isinstance(doc, dict):
        continue
    for svc in (doc.get('services') or {}).values():
        if not isinstance(svc, dict):
            continue
        for spec in (svc.get('ports') or []):
            text = str(spec)
            # ONE PATTERN FOR ALL FOUR SHAPES. An optional IP prefix may precede
            # EITHER a literal or a ${VAR:-n}:
            #   "22000:5432"  "127.0.0.1:22000:5432"
            #   "${PG_HOST_PORT:-22000}:5432"
            #   "127.0.0.1:${PG_HOST_PORT:-22000}:5432"
            # Two separate patterns - one anchored at ^${, one at ^[\d.]+: -
            # matched neither of the last shape, and SILENTLY SKIPPED 32
            # declarations across 8 suites while this guard reported green.
            m = re.match(
                r'^(?:[\d.]+:)?(?:\$\{[A-Za-z_][A-Za-z0-9_]*:-(\d+)\}|(\d+)):\d+', text)
            if not m:
                continue
            port = int(m.group(1) or m.group(2))
            var = None
            vm = re.match(r'^(?:[\d.]+:)?\$\{([A-Za-z_][A-Za-z0-9_]*):-', text)
            if vm:
                var = vm.group(1)
                bound_vars.setdefault(suite, set()).add(var)
            if port not in root_ports:
                declared.append((suite, port, os.path.relpath(path, ROOT)))

# THE NAME MUST END IN _PORT (or be exactly PORT), and must not contain
# EXPORT. A looser `[A-Z_]*PORT[A-Z_]*` matched
# OTEL_METRIC_EXPORT_INTERVAL - "EXPORT" contains "PORT" - and
# PORT_WINDOW_HI, neither of which is a port. It inflated the suite count
# from 72 to 87 and would have emitted false violations.
SCRIPT_DECL = re.compile(
    r'(?<![A-Z0-9_])([A-Z][A-Z0-9_]*_PORT|PORT)\s*=\s*"?(?:\$\{[A-Za-z_][A-Za-z0-9_]*:-)?(\d{4,5})')
# The role variables the registry's offset table defines. An unrecognised
# *_PORT name fails rather than being silently ignored - that silence is how a
# suite count of 63 hid nine more suites earlier in this work.
KNOWN_ROLE_VARS = {
    'PG_HOST_PORT', 'PG_PORT', 'REDIS_HOST_PORT', 'REDIS_PORT',
    'AGENT_HOST_PORT', 'AGENT_PORT', 'ORCH_HOST_PORT', 'ORCH_PORT',
    'PORTAL_HOST_PORT', 'PORTAL_PORT', 'UI_PORT', 'KMS_HOST_PORT',
    'MINIO_PORT', 'MINIO_CONSOLE_PORT', 'KEYCLOAK_HOST_PORT',
    'OLLAMA_PORT', 'FAKE_PORT',
}
# A `docker run -p HOST:CONTAINER` / `--publish` is a HOST bind as surely as a
# compose `ports:` entry. The host side may itself be a VARIABLE and not only a
# literal IP - 2552 publishes `-p "${DATABASE_HOST}:${DATABASE_PORT}:5432"`, and
# a pattern that allowed only `[\d.]+:` before the port read straight past it.
# The separator is OPTIONAL (`-p22099:5432` is valid docker), the container
# side may itself be a variable (`-p "22099:${PG_INTERNAL:-5432}"`), and a
# PORT RANGE (`-p 22099-22105:5438-5444`) publishes every port in it.
PUBLISH = re.compile(
    r'(?:--publish|(?<![\w-])-p)[= ]*"?'
    r'(?:(?:[\d.]+|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?):)?'
    r'(?:\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(\d{4,5}))?\}|(\d{4,5})(?:-(\d{4,5}))?)'
    r':(?:\d+(?:-\d+)?|\$\{?[A-Za-z_][A-Za-z0-9_]*)')

# ===========================================================================
# WHAT A SCRIPT CAN PROVE ABOUT A HOST BIND (#3765).
#
# Until now a script declaration counted only when the variable backed a
# COMMITTED compose `${VAR:-N}` default. Everything else was excluded as
# undecidable - 112 declarations across 29 suites - and two live collisions
# hid in that bucket, on ports outside BOTH suites' blocks so containment
# could not see them:
#     migration_version_collision:197 and v9_phase8_b1_rls:76   both PORT=18290
#     3550_trust_realm_persistence:160 and 3604_durable_stores:178  both 18296
#
# Most of that bucket was never ambiguous - it was invisible. Three forms:
#
#   H1 GENERATED COMPOSE. The script WRITES a compose document at run time
#      (`cat > "$ISOLATE" <<YAML` ... `ports: !override ["127.0.0.1:${PG_PORT}:5432"]`)
#      and binds through it. Real bind, no committed file to read.
#   H2 PUBLISH WITH A VARIABLE HOST SIDE. Handled by PUBLISH above.
#   H3 NATIVE PROCESS. No Docker at all: the suite runs a built binary on the
#      runner (`PORT=18290 ... "$WORKDIR/agent" &`) and dials it back on
#      loopback. It occupies the fleet host exactly as a published container
#      port does, and `docker ps` shows nothing.
#
# THE H3 RULE IS DELIBERATELY TWO-SIDED: the suite must BOTH declare the port
# in a `*_PORT` variable it owns AND dial that same port on loopback in the
# same file. A loopback dial ALONE is not enough and must not be, or
# `ORCHESTRATOR_URL=http://localhost:18291` in migration_version_collision
# becomes a violation - nothing listens there, the URL is handed to a process
# that fails to reach it, and the port is not occupied. Requiring the
# declaration too is what keeps this from inventing findings.
# ===========================================================================
GEN_COMPOSE_VAR = re.compile(
    r'"(?:[^"\s:]*:)?\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-\d+)?\}:\d+"')
GEN_COMPOSE_LIT = re.compile(r'"(?:[\d.]+:)?(\d{4,5}):\d+"')
LOOPBACK_VAR = re.compile(r'(?:localhost|127\.0\.0\.1):\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?')
LOOPBACK_LIT = re.compile(r'(?:localhost|127\.0\.0\.1):(\d{4,5})(?![\d])')

# THE ANNOTATION, for what no static reading can settle. 2886 substitutes its
# ports into an agentgateway config template through `sed`; whether the gateway
# then listens on them is a fact about the template, not about the script.
#
# IT IS SCOPED TO ONE LINE - the next declaration below it - and that scope is
# the whole safety property. A file-wide, name-keyed claim was strictly worse
# than no claim at all: 2552 declares DATABASE_PORT twice in one file, a host
# bind in one branch and an in-container DSN port in the other, so ONE correct
# `container-port` annotation written for the DSN line silently disabled
# containment on the host bind 20 lines above it. Worse, the claim was applied
# retroactively and beat a COMMITTED compose bind, so two words in a comment
# could switch off a proven host port anywhere in the file and the guard would
# still exit 0.
#
# `host-port` takes containment; `container-port` is skipped, counted and
# PRINTED. Neither is a licence to assert: a wrong `host-port` fails the moment
# the number leaves the block, a `container-port` costs a visible line in the
# report, and every one in this tree was settled by EXECUTING its suite. An
# unannotated, unprovable declaration keeps printing as undecidable, so the
# bucket can only empty through proof or through a claim someone signed on a
# specific line.
ANNOT = re.compile(r'#\s*(host-port|container-port):\s*([A-Za-z_][A-Za-z0-9_]*)\b')
# `not-a-port` answers CHECK 5 only, and takes a TOKEN rather than a variable:
# a five-digit run inside a pinned image digest or a SQLSTATE is not a port and
# has no variable to name.
NOT_A_PORT = re.compile(r'#\s*not-a-port:\s*(\d{5})\b')


def comment_of(line):
    """The line's REAL comment: everything after the first '#' that OPENS one.

    An annotation must be read from a genuine comment, not from anywhere the
    characters happen to appear, because `container-port` SKIPS containment:
    a line of unrelated output that could switch one off is a fail-open path.

    Two conditions, and the second was missed the first time round. The '#'
    must be UNQUOTED - or `echo "# container-port: DATABASE_PORT"` counts - and
    it must be at the START OF A WORD, because that is when bash opens a
    comment. Without the word-start rule a URL fragment still slips through:

        curl -sS http://example.com/docs#container-port:PG_HOST_PORT

    is three arguments to curl, not a comment, and it silenced a real publish.
    """
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            continue
        if ch == '#' and (i == 0 or line[i - 1].isspace()):
            return line[i:]
    return ''

pick_port_uses = []
annotated_container = []       # (where, value, name)
not_a_port_claims = []         # (where, value)
for path in sorted(glob.glob(os.path.join(ROOT, 'runtime-e2e', '**', '*.sh'), recursive=True)):
    suite = suite_of(path)
    rel = os.path.relpath(path, ROOT)
    raw_lines = open(path, errors='ignore').read().splitlines()

    # PASS 1 - what does this file prove, and what does it claim?
    # `annot` is keyed by (NAME, LINE THE CLAIM GOVERNS) - the next non-blank
    # line below the comment - never by name alone. See the ANNOT comment: a
    # name-keyed claim reaches every declaration of that name in the file, in
    # both directions, which is how one annotation written for a DSN branch
    # silenced a host bind in the branch above it.
    host_vars, host_lits, annot = set(), set(), {}
    for lineno, raw in enumerate(raw_lines, 1):
        comment = comment_of(raw)
        if comment:
            # The next line carrying CODE, not merely the next non-blank line:
            # an annotation is normally followed by the prose explaining it, and
            # a claim that landed on its own explanation governed nothing.
            target = next((n for n in range(lineno + 1, len(raw_lines) + 1)
                           if strip_sh(raw_lines[n - 1]).strip()), None)
            for am in ANNOT.finditer(comment):
                if target:
                    annot[(am.group(2), target)] = am.group(1)
        line = strip_sh(raw)
        if not line.strip():
            continue
        for gm in GEN_COMPOSE_VAR.finditer(line):
            host_vars.add(gm.group(1))
        for gm in GEN_COMPOSE_LIT.finditer(line):
            host_lits.add(int(gm.group(1)))
        for pm in PUBLISH.finditer(line):
            if pm.group(1):
                host_vars.add(pm.group(1))
            if pm.group(2):
                host_lits.add(int(pm.group(2)))
            if pm.group(3):
                host_lits.add(int(pm.group(3)))
        for lm in LOOPBACK_VAR.finditer(line):
            host_vars.add(lm.group(1))
        for lm in LOOPBACK_LIT.finditer(line):
            host_lits.add(int(lm.group(1)))

    # PASS 2 - classify each declaration.
    for lineno, raw in enumerate(raw_lines, 1):
        line = strip_sh(raw)
        if not line.strip():
            continue
        if re.search(r'\bpick_port\b', line):
            pick_port_uses.append(f"{rel}:{lineno}")
        if not suite:
            continue
        # A publish is a bind whoever owns the number, so it is recorded even
        # when no `*_PORT` variable carries it. Same for a LITERAL host port in
        # a compose document the script generates: `ports: ["0.0.0.0:22099:5432"]`
        # inside a heredoc binds that port with no variable to classify, and
        # recording only the variable form left it invisible.
        for pm in PUBLISH.finditer(line):
            pport = pm.group(2) or pm.group(3)
            if pport and int(pport) not in root_ports:
                declared.append((suite, int(pport), f"{rel}:{lineno}"))
        for gm in GEN_COMPOSE_LIT.finditer(line):
            gport = int(gm.group(1))
            if gport not in root_ports:
                declared.append((suite, gport, f"{rel}:{lineno}"))
        for m in SCRIPT_DECL.finditer(line):
            name, value = m.group(1), int(m.group(2))
            if 'EXPORT' in name or value in root_ports:
                continue
            where = f"{rel}:{lineno}"
            # THE CLAIM GOVERNS THIS LINE ONLY - see the ANNOT comment. A
            # `container-port` here still wins over proof, and it has to: 2552's
            # two DATABASE_PORT declarations sit in opposite branches of one
            # file, so the evidence sets (which are file-wide) prove "host" for
            # both, and the DSN one needs a way to say otherwise. What it can no
            # longer do is reach any OTHER line.
            claim = annot.get((name, lineno))
            if claim == 'container-port' and name in bound_vars.get(suite, set()):
                # A CLAIM MAY NOT CONTRADICT A COMMITTED BIND. The evidence
                # sets are file-wide heuristics and a signed claim may overrule
                # them; a compose `${VAR:-N}` default in a checked-in file is
                # not a heuristic, it is the bind itself. Silently honouring
                # "container" over it would let two words switch off a proven
                # host port, so this is an error rather than a skip.
                fail(f"[claim-contradicts-bind] {where}: {name}={value} is annotated "
                     f"`container-port`, but a committed compose file binds it as a "
                     f"host port - one of the two is wrong and it is not decidable here")
            elif claim == 'container-port':
                annotated_container.append((where, value, name))
                continue
            if name in bound_vars.get(suite, set()):
                # Backs a COMMITTED compose bind. Its correct port cannot be
                # computed without a role, so an unclassified name FAILS here
                # rather than being waved through. The role table governs the
                # platform overlays; the H1/H2/H3 forms below carry fixtures
                # that have no platform role, so they take containment only.
                if name not in KNOWN_ROLE_VARS:
                    fail(f"[unknown-port-variable] {where}: {name}={value} backs a "
                         f"compose bind but has no role in the registry's offset table - "
                         f"classify it there; an unclassified name has no correct port")
                declared.append((suite, value, where))
            elif (claim == 'host-port' or name in host_vars
                  or value in host_lits):
                declared.append((suite, value, where))
            else:
                # Nothing in the file proves it is a HOST port and nobody has
                # claimed it is. Excluded from containment and printed with its
                # file:line - never silently dropped.
                excluded.append((where, value, name))

suites_declaring = {s for s, _, _ in declared}
print(f"  {len(declared)} host-port declaration(s) across {len(suites_declaring)} suite(s)")

# ANTI-VACUITY on declarations EXAMINED, not on findings.
if len(declared) < FLOOR:
    print(f"FAIL: only {len(declared)} declarations examined (floor {FLOOR}). "
          f"The scan is not reaching runtime-e2e/.")
    sys.exit(2)

# CHECK 1 - every declaring suite is in the registry.
for suite in sorted(suites_declaring):
    if suite not in registry:
        fail(f"[suite-not-in-registry] {suite} declares a host port but has no "
             f"row in {REG_PATH}")

# CHECK 3 - containment.
for suite, port, where in sorted(declared):
    base = registry.get(suite)
    if base is None:
        continue                      # already reported by check 1
    if not (base <= port < base + BLOCK):
        fail(f"[port-outside-block] {where}: {suite} declares {port}, outside its "
             f"block {base}..{base + BLOCK - 1}")

# CHECK 4 - no run-time allocation.
for use in pick_port_uses:
    fail(f"[pick-port-forbidden] {use}: pick_port probes without binding and walks "
         f"100 ports; allocate statically from the registry instead")

# CHECK 5 - A NUMBER IN THE MANAGED RANGE BELONGS TO THE SUITE THAT OWNS ITS
# BLOCK, WHEREVER IT IS WRITTEN.
#
# Checks 1-4 all start from a DECLARATION they can parse. This one starts from
# the number, in any file of any type under a suite directory, and it exists
# because the declaration forms are not a closed set. v9_identity_wire binds its
# orchestrator sink from a Go literal inside a shell heredoc:
#
#     port := os.Getenv("PORT")
#     if port == "" {
#         port = "23171"          <- a host bind, in generated Go
#     }
#
# No port-shaped pattern matches that, and none ever will for the next language
# a suite generates. But the number is in the registry's range, so ownership is
# decidable without understanding the syntax around it: if 23171 is inside
# v9_identity_wire's block it is that suite's to use, and if it appears under a
# DIFFERENT suite it is that suite reaching into someone else's allocation.
#
# This is also what keeps a suite's README, its probes and its compose comments
# honest after a renumbering.
#
# TWO LIMITS, both real, both stated so nobody reads more into a green run:
#   - It cannot see a straggler OUTSIDE the range (an old 18xxx left behind), so
#     it supplements the proof forms rather than replacing them. Renumbering a
#     suite still needs the old numbers grepped across the tree by hand; that
#     sweep is what found two stale READMEs this check is blind to.
#   - IT DOES NOT SCAN .github/workflows/. Six workflow files carry suite ports
#     in prose and went stale through the #3770 renumbering; they are correct
#     now and unguarded. Covering them needs a workflow-to-suite mapping, which
#     is a separate change - naming the gap here so the comment does not claim
#     a reach the glob below does not have.
#   - It scans EVERY suite directory, registered or not. An unregistered suite
#     has no block, so any managed-range number it writes belongs to someone
#     else and is reported as such.
#
# THE RANGE IS DERIVED FROM THE REGISTRY, never written down twice. Hardcoding
# it made this check a second source of truth that silently drifted: the literal
# ceiling was exactly today's highest base plus 15, so the registry's own
# documented growth path - "append a row with the next unused base" - would put
# the new suite ABOVE the ceiling and disable CHECK 5 for it, with nothing said.
RANGE_LO = min(registry.values()) if registry else 0
RANGE_HI = (max(registry.values()) + BLOCK - 1) if registry else -1
owner = {}
for suite, base in registry.items():
    for p in range(base, base + BLOCK):
        owner[p] = suite
# The trailing guard is `(?!\.?\d)`, NOT `(?![\d.])`. Both keep the scan out of
# IPs and dotted versions, but the second also skips a port at the END OF A
# SENTENCE - "The postgres port is 22017." - because it treats the full stop as
# part of the number. The README control below is what found that, and prose is
# exactly where this check earns its keep.
# A HEX NEIGHBOUR MEANS IT IS NOT A PORT - hex, deliberately, not any letter.
# Starting from the number rather than a declaration buys reach and costs
# precision: a five-digit run inside a pinned image digest
# (`postgres@sha256:9ab22017cd4e...`) is not a port, and at ~1% per digest it
# WILL happen. But excluding EVERY letter went too far the other way and blinded
# this check to `-p22017:5432`, a docker spelling the PUBLISH pattern goes out
# of its way to support - and PUBLISH only reads `*.sh`, so in a Makefile or a
# workflow nothing would have caught it. A digest's neighbours are hex; the `p`
# of `-p` is not.
NUM = re.compile(r'(?<![0-9A-Fa-f.])(\d{5})(?![0-9A-Fa-f]|\.\d)')
for path in sorted(glob.glob(os.path.join(ROOT, 'runtime-e2e', '**', '*'), recursive=True)):
    if not os.path.isfile(path):
        continue
    suite = suite_of(path)
    if not suite:
        continue
    # `lib` is the declared HELPER directory, not a suite - the runtime-e2e
    # ledger classifies it that way - and it holds the registry itself, which
    # names every base by definition. Comparing against REG_PATH is not enough:
    # that argument is relative to the caller's cwd, so scanning another tree
    # (the pre-fix control) missed it and reported all 78 rows as foreign.
    if suite == 'lib':
        continue
    rel = os.path.relpath(path, ROOT)
    # AN UNREGISTERED SUITE HAS NO BLOCK, SO EVERY MANAGED-RANGE NUMBER IT
    # WRITES IS SOMEBODY ELSE'S. Skipping those directories was an undeclared
    # third limit on this check and by far its largest: 183 of the 261
    # directories under runtime-e2e/ have no registry row, and an unregistered
    # suite is only caught by CHECK 1 when it declares a port in a form the
    # parser recognises - which is exactly what CHECK 5 exists to cover when it
    # does not. `base = None` means nothing is in-block, so every hit reports.
    base = registry.get(suite)
    try:
        content = open(path, errors='ignore').read()
    except OSError:
        continue
    lines = content.splitlines()
    # `# not-a-port: NNNNN` on the line above. CHECK 5 is the one path with no
    # other remedy - a SQLSTATE like 23000 is a real five-digit token that no
    # delimiter rule can tell from a port - so it gets the same signed, scoped,
    # PRINTED escape as the others rather than an invisible allow-list.
    exempt = {}
    for lineno, raw in enumerate(lines, 1):
        for nm in NOT_A_PORT.finditer(comment_of(raw)):
            value = int(nm.group(1))
            # The annotation NAMES the number, so its own line would otherwise
            # be reported - the claim would fire the check it exists to answer.
            exempt[(value, lineno)] = True
            target = next((n for n in range(lineno + 1, len(lines) + 1)
                           if lines[n - 1].strip()), None)
            if target:
                exempt[(value, target)] = True
    for lineno, raw in enumerate(lines, 1):
        for nm in NUM.finditer(raw):
            port = int(nm.group(1))
            if not (RANGE_LO <= port <= RANGE_HI):
                continue
            if base is not None and base <= port < base + BLOCK:
                continue
            if exempt.get((port, lineno)):
                not_a_port_claims.append((f"{rel}:{lineno}", port))
                continue
            holder = owner.get(port)
            whose = f"{holder}'s" if holder else "no suite's"
            if base is not None:
                fail(f"[foreign-block-number] {rel}:{lineno}: {suite} writes {port}, "
                     f"which is in {whose} block, not its own "
                     f"{base}..{base + BLOCK - 1}")
            else:
                fail(f"[foreign-block-number] {rel}:{lineno}: {suite} writes {port}, "
                     f"which is in {whose} block - and {suite} has no registry row, "
                     f"so it owns no block of its own")

# THE ANNOTATION CENSUS IS UNCONDITIONAL, and prints its zero. Every line it
# counts is a check this guard agreed NOT to perform because somebody signed for
# it, so the count is the standing bill for the escape hatch. Printing it only
# when non-empty would leave a reader unable to tell "nobody has claimed
# anything" from "this build forgot to look": an exemption that is counted is
# reviewable, one that is silent is truncation under a safer name.
print(f"  ANNOTATION CENSUS: {len(annotated_container)} container-port, "
      f"{len(not_a_port_claims)} not-a-port")

if not_a_port_claims:
    print(f"  {len(not_a_port_claims)} managed-range number(s) CLAIMED not to be a "
          f"port by a `# not-a-port:` annotation and skipped by CHECK 5:")
    for where, value in sorted(not_a_port_claims):
        print(f"      {where}: {value}")

if annotated_container:
    print(f"  {len(annotated_container)} declaration(s) CLAIMED as container/DSN "
          f"values by a `# container-port:` annotation and skipped:")
    for where, value, name in sorted(annotated_container):
        print(f"      {where}: {name}={value}")

if excluded:
    print(f"  {len(excluded)} free-standing script declaration(s) NOT covered by "
          f"containment (undecidable host-vs-container; tracked on #3765):")
    for where, value, name in sorted(excluded):
        print(f"      {where}: {name}={value}")
else:
    print("  0 undecidable declarations: every script port is proven a host bind, "
          "proven a root port, or carries a signed classification")

# CHECK 6 - THE BUCKET STAYS EMPTY.
#
# Printing it was not enough, and the gap was wide enough to drive this whole
# PR through: run the PREVIOUS checker against TODAY's tree and it reports 110
# undecidable declarations and EXITS 0, because the only real-tree ratchet was
# an anti-vacuity floor calibrated to the old count. Neutering all three proof
# forms at once would still have cleared it by 90 declarations.
#
# The header claims the bucket "can only empty through proof or through a claim
# someone signed". Nothing asserted it STAYS empty - and the guard's own history
# is that two live collisions hid in exactly this bucket while it was reported
# and ignored.
if EXCLUDED_MAX is not None and len(excluded) > EXCLUDED_MAX:
    print(f"FAIL: {len(excluded)} undecidable declaration(s), limit {EXCLUDED_MAX}. "
          f"Each is a host port nothing checks. Prove it - a generated compose "
          f"bind, a publish, a loopback dial - or classify it with a "
          f"`# host-port:` / `# container-port:` annotation on its own line.")
    sys.exit(1)

if failures:
    print(f"{len(failures)} violation(s)")
    sys.exit(1)
print("  ok: every host port lies in its suite's block; nothing allocates at run time")
PYEOF

run() { python3 "$CHECKER" "$@"; }

# 1. CONTROLS ---------------------------------------------------------------
mk_tree() {                       # $1 dir
  mkdir -p "$1/runtime-e2e/lib" "$1/runtime-e2e/aaa"
  printf '# suite\tbase\naaa\t22000\n' > "$1/runtime-e2e/lib/host-ports.tsv"
  cat > "$1/runtime-e2e/aaa/docker-compose.wta.yml" <<'YML'
services:
  postgres:
    ports: !override
      - "127.0.0.1:22000:5432"
YML
}

mk_tree "$TMP/ok"
if ! run "$TMP/ok" "$TMP/ok/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a compliant tree was rejected"; cat "$TMP/o"; exit 1; fi
echo "  ok: a compliant tree passes"

# (a) a port outside its block
mk_tree "$TMP/a"
sed -i.bak 's/22000:5432/22099:5432/' "$TMP/a/runtime-e2e/aaa/docker-compose.wta.yml"; rm -f "$TMP/a"/runtime-e2e/aaa/*.bak
if run "$TMP/a" "$TMP/a/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a port outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: fires on a port outside its suite's block"

# (a2) THE SHAPE THAT WAS SILENTLY SKIPPED: an IP prefix before a ${VAR:-n}.
# Without this control the guard passed while ignoring 32 real declarations.
mk_tree "$TMP/a2"
cat > "$TMP/a2/runtime-e2e/aaa/docker-compose.wta.yml" <<'YML'
services:
  postgres:
    ports: !override
      - "127.0.0.1:${PG_HOST_PORT:-22099}:5432"
YML
if run "$TMP/a2" "$TMP/a2/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: an IP-prefixed \${VAR:-n} outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: fires on an IP-prefixed \${VAR:-n} outside its block"

# (a3) A `docker run -p` publish outside the block - the sixth form, and the
# one that survived a whole rewrite because no guard version could see it.
mk_tree "$TMP/a3"
printf '#!/usr/bin/env bash\ndocker run -d --name x -p 22099:8080 img\n' > "$TMP/a3/runtime-e2e/aaa/test.sh"
if run "$TMP/a3" "$TMP/a3/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a docker -p publish outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: fires on a docker run -p publish outside its block"

# (b) pick_port anywhere - the pre-fix tree's signature
mk_tree "$TMP/b"
printf '#!/usr/bin/env bash\nPG_PORT="${PG_PORT:-$(pick_port 22000)}"\n' > "$TMP/b/runtime-e2e/aaa/test.sh"
if run "$TMP/b" "$TMP/b/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: pick_port passed"; cat "$TMP/o"; exit 1; fi
grep -q 'pick-port-forbidden' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: fires on any pick_port use"

# (c) a suite declaring a port with no registry row
mk_tree "$TMP/c"
printf '# suite\tbase\nzzz\t22000\n' > "$TMP/c/runtime-e2e/lib/host-ports.tsv"
if run "$TMP/c" "$TMP/c/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: an unregistered suite passed"; cat "$TMP/o"; exit 1; fi
grep -q 'suite-not-in-registry' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: fires when a declaring suite has no registry row"

# (d) a registry with overlapping or misaligned blocks
mk_tree "$TMP/d"
printf '# suite\tbase\naaa\t22000\nbbb\t22008\n' > "$TMP/d/runtime-e2e/lib/host-ports.tsv"
if run "$TMP/d" "$TMP/d/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: overlapping registry blocks passed"; cat "$TMP/o"; exit 1; fi
grep -q 'blocks-overlap\|block-misaligned' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: refuses a registry with overlapping or misaligned blocks"

# --------------------------------------------------------------------------
# (f)-(l) THE FORMS ADDED BY #3765. Each fires on a port outside the block, and
# each has a NEGATIVE twin where the same shape in the block passes - a checker
# that fired on everything would also be "green after the fix" and would prove
# nothing. The negatives are the half that makes the positives mean something.
# --------------------------------------------------------------------------

# EACH FIXTURE CONTAINS ONLY THE FORM IT NAMES, and that is not fussiness.
# The first version of (f), (g) and (h) each carried two forms at once - a
# generated-compose spec whose host side is `127.0.0.1:${PG_PORT}` is ALSO a
# loopback match, and a publish written `"${HOST}:${PORT}:5432"` is ALSO a
# generated-compose match. Every one of them still passed with the mechanism it
# was named for deleted, so seven mutants survived the whole suite: all four
# evidence regexes, the H2 host-side fix, the `host_lits` branch, and CHECK 5's
# ceiling. A control that another mechanism can satisfy is not a control.
# Each positive below is now mutation-tested against ITS OWN mechanism.

# (f) H1 - a compose document the SCRIPT generates, not a committed file.
# 0.0.0.0, NOT 127.0.0.1: a loopback host side would let LOOPBACK_VAR satisfy
# this control with GEN_COMPOSE_VAR deleted.
mk_tree "$TMP/f"
cat > "$TMP/f/runtime-e2e/aaa/test.sh" <<'SH'
#!/usr/bin/env bash
PG_PORT=22099
cat > "$WORK/isolate.yml" <<YAML
services:
  postgres:
    ports: !override ["0.0.0.0:${PG_PORT}:5432"]
YAML
SH
if run "$TMP/f" "$TMP/f/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a generated-compose bind outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: H1 fires on a bind through a compose file the script generates"

sed -i.bak 's/PG_PORT=22099/PG_PORT=22001/' "$TMP/f/runtime-e2e/aaa/test.sh"; rm -f "$TMP/f"/runtime-e2e/aaa/*.bak
if ! run "$TMP/f" "$TMP/f/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: an in-block generated-compose bind was rejected"; cat "$TMP/o"; exit 1; fi
echo "  ok: H1 in-block passes"

# (f2) H1's LITERAL half. GEN_COMPOSE_LIT had no control at all, so deleting it
# outright changed nothing anywhere in the suite.
mk_tree "$TMP/f2"
cat > "$TMP/f2/runtime-e2e/aaa/test.sh" <<'SH'
#!/usr/bin/env bash
cat > "$WORK/isolate.yml" <<YAML
services:
  postgres:
    ports: ["0.0.0.0:22099:5432"]
YAML
SH
if run "$TMP/f2" "$TMP/f2/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a generated-compose LITERAL outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: H1 fires on a literal port in a generated compose file"

# (g) H2 - a publish whose HOST side is a variable, not a literal IP. Written
# UNQUOTED and with no loopback anywhere, so neither GEN_COMPOSE_VAR (which
# needs the quotes) nor either loopback regex can stand in for the H2 fix; with
# the host side reverted to `(?:[\d.]+:)?` this control fails.
mk_tree "$TMP/g"
printf '#!/usr/bin/env bash\nDATABASE_PORT=22099\ndocker run -d -p ${DATABASE_HOST}:${DATABASE_PORT}:5432 alpine\n' \
  > "$TMP/g/runtime-e2e/aaa/test.sh"
if run "$TMP/g" "$TMP/g/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a publish with a variable host side outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: H2 fires on a publish whose host side is a variable"

# (g2) the three docker publish spellings the pattern used to miss: no
# separator after -p, a variable CONTAINER side, and a port RANGE.
for spec in '-p22099:5432' '-p 22099:${PG_INTERNAL}' '-p 22099-22101:5432-5434'; do
  mk_tree "$TMP/g2"
  printf '#!/usr/bin/env bash\ndocker run -d %s alpine\n' "$spec" > "$TMP/g2/runtime-e2e/aaa/test.sh"
  if run "$TMP/g2" "$TMP/g2/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
    echo "FAIL: publish spelling '$spec' outside the block passed"; cat "$TMP/o"; exit 1; fi
  grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding for '$spec'"; cat "$TMP/o"; exit 1; }
done
echo "  ok: H2 fires on -p without a separator, a variable container side, and a range"

# (h) H3 through the VARIABLE - `localhost:$PORT` only, no literal loopback, so
# LOOPBACK_LIT cannot satisfy it.
mk_tree "$TMP/h"
printf '#!/usr/bin/env bash\nPORT=22099\ncurl -fsS "http://localhost:$PORT/health"\n' \
  > "$TMP/h/runtime-e2e/aaa/test.sh"
if run "$TMP/h" "$TMP/h/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a native-process host bind (variable dial) outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: H3 fires when the declared port is dialled through the variable"

# (h2) H3 through the LITERAL - `localhost:22099` only, the variable never
# appearing in a URL, so LOOPBACK_VAR cannot satisfy it. Deleting the
# `value in host_lits` branch fails here and nowhere else.
mk_tree "$TMP/h2"
printf '#!/usr/bin/env bash\nPORT=22099\nAXONFLOW_AGENT_URL=http://localhost:22099 "$WORKDIR/agent" &\n' \
  > "$TMP/h2/runtime-e2e/aaa/test.sh"
if run "$TMP/h2" "$TMP/h2/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a native-process host bind (literal dial) outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: H3 fires when the declared port is dialled as a literal"

# (i) H3's NEGATIVE, and the reason the rule is two-sided. A loopback URL with
# NO declaration behind it must NOT be a finding: migration_version_collision
# hands `ORCHESTRATOR_URL=http://localhost:18291` to a process, nothing listens
# there, and the port is not occupied. A one-sided rule invents that finding.
mk_tree "$TMP/i"
printf '#!/usr/bin/env bash\nORCHESTRATOR_URL=http://localhost:19291 "$WORKDIR/agent" &\n' \
  > "$TMP/i/runtime-e2e/aaa/test.sh"
if ! run "$TMP/i" "$TMP/i/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a loopback URL with no declaration behind it was reported"; cat "$TMP/o"; exit 1; fi
echo "  ok: a loopback dial with no declaration is not a host bind"

# (j) THE ANNOTATION IS ENFORCED, NOT TRUSTED. `host-port:` takes containment,
# so a wrong claim fails the moment the number leaves the block.
mk_tree "$TMP/j"
printf '#!/usr/bin/env bash\n# host-port: MCP_FULL_PORT\nMCP_FULL_PORT=22099\n' \
  > "$TMP/j/runtime-e2e/aaa/test.sh"
if run "$TMP/j" "$TMP/j/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a host-port annotation outside the block passed"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: a host-port annotation is enforced, not trusted"

# (k) `container-port:` skips - and an UNANNOTATED twin of the same line is
# still reported as undecidable, so the annotation is doing the work and the
# bucket cannot empty by accident.
mk_tree "$TMP/k"
printf '#!/usr/bin/env bash\n# container-port: DATABASE_PORT\nDATABASE_PORT=54321\n' \
  > "$TMP/k/runtime-e2e/aaa/test.sh"
if ! run "$TMP/k" "$TMP/k/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a container-port annotation did not skip"; cat "$TMP/o"; exit 1; fi
grep -q 'CLAIMED as container/DSN' "$TMP/o" || { echo "FAIL: the skip was not reported"; cat "$TMP/o"; exit 1; }
printf '#!/usr/bin/env bash\nDATABASE_PORT=54321\n' > "$TMP/k/runtime-e2e/aaa/test.sh"
if ! run "$TMP/k" "$TMP/k/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: an unannotated free-standing value was treated as a violation"; cat "$TMP/o"; exit 1; fi
grep -q 'NOT covered by' "$TMP/o" || { echo "FAIL: the unannotated twin was not reported as undecidable"; cat "$TMP/o"; exit 1; }
echo "  ok: container-port skips and its unannotated twin still prints as undecidable"

# (k2) AN ANNOTATION INSIDE A STRING IS NOT AN ANNOTATION. `container-port`
# SKIPS containment, so honouring one that merely appears in output would let a
# line of unrelated text switch off a real check - the one fail-open path in
# this design. The declaration below must still be reported as undecidable.
# Load-bearing, not decorative: revert the one expression to
# `ANNOT.finditer(raw)` and this control fails.
mk_tree "$TMP/k2"
printf '#!/usr/bin/env bash\necho "# container-port: DATABASE_PORT"\nDATABASE_PORT=54321\n' \
  > "$TMP/k2/runtime-e2e/aaa/test.sh"
if ! run "$TMP/k2" "$TMP/k2/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: the tree was rejected for the wrong reason"; cat "$TMP/o"; exit 1; fi
grep -q 'CLAIMED as container/DSN' "$TMP/o" && {
  echo "FAIL: an annotation inside a STRING was honoured — container-port is fail-open"; cat "$TMP/o"; exit 1; }
grep -q 'NOT covered by' "$TMP/o" || { echo "FAIL: the declaration was not reported"; cat "$TMP/o"; exit 1; }
echo "  ok: an annotation inside a string is not honoured"

# (k3) NOR IS A URL FRAGMENT. `#` opens a bash comment only at the START OF A
# WORD, so `http://x/docs#container-port:FOO` is an argument to curl. The
# quote-aware rule alone let this through and it silenced a real publish.
mk_tree "$TMP/k3"
# THE FRAGMENT MUST PRECEDE THE DECLARATION. On the last line `target` is None
# and the claim governs nothing whatever `comment_of` decides, so the per-line
# scoping alone satisfied the assertion and this control passed with the
# start-of-word rule reverted.
printf '#!/usr/bin/env bash\ncurl -sS http://example.com/docs#container-port:PG_HOST_PORT\nPG_HOST_PORT=22099\ndocker run -d -p "127.0.0.1:${PG_HOST_PORT}:5432" alpine\n' \
  > "$TMP/k3/runtime-e2e/aaa/test.sh"
if run "$TMP/k3" "$TMP/k3/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a URL fragment was honoured as an annotation"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: a URL fragment is not an annotation"

# (k4) A CLAIM GOVERNS ONE LINE. The same variable is declared twice in one
# file - 2552's real shape, a host bind in one branch and a DSN in the other -
# and the annotation sits on the second. It must not reach the first.
# File-wide, name-keyed claims made this the single most dangerous path in the
# guard: one correct annotation switched off containment everywhere else.
mk_tree "$TMP/k4"
cat > "$TMP/k4/runtime-e2e/aaa/test.sh" <<'SH'
#!/usr/bin/env bash
DATABASE_PORT=22099
docker run -d -p "${DATABASE_HOST}:${DATABASE_PORT}:5432" alpine
# container-port: DATABASE_PORT
DATABASE_PORT=26257
SH
if run "$TMP/k4" "$TMP/k4/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a claim on the second declaration silenced the first"; cat "$TMP/o"; exit 1; fi
# The DSN value must appear in the CLAIMS listing and NOT as a violation - a
# bare grep of the whole output cannot tell those apart, and the claims report
# is exactly where it is supposed to show up.
grep 'VIOLATION' "$TMP/o" | grep -q '22099' || { echo "FAIL: the governed host bind was not reported"; cat "$TMP/o"; exit 1; }
grep 'VIOLATION' "$TMP/o" | grep -q '26257' && { echo "FAIL: the annotated DSN line was reported as a violation"; cat "$TMP/o"; exit 1; }
grep -q 'CLAIMED as container/DSN' "$TMP/o" || { echo "FAIL: the claim was not printed"; cat "$TMP/o"; exit 1; }
echo "  ok: a container-port claim governs its own line only"

# (k5) AND IT MAY NOT CONTRADICT A COMMITTED BIND. The evidence sets are
# file-wide heuristics a signed claim may overrule; a compose `${VAR:-N}` in a
# checked-in file is the bind itself. Honouring "container" over it would let
# two words switch off a proven host port.
mk_tree "$TMP/k5"
cat > "$TMP/k5/runtime-e2e/aaa/docker-compose.a.yml" <<'YML'
services:
  postgres:
    ports: !override ["127.0.0.1:${PG_HOST_PORT:-22000}:5432"]
YML
printf '#!/usr/bin/env bash\n# container-port: PG_HOST_PORT\nPG_HOST_PORT=22099\n' \
  > "$TMP/k5/runtime-e2e/aaa/test.sh"
if run "$TMP/k5" "$TMP/k5/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a claim contradicting a committed compose bind was honoured"; cat "$TMP/o"; exit 1; fi
grep -q 'claim-contradicts-bind' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: a container-port claim may not contradict a committed compose bind"

# (l) CHECK 5 - a number in the managed range, in ANY file type, belongs to the
# suite that owns its block. This is the form no pattern can be written for:
# a host bind expressed as a Go literal inside a shell heredoc.
mk_tree "$TMP/l"
printf '# suite\tbase\naaa\t22000\nbbb\t22016\n' > "$TMP/l/runtime-e2e/lib/host-ports.tsv"
mkdir -p "$TMP/l/runtime-e2e/bbb"
cat > "$TMP/l/runtime-e2e/aaa/stub.sh" <<'SH'
#!/usr/bin/env bash
cat > main.go <<GO
port := os.Getenv("PORT")
if port == "" {
	port = "22017"
}
GO
SH
if run "$TMP/l" "$TMP/l/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a foreign block number in generated Go passed"; cat "$TMP/o"; exit 1; fi
grep -q 'foreign-block-number' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: CHECK 5 fires on a managed-range number in generated Go"

sed -i.bak 's/22017/22001/' "$TMP/l/runtime-e2e/aaa/stub.sh"; rm -f "$TMP/l"/runtime-e2e/aaa/*.bak
if ! run "$TMP/l" "$TMP/l/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a suite's OWN block number was reported"; cat "$TMP/o"; exit 1; fi
echo "  ok: CHECK 5 passes on a suite's own block number"

# CHECK 5 reaches a README too - the class that left six workflow files naming
# ports that no longer existed after a renumbering.
printf 'The postgres port is 22017.\n' > "$TMP/l/runtime-e2e/aaa/README.md"
if run "$TMP/l" "$TMP/l/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a foreign block number in a README passed"; cat "$TMP/o"; exit 1; fi
grep -q 'README.md' "$TMP/o" || { echo "FAIL: the README was not scanned"; cat "$TMP/o"; exit 1; }
echo "  ok: CHECK 5 reaches prose, not only code"

# (l2) THE CEILING IS DERIVED FROM THE REGISTRY, not written down again. A
# hardcoded ceiling equal to today's highest block silently exempts the NEXT
# suite added - and "append a row with the next unused base" is the registry's
# own documented growth path, so that suite is exactly the one nobody checks.
# The new suite is deliberately based ABOVE the real registry's highest block,
# because that is the scenario: today's ceiling is literally `max(base)+15`, so
# ANY hardcoded value is already stale for the next row appended. A control
# whose registry fits under the old literal cannot tell the two apart.
mk_tree "$TMP/l2"
printf '# suite\tbase\naaa\t22000\nbbb\t23248\n' > "$TMP/l2/runtime-e2e/lib/host-ports.tsv"
mkdir -p "$TMP/l2/runtime-e2e/bbb"
printf 'The postgres port is 23249.\n' > "$TMP/l2/runtime-e2e/aaa/README.md"
if run "$TMP/l2" "$TMP/l2/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a number in a block ABOVE the old ceiling was not checked"; cat "$TMP/o"; exit 1; fi
grep -q 'foreign-block-number' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: CHECK 5's ceiling follows the registry's highest block"

# (l3) `# not-a-port:` - CHECK 5 is the one path with no other remedy, because
# a SQLSTATE or an image digest is a real five-digit token no delimiter rule
# can tell from a port. The escape is signed, scoped to the next line, and
# PRINTED, like every other claim here.
mk_tree "$TMP/l3"
printf '# suite\tbase\naaa\t22000\nbbb\t22016\n' > "$TMP/l3/runtime-e2e/lib/host-ports.tsv"
mkdir -p "$TMP/l3/runtime-e2e/bbb"
printf '#!/usr/bin/env bash\n# not-a-port: 22017\ngrep -q "SQLSTATE 22017" "$LOG"\n' \
  > "$TMP/l3/runtime-e2e/aaa/test.sh"
if ! run "$TMP/l3" "$TMP/l3/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a not-a-port claim did not exempt the number"; cat "$TMP/o"; exit 1; fi
grep -q 'CLAIMED not to be a port' "$TMP/o" || { echo "FAIL: the exemption was not printed"; cat "$TMP/o"; exit 1; }
printf '#!/usr/bin/env bash\ngrep -q "SQLSTATE 22017" "$LOG"\n' > "$TMP/l3/runtime-e2e/aaa/test.sh"
if run "$TMP/l3" "$TMP/l3/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: the unannotated twin was not reported"; cat "$TMP/o"; exit 1; fi
echo "  ok: not-a-port exempts one line, is printed, and its twin still fires"

# (l4) A LETTER EITHER SIDE MEANS IT IS NOT A PORT. A pinned image digest
# contains a matching five-digit run about 1% of the time, and there is no
# reason to make anyone annotate that.
mk_tree "$TMP/l4"
printf '# suite\tbase\naaa\t22000\nbbb\t22016\n' > "$TMP/l4/runtime-e2e/lib/host-ports.tsv"
mkdir -p "$TMP/l4/runtime-e2e/bbb"
printf '#!/usr/bin/env bash\nIMG="postgres@sha256:9ab22017cd4e5f0a1b2c3d4e5f6a7b8c"\n' \
  > "$TMP/l4/runtime-e2e/aaa/test.sh"
if ! run "$TMP/l4" "$TMP/l4/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a five-digit run inside an image digest was read as a port"; cat "$TMP/o"; exit 1; fi
echo "  ok: a digit run bounded by letters is not a port"

# (m) CHECK 6 - THE UNDECIDABLE BUCKET IS RATCHETED, NOT JUST PRINTED. Without
# this, the previous checker run against today's tree reports 110 undecidable
# declarations and exits 0: the only real-tree ratchet was a floor calibrated to
# the old count, so neutering all three proof forms at once still cleared it.
mk_tree "$TMP/m"
printf '#!/usr/bin/env bash\nDATABASE_PORT=54321\n' > "$TMP/m/runtime-e2e/aaa/test.sh"
if run "$TMP/m" "$TMP/m/runtime-e2e/lib/host-ports.tsv" 1 0 >"$TMP/o" 2>&1; then
  echo "FAIL: an undecidable declaration passed with the bucket pinned at 0"; cat "$TMP/o"; exit 1; fi
grep -q 'undecidable declaration' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
if ! run "$TMP/m" "$TMP/m/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: the bucket limit fired when it was not requested"; cat "$TMP/o"; exit 1; fi
echo "  ok: the undecidable bucket is ratcheted, not only reported"

# (n) `not-a-port` IS LINE-SCOPED TOO - the same defect round 1 found in
# `container-port`, which had no control here. One honest claim above a
# SQLSTATE must not exempt a genuine foreign port further down the file.
mk_tree "$TMP/n"
printf '# suite\tbase\naaa\t22000\nbbb\t22016\n' > "$TMP/n/runtime-e2e/lib/host-ports.tsv"
mkdir -p "$TMP/n/runtime-e2e/bbb"
cat > "$TMP/n/runtime-e2e/aaa/test.sh" <<'SH'
#!/usr/bin/env bash
# not-a-port: 22017
grep -q "SQLSTATE 22017" "$LOG"
echo "and now a genuinely foreign port: 22017"
SH
if run "$TMP/n" "$TMP/n/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a not-a-port claim exempted a line it does not govern"; cat "$TMP/o"; exit 1; fi
grep -q 'foreign-block-number' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: a not-a-port claim governs its own line only"

# (o) THE CLAIM'S TARGET IS THE NEXT LINE CARRYING CODE, not the next non-blank
# line. cross-system-hitl puts `# host-port: DB_PORT` five prose-comment lines
# above the declaration; under the weaker rule the claim lands on a comment,
# governs nothing, and the declaration silently falls back to undecidable.
mk_tree "$TMP/o2"
cat > "$TMP/o2/runtime-e2e/aaa/test.sh" <<'SH'
#!/usr/bin/env bash
# host-port: DB_PORT
# Published by this suite's compose file as a literal, and dialled from the
# host by psql, so no ${VAR:-N} default ties the variable to the bind.
DB_PORT="22099"
SH
if run "$TMP/o2" "$TMP/o2/runtime-e2e/lib/host-ports.tsv" 1 0 >"$TMP/o" 2>&1; then
  echo "FAIL: a claim separated from its declaration by prose governed nothing"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: a claim reaches past its own explanation to the next line of code"

# (p) [unknown-port-variable] - a variable that backs a COMMITTED compose bind
# but has no role in the registry's offset table must fail rather than be waved
# through. The mechanism worked and nothing pinned it.
mk_tree "$TMP/p"
cat > "$TMP/p/runtime-e2e/aaa/docker-compose.a.yml" <<'YML'
services:
  postgres:
    ports: !override ["127.0.0.1:${WEIRD_HOST_PORT:-22000}:5432"]
YML
printf '#!/usr/bin/env bash\nWEIRD_HOST_PORT=22000\n' > "$TMP/p/runtime-e2e/aaa/test.sh"
if run "$TMP/p" "$TMP/p/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: an unclassified compose-bound variable passed"; cat "$TMP/o"; exit 1; fi
grep -q 'unknown-port-variable' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: a compose-bound variable with no role in the offset table fails"

# (d2) CHECK 2's TWO MECHANISMS, SEPARATELY. Control (d) used a registry that
# was misaligned AND overlapping and accepted either finding, so deleting
# either check alone left the suite green.
mk_tree "$TMP/d2"
printf '# suite\tbase\naaa\t22000\nbbb\t22004\n' > "$TMP/d2/runtime-e2e/lib/host-ports.tsv"
if run "$TMP/d2" "$TMP/d2/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a misaligned base passed"; cat "$TMP/o"; exit 1; fi
grep -q 'block-misaligned' "$TMP/o" || { echo "FAIL: misalignment not reported"; cat "$TMP/o"; exit 1; }
printf '# suite\tbase\naaa\t22000\nbbb\t22000\n' > "$TMP/d2/runtime-e2e/lib/host-ports.tsv"
if run "$TMP/d2" "$TMP/d2/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: two suites on the same base passed"; cat "$TMP/o"; exit 1; fi
grep -q 'blocks-overlap' "$TMP/o" || { echo "FAIL: overlap not reported"; cat "$TMP/o"; exit 1; }
echo "  ok: misalignment and overlap each fire on their own"

# (q) strip_sh's START-OF-WORD RULE. A '#' inside a word is not a comment, and
# mistaking one deletes the rest of the line from BOTH scans - not a weaker
# claim, no finding at all, on the port that ejected merge-queue drain 9.
mk_tree "$TMP/q"
printf '#!/usr/bin/env bash\ndocker run -d -e PGPASSWORD=a#b -p 22099:5432 alpine\n' \
  > "$TMP/q/runtime-e2e/aaa/test.sh"
if run "$TMP/q" "$TMP/q/runtime-e2e/lib/host-ports.tsv" 1 >"$TMP/o" 2>&1; then
  echo "FAIL: a '#' inside a word truncated the line and hid a publish"; cat "$TMP/o"; exit 1; fi
grep -q 'port-outside-block' "$TMP/o" || { echo "FAIL: wrong finding"; cat "$TMP/o"; exit 1; }
echo "  ok: a '#' inside a word does not truncate the scan"

# (e) the anti-vacuity floor must be reachable
mkdir -p "$TMP/e/runtime-e2e/lib"; printf '# suite\tbase\n' > "$TMP/e/runtime-e2e/lib/host-ports.tsv"
if run "$TMP/e" "$TMP/e/runtime-e2e/lib/host-ports.tsv" 5 >"$TMP/o" 2>&1; then
  echo "FAIL: an empty tree passed; the floor is not wired"; cat "$TMP/o"; exit 1; fi
grep -q 'floor' "$TMP/o" || { echo "FAIL: empty tree failed for the wrong reason"; cat "$TMP/o"; exit 1; }
echo "  ok: an empty scan fails on the floor rather than passing"

# 2. THE REAL TREE. Floor of 430 (452 declarations today), and the
#    undecidable bucket pinned at 0 - see CHECK 6.
if ! run . "$REGISTRY" 430 0; then
  echo
  echo "FAIL: a host port is outside its suite's block, or something allocates a"
  echo "port at run time. The registry is $REGISTRY; see the header of $0."
  exit 1
fi
echo "ok: host-port containment holds"
