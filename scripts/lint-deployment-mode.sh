#!/usr/bin/env bash
# lint-deployment-mode.sh — DEPLOYMENT_MODE hygiene, two independent checks.
#
# Usage: bash scripts/lint-deployment-mode.sh [ROOT]
#   ROOT defaults to the repository root DERIVED FROM THIS SCRIPT'S OWN PATH,
#   not from $PWD. Before #3170 the scan roots were the relative literals
#   `platform/`, `ee/` and `.`, so running the lint from any other directory
#   found nothing and reported success. Tests pass a fixture directory here.
#
# Check 1 (Issue #1133) — SOURCE. Flags any direct os.Getenv("DEPLOYMENT_MODE")
#   call outside an allowlist. The canonical way to ask "is this the Community
#   posture?" is isCommunityMode() in run.go. Files that legitimately need the
#   full mode string (not just the boolean) are allowlisted.
#
# Check 2 (Issues #3117, #3170, #3137) — DEPLOYMENT SURFACES. Asserts that every
#   surface that runs the agent or the orchestrator sets DEPLOYMENT_MODE **to a
#   value the platform recognises**. Check 1 governs how the variable is read;
#   nothing governed whether it was ever written, and #3096 made that gap load
#   bearing: isCommunityMode() fails CLOSED on unset, so a surface that never
#   sets the variable runs the enterprise posture, boots perfectly, and then
#   returns 403/zero rows on audit, decisions, cost and replay reads.
#
#   #3170/#3137: the first version of this check tested for the SUBSTRING
#   `DEPLOYMENT_MODE` anywhere in a service block. `DEPLOYMENT_MODE: ""`,
#   `${DEPLOYMENT_MODE}` with no default, a trailing comment reading
#   "# TODO: set DEPLOYMENT_MODE", the unrelated NEXT_PUBLIC_DEPLOYMENT_MODE,
#   and — the one that mattered — an UNRECOGNISED value all satisfied it.
#   `enterprise` was unrecognised by the migration selector for the whole life
#   of that lint (#3167) and the lint reported ✅ every run. The key is now
#   anchored and the VALUE is validated against the recognised set.

set -euo pipefail

ROOT="${1:-}"
FIXTURE_MODE=1
if [ -z "$ROOT" ]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  FIXTURE_MODE=0
fi
cd "$ROOT"

# ════════════════════════════════════════════════════════════════════════════
# The recognised DEPLOYMENT_MODE values.
# ════════════════════════════════════════════════════════════════════════════
# MUST equal recognisedDeploymentModes() in platform/agent/migration_helpers.go
# — canonicalDeploymentModes plus deploymentModeAliases. Drift between the two
# is caught by TestLintScriptRecognisedModesMatchGo in
# platform/agent/migration_helpers_test.go, which parses this very array.
#
# Keep sorted; the Go test compares sorted lists.
RECOGNISED_MODES=(
  community
  community-saas
  enterprise
  evaluation
  in-vpc-banking
  in-vpc-enterprise
  in-vpc-healthcare
  in-vpc-travel
  invpc
  saas
)
RECOGNISED_MODES_CSV=$(IFS=,; echo "${RECOGNISED_MODES[*]}")

# Paths excluded from the *launcher* half of Check 2 (below). These are test
# harnesses, not deployment surfaces: they compose their container environment
# from bash arrays this lint cannot resolve, and their posture is asserted by
# the suite itself. Printed on every run — a cap nobody can see reads as
# "covered everything".
LAUNCHER_EXCLUDED_PREFIXES=(
  "runtime-e2e/"
  "tests/"
  "platform/test/"
  "scripts/e2e/"
)
# …plus any file whose name ends in _test.sh (harness fixtures that WRITE
# example workflows containing `docker run`, e.g.
# .github/scripts/check-workflow-telemetry-marker_test.sh).
LAUNCHER_EXCLUDED_SUFFIXES=(
  "_test.sh"
)

# Files that legitimately need raw DEPLOYMENT_MODE access:
# - run.go: defines the canonical isCommunityMode() helper
# - migration_helpers.go: needs full mode string for migration path selection
# - admin_auth.go: needs full mode string for auth matrix (saas, in-vpc-*, community)
# - deployment.go: needs full mode string for deployment config (invpc, saas, default)
# - dev_token_handler.go: the fail-closed dev-token gate (#2541) reads the raw
#   value deliberately, and STILL does after #3096 made isCommunityMode() fail
#   closed on unset. Two reasons survive the premise change: (a) the gate
#   normalises (trim + case-fold) where isCommunityMode() is deliberately exact,
#   so the two accepting sets are not the same set and must not be conflated;
#   (b) more importantly, a gate that REGISTERS A TOKEN MINTER must not inherit
#   its accepting set from a helper whose job is to DISABLE AUTHENTICATION —
#   coupling them means any future widening of isCommunityMode() silently
#   re-arms the minter in production. See the dev_token_handler.go file header.
# - customer-portal/main.go: the portal-credential bootstrap gate (#2552) needs
#   the FULL mode string (enterprise / in-vpc-*) for a fail-closed ENABLE
#   allow-list. A boolean "is community?" cannot express that allow-list at all,
#   and isCommunityMode() is package-private to platform/agent and
#   platform/orchestrator, so the portal cannot call it in any case.
ALLOWED_FILES=(
  "platform/agent/run.go"
  "platform/orchestrator/run.go"
  "platform/shared/policy/dynamic_evaluator.go"
  "platform/shared/execution/event_hub.go"
  "platform/agent/migration_helpers.go"
  "platform/agent/dev_token_handler.go"  # #2541 fail-closed gate: normalises where isCommunityMode() is exact, and must not inherit its accepting set from the helper that disables auth
  "platform/orchestrator/llm/bootstrap.go"  # community-saas Ollama-only guard (#1500)
  "ee/platform/customer-portal/middleware/admin_auth.go"
  "ee/platform/customer-portal/config/deployment.go"
  "ee/platform/customer-portal/main.go"  # #2552 portal-credential bootstrap gate needs the FULL mode string (enterprise / in-vpc-*) for a fail-closed allow-list; a boolean cannot express it, and isCommunityMode() is package-private to platform/
)

# Build grep -v exclusion pattern for allowed files.
# Note: --exclude with path separators only works on BSD grep (macOS).
# GNU grep (Linux/CI) matches --exclude against basenames only.
# Using grep -v post-filter ensures cross-platform correctness.
EXCLUDE_PATTERN=""
for f in "${ALLOWED_FILES[@]}"; do
  EXCLUDE_PATTERN="${EXCLUDE_PATTERN:+$EXCLUDE_PATTERN|}^${f}:"
done

# Find violations in non-test Go files
# Note: This catches the canonical form os.Getenv("DEPLOYMENT_MODE").
# It does NOT catch backtick strings (`DEPLOYMENT_MODE`) or indirect access.
VIOLATIONS=$(grep -rn 'os\.Getenv("DEPLOYMENT_MODE")' \
  --include="*.go" \
  --exclude="*_test.go" \
  --exclude="*_integration_test.go" \
  platform/ ee/ 2>/dev/null | \
  grep -Ev "$EXCLUDE_PATTERN" || true)

if [ -n "$VIOLATIONS" ]; then
  echo "❌ DEPLOYMENT_MODE lint check failed (Issue #1133)"
  echo ""
  echo "Found direct os.Getenv(\"DEPLOYMENT_MODE\") calls outside allowed files:"
  echo ""
  echo "$VIOLATIONS"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "HOW TO FIX:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "Use the canonical isCommunityMode() helper instead of raw os.Getenv:"
  echo ""
  echo "  // ✅ Correct"
  echo "  if isCommunityMode() {"
  echo "      return nil"
  echo "  }"
  echo ""
  echo "  // ❌ Wrong — bypasses the canonical pattern"
  echo "  if os.Getenv(\"DEPLOYMENT_MODE\") == \"community\" {"
  echo "      return nil"
  echo "  }"
  echo ""
  echo "If you genuinely need the full mode string (not just the boolean),"
  echo "add your file to the allowlist in scripts/lint-deployment-mode.sh"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 1
fi

echo "✅ DEPLOYMENT_MODE lint check passed — all non-test code uses isCommunityMode()"

# ════════════════════════════════════════════════════════════════════════════
# Check 2 (#3117 / #3170 / #3137) — every deployment surface must SET
# DEPLOYMENT_MODE to a RECOGNISED value
# ════════════════════════════════════════════════════════════════════════════
#
# A "deployment surface" is
#   (a) a Compose service,
#   (b) an ECS container definition,
#   (c) a `docker run` invocation in a non-test shell script or workflow, or
#   (d) a code block in a published component README
# that runs the AxonFlow agent or orchestrator. Each one must set
# DEPLOYMENT_MODE, and the value must be one the platform recognises.
#
# WHY THIS IS FAIL-CLOSED BY CONSTRUCTION.
#
# The recogniser's default answer is "this is a surface and it is missing the
# variable", never "skip it". Anything it cannot classify with certainty is
# reported as UNPARSEABLE and fails the lint. That is deliberate: a recogniser
# whose default is *accept* silently exempts every file shape its author did
# not imagine, which is precisely how the marketplace orchestrator task
# definition went five releases without the variable while three sibling task
# definitions had it.
#
# Concretely, the following all FAIL rather than pass:
#   - a Compose file with tab indentation, multiple YAML documents, `extends:`,
#     `include:`, a merge key (`<<:`) or an anchor/alias — none of which this
#     parser resolves;
#   - a file that plainly declares an agent/orchestrator image or Dockerfile
#     somewhere but from which the parser attributed ZERO services;
#   - a surface service whose environment comes from `env_file:` (the lint
#     cannot see inside it — declare the variable inline instead);
#   - a service whose `image:` is variable-expanded and NAMES an agent or
#     orchestrator without being the canonical repository (#3137: the old
#     `flush()` matched only the literal strings `axonflow-agent` /
#     `axonflow-orchestrator`, so `image: ${ECR_REGISTRY}/af-agent:${VERSION}`
#     was silently skipped), or whose image has no literal repository name at
#     all;
#   - an ECS container definition whose image is the agent or the orchestrator
#     and whose Environment list has no DEPLOYMENT_MODE entry. Container
#     definitions are counted INDIVIDUALLY (#3137: the previous parser assumed
#     one container per task definition, so a second container in the same
#     resource inherited the first one's verdict);
#   - any of the above setting DEPLOYMENT_MODE to an empty string, to a bare
#     `${VAR}` with no default, or to a value outside the recognised set.
#
# WHAT IT STILL CANNOT CATCH — written down rather than left to be discovered:
#   - a value supplied entirely at runtime (`-e DEPLOYMENT_MODE=$MODE` where
#     $MODE comes from an API call). Use the `${VAR:-<recognised>}` form so the
#     fallback is at least assertable.
#   - environment injected by a deploy pipeline into a template that does not
#     declare it (this is how the marketplace orchestrator task definition was
#     masked internally — `deploy-application.yml` injected the variable, so
#     only a direct-from-template stack was affected).
#   - the excluded test-harness prefixes, printed on every run.
#
# THE ONE ESCAPE HATCH, and why it is not a silent skip.
#
# Compose OVERRIDE files (`-f base.yml -f override.yml`) legitimately redeclare
# a service — sometimes even its `image:` — while inheriting the base file's
# environment. Such a file must say so, on its own line:
#
#     # axonflow-lint: compose-overlay
#
# The marker is greppable, appears in this lint's output every run, and has to
# be added by a human in a reviewed diff. Absence of the marker is treated as
# "this is a root surface", so forgetting it fails the build rather than
# exempting the file.
#
# WHY THE IMAGES DELIBERATELY DO NOT CARRY AN `ENV DEPLOYMENT_MODE` DEFAULT.
#
# Neither platform/agent/Dockerfile nor platform/orchestrator/Dockerfile sets
# one, and neither should. A baked-in default recreates the exact defect #3096
# closed one layer down: whatever value is baked in becomes the posture you get
# by forgetting to configure one, and the process can no longer distinguish
# "the operator chose this" from "the operator chose nothing". `community`
# would restore the fail-open (authentication disabled) default outright;
# `enterprise` would fail closed but would silently satisfy this very lint and
# hide an unconfigured surface. The same Dockerfile also builds both editions
# (ARG EDITION), so no single value is correct for both. The posture is
# asserted per deployment, and this check is what makes sure it is asserted.

SURFACE_RECORDS=""

# --- Compose surfaces -------------------------------------------------------
COMPOSE_AWK='
function indentof(s,   n) {
  n = 0
  while (substr(s, n + 1, 1) == " ") n++
  return n
}
function normpath(p,   parts, n, i, m, out, res) {
  gsub(/\/+/, "/", p)
  n = split(p, parts, "/")
  m = 0
  for (i = 1; i <= n; i++) {
    if (parts[i] == "" || parts[i] == ".") continue
    if (parts[i] == "..") { if (m > 0) m--; continue }
    out[++m] = parts[i]
  }
  res = ""
  for (i = 1; i <= m; i++) res = (res == "" ? out[i] : res "/" out[i])
  return res
}
function bad(reason) { printf "UNPARSEABLE\t%s\t\t%s\n", file, reason; unparseable = 1 }
# Classify an image string. Returns "agent", "orchestrator", "" (definitely not
# a surface) or "?" (cannot tell — caller must fail).
function classify_image(img,   repo, stripped) {
  if (img ~ /axonflow-agent/) return "agent"
  if (img ~ /axonflow-orchestrator/) return "orchestrator"
  # An image that NAMES an agent or an orchestrator without being the canonical
  # repository cannot be ruled out, whether or not it is variable-expanded.
  # Checking only the variable form was itself a fail-open: a literal
  # `ghcr.io/getaxonflow/af-agent:9.12.2` was silently skipped.
  #
  # Two things keep this from firing on the rest of the world. The token has to
  # sit on a NAME BOUNDARY, so `pytorch/pytorch` (the `orch` inside pyt-orch) is
  # not a match; and the image has to be plausibly OURS — an axonflow namespace,
  # or a repository part that is variable-expanded and therefore unreadable —
  # so `grafana/agent` and `datadog/agent` are third-party images, not
  # unclassifiable AxonFlow ones. A repo that legitimately needs one of those is
  # not forced into an exemption it has no way to express.
  if (tolower(img) ~ /(^|[\/_.-])(agent|orchestrator)([:\/_.-]|$)/ &&
      (tolower(img) ~ /axonflow/ || img ~ /[$]/)) return "?"
  if (img !~ /[$]/) return ""
  # Variable-expanded with no literal repository name at all (image: $IMG).
  repo = img; sub(/:[^:\/]*$/, "", repo)         # drop the tag
  stripped = repo
  gsub(/[$][{][^}]*[}]/, "", stripped)           # drop ${...}
  gsub(/[$][(][^)]*[)]/, "", stripped)           # drop $(...)
  gsub(/[$][A-Za-z_][A-Za-z0-9_]*/, "", stripped) # drop $VAR
  if (stripped !~ /[A-Za-z0-9][A-Za-z0-9]{2,}/) return "?"
  return ""
}
function flush(   df, ctx, kind) {
  if (svc == "") return
  kind = classify_image(svc_image)
  if (kind == "?") {
    if (svc_image ~ /[$]/)
      printf "UNPARSEABLE\t%s\t%s\timage %s is variable-expanded and this lint cannot rule out that it runs the agent or the orchestrator — pin the repository name or split the variable\n", file, svc, svc_image
    else
      printf "UNPARSEABLE\t%s\t%s\timage %s names an agent or orchestrator under a repository this lint does not recognise — rename it to axonflow-agent/axonflow-orchestrator, or set DEPLOYMENT_MODE on the service so the answer does not matter\n", file, svc, svc_image
    unparseable = 1
    svc = ""
    return
  }
  if (kind == "" && svc_build) {
    ctx = (svc_context != "" ? svc_context : svc_inline_build)
    if (ctx == "") ctx = "."
    df = (svc_dockerfile != "" ? svc_dockerfile : "Dockerfile")
    if (df !~ /^\//) df = ctx "/" df
    df = normpath(basedir "/" df)
    if (df == "platform/agent/Dockerfile") kind = "agent"
    else if (df == "platform/orchestrator/Dockerfile") kind = "orchestrator"
  }
  # A service this lint cannot attribute is not a surface — but if it WRITES
  # DEPLOYMENT_MODE, the value still has to be one the platform accepts. The
  # four docker/docker-compose.<client>.yaml demo overlays declare `agent:` and
  # `orchestrator:` with no image and no build (they override a base file), so
  # nothing is attributed and the modes they set were never checked at all:
  # `in-vpc-travell` would have left this lint green and hard-failed the agent
  # at boot. Presence is a question about surfaces; validity is a question about
  # the string, and it does not need the surface to be identified.
  if (kind == "" && svc_mode_state != "" && svc_mode_state != "ok") {
    printf "SURFACE\t%s\t%s\t(unattributed)\tBADVALUE: %s\n", file, svc, svc_mode_state
  }
  if (kind != "") {
    attributed++
    if (overlay) {
      printf "OVERLAY\t%s\t%s\t%s\n", file, svc, kind
    } else if (svc_envfile && svc_mode_state == "") {
      printf "UNPARSEABLE\t%s\t%s\tservice runs the %s and takes environment from env_file:, which this lint cannot read — declare DEPLOYMENT_MODE inline\n", file, svc, kind
      unparseable = 1
    } else if (svc_mode_state == "") {
      printf "SURFACE\t%s\t%s\t%s\tMISSING\n", file, svc, kind
    } else if (svc_mode_state == "ok") {
      printf "SURFACE\t%s\t%s\t%s\tok\n", file, svc, kind
    } else {
      printf "SURFACE\t%s\t%s\t%s\tBADVALUE: %s\n", file, svc, kind, svc_mode_state
    }
  }
  svc = ""
}
BEGIN {
  svcindent = -1; inservices = 0; docs = 0; attributed = 0; unparseable = 0
  declares = 0; overlay = 0; env_indent = -1
  n = split(modes, modelist, ",")
  for (i = 1; i <= n; i++) recognised[modelist[i]] = 1
}
# Extract and validate the value of an anchored DEPLOYMENT_MODE assignment.
# Sets svc_mode_state to "ok" or a human-readable rejection.
function eval_mode_line(line,   v, inner, dflt) {
  v = line
  sub(/^[[:space:]]*-?[[:space:]]*"?DEPLOYMENT_MODE"?[[:space:]]*[:=][[:space:]]*/, "", v)
  sub(/[[:space:]]+#.*$/, "", v)                 # trailing comment
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
  gsub(/^["'"'"']|["'"'"']$/, "", v)
  if (v == "") { svc_mode_state = "empty value"; return }
  if (v ~ /^[$][{][^}]*[}]$/) {
    inner = substr(v, 3, length(v) - 3)
    if (index(inner, ":-") == 0) {
      svc_mode_state = "${" inner "} has no :- default, so an unset variable leaves it empty"
      return
    }
    dflt = substr(inner, index(inner, ":-") + 2)
    if (dflt in recognised) { svc_mode_state = "ok"; return }
    svc_mode_state = "default \"" dflt "\" is not a recognised DEPLOYMENT_MODE"
    return
  }
  if (v ~ /[$]/) { svc_mode_state = "\"" v "\" is variable-expanded; use ${VAR:-<mode>}"; return }
  if (v in recognised) { svc_mode_state = "ok"; return }
  svc_mode_state = "\"" v "\" is not a recognised DEPLOYMENT_MODE"
}
{
  line = $0
  if (line ~ /axonflow-lint:[ ]*compose-overlay/) overlay = 1
  # A plain declaration of an agent/orchestrator image or Dockerfile anywhere in
  # the file. Used only as a tripwire: if one of these exists and the structural
  # parse attributed no service, the parse is wrong and the file fails.
  if (line ~ /^[ ]*image:.*axonflow-(agent|orchestrator)/) declares = 1
  if (line ~ /^[ ]*dockerfile:.*(agent|orchestrator)\/Dockerfile/) declares = 1
  if (line ~ /^---/) { docs++; if (docs > 1 || NR > 1) bad("multiple YAML documents in one Compose file") }
  if (line ~ /^[ ]*\t/ || line ~ /^\t/) bad("tab character in indentation")
  if (line ~ /^[[:space:]]*$/) next
  if (line ~ /^[[:space:]]*#/) next
  if (line ~ /^[[:space:]]*extends:/) bad("uses extends:, which this lint does not resolve")
  if (line ~ /^include:/) bad("uses a top-level include:, which this lint does not resolve")
  if (line ~ /^[[:space:]]*<<:/) bad("uses a YAML merge key, which this lint does not resolve")
  if (line ~ /:[[:space:]]+&[A-Za-z0-9_-]+[[:space:]]*$/) bad("declares a YAML anchor, which this lint does not resolve")
  if (line ~ /:[[:space:]]+\*[A-Za-z0-9_-]+[[:space:]]*$/) bad("uses a YAML alias, which this lint does not resolve")
  ind = indentof(line)
  if (ind == 0) {
    flush()
    inservices = (line ~ /^services:/)
    svcindent = -1
    next
  }
  if (!inservices) next
  if (svcindent == -1) svcindent = ind
  if (ind == svcindent && line ~ /^[[:space:]]*[A-Za-z0-9_.-]+:/) {
    flush()
    svc = line; sub(/:.*$/, "", svc); gsub(/[[:space:]]/, "", svc)
    svc_image = ""; svc_build = 0; svc_context = ""; svc_dockerfile = ""
    svc_mode_state = ""; svc_envfile = 0; svc_inline_build = ""; env_indent = -1
    next
  }
  if (svc == "") next
  # Track the `environment:` block by indent. `build.args:` and `labels:` also
  # take a KEY: VALUE map, and neither puts the variable in the container — but
  # a service-wide key match credited both. docker-compose.portal-ui.yml already
  # carries the build-arg-and-environment shape, so this is not hypothetical.
  # A same-indent `- KEY=value` under `environment:` is valid YAML block-sequence
  # style, so the block must NOT close on a list item at the same indent; and an
  # inline flow mapping (`environment: {A: b}`) puts the key on the same line, so
  # it must not be discarded by `next`.
  if (env_indent >= 0 && ind <= env_indent && line !~ /^[[:space:]]*-/) env_indent = -1
  if (line ~ /^[[:space:]]*environment:/) {
    env_indent = ind
    inline = line
    sub(/^[[:space:]]*environment:[[:space:]]*/, "", inline)
    if (inline ~ /DEPLOYMENT_MODE/) {
      gsub(/[{}",]/, " ", inline)
      n2 = split(inline, kvs, / +/)
      for (k2 = 1; k2 <= n2; k2++) {
        if (kvs[k2] == "DEPLOYMENT_MODE:" || kvs[k2] == "DEPLOYMENT_MODE=") {
          eval_mode_line("DEPLOYMENT_MODE: " kvs[k2 + 1])
        } else if (kvs[k2] ~ /^DEPLOYMENT_MODE[:=]./) {
          eval_mode_line(kvs[k2])
        }
      }
    }
    next
  }
  # ANCHORED (#3170). The old test was `line ~ /DEPLOYMENT_MODE/`, which a
  # trailing comment and NEXT_PUBLIC_DEPLOYMENT_MODE both satisfied.
  if (env_indent >= 0 && ind > env_indent &&
      line ~ /^[[:space:]]*-?[[:space:]]*"?DEPLOYMENT_MODE"?[[:space:]]*[:=]/) {
    eval_mode_line(line)
  }
  if (line ~ /^[[:space:]]*env_file:/) svc_envfile = 1
  if (line ~ /^[[:space:]]*image:/) { svc_image = line; sub(/^[[:space:]]*image:[[:space:]]*/, "", svc_image) }
  if (line ~ /^[[:space:]]*build:/) {
    svc_build = 1
    svc_inline_build = line; sub(/^[[:space:]]*build:[[:space:]]*/, "", svc_inline_build)
    gsub(/["'"'"'!]/, "", svc_inline_build)
    if (svc_inline_build == "reset null" || svc_inline_build == "null") svc_inline_build = ""
  }
  if (line ~ /^[[:space:]]*context:/) { svc_context = line; sub(/^[[:space:]]*context:[[:space:]]*/, "", svc_context); gsub(/["'"'"']/, "", svc_context) }
  if (line ~ /^[[:space:]]*dockerfile:/) { svc_dockerfile = line; sub(/^[[:space:]]*dockerfile:[[:space:]]*/, "", svc_dockerfile); gsub(/["'"'"']/, "", svc_dockerfile) }
}
END {
  flush()
  if (declares && attributed == 0 && !unparseable) {
    printf "UNPARSEABLE\t%s\t\tdeclares an agent/orchestrator image or Dockerfile but no service could be attributed — the structural parse is wrong\n", file
  }
}
'

# Discovery is the UNION of the historical name globs and "any YAML with a
# top-level services: key" (#3137: the glob missed `stack.yml` entirely).
compose_candidates() {
  find . \( -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' \
            -o -name 'compose*.yml' -o -name 'compose*.yaml' \) \
       -not -path '*/node_modules/*' -not -path './.git/*'
  grep -rl '^services:' --include='*.yml' --include='*.yaml' . 2>/dev/null \
    | grep -v '/node_modules/' | grep -v '^./.git/' || true
}

COMPOSE_FILE_COUNT=0
while IFS= read -r composefile; do
  rel="${composefile#./}"
  dir=$(dirname "$rel")
  [ "$dir" = "." ] && dir=""
  COMPOSE_FILE_COUNT=$((COMPOSE_FILE_COUNT + 1))
  out=$(awk -v basedir="$dir" -v file="$rel" -v modes="$RECOGNISED_MODES_CSV" "$COMPOSE_AWK" "$composefile" || true)
  [ -n "$out" ] && SURFACE_RECORDS="${SURFACE_RECORDS}${out}"$'\n'
done < <(compose_candidates | sed 's|^\./||' | sort -u | sed 's|^|./|')

# --- CloudFormation ECS task definitions ------------------------------------
# Unit of analysis is the CONTAINER DEFINITION, not the task definition (#3137:
# the previous parser assumed one container per resource, so a second container
# in the same ContainerDefinitions list inherited the first one's verdict).
#
# `Value: !Ref X` is resolved against the template's own Parameters block: X
# must declare AllowedValues and every one of them must be a recognised mode.
# That is what would have caught a template offering `Default: enterprise` in a
# picker whose values the platform does not accept.
CFN_AWK='
function indentof(s,   n) {
  n = 0
  while (substr(s, n + 1, 1) == " ") n++
  return n
}
function emit(   state) {
  if (!istaskdef || ckind == "") return
  attributed++
  if (cmode_state == "") {
    printf "SURFACE\t%s\t%s/%s\t%s\tMISSING\n", file, res, cname, ckind
  } else if (cmode_state ~ /^REF:/) {
    printf "CFNREF\t%s\t%s/%s\t%s\t%s\n", file, res, cname, ckind, substr(cmode_state, 5)
  } else if (cmode_state == "ok") {
    printf "SURFACE\t%s\t%s/%s\t%s\tok\n", file, res, cname, ckind
  } else {
    printf "SURFACE\t%s\t%s/%s\t%s\tBADVALUE: %s\n", file, res, cname, ckind, cmode_state
  }
}
function newcontainer() { emit(); cname = "?"; ckind = ""; cmode_state = ""; pending_mode = 0 }
function flushres() { emit(); res = ""; istaskdef = 0; cname = ""; ckind = ""; cmode_state = ""; pending_mode = 0; cd_indent = -1; item_indent = -1 }
function unquote(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); gsub(/^["'"'"']|["'"'"']$/, "", v); return v }
BEGIN {
  attributed = 0; declares = 0; bad = 0
  n = split(modes, modelist, ",")
  for (i = 1; i <= n; i++) recognised[modelist[i]] = 1
  inparams = 0; param = ""; collecting_allowed = 0
  cd_indent = -1; item_indent = -1
}
{
  line = $0
  if (line ~ /^[ ]*Image:.*axonflow-(agent|orchestrator)/) declares = 1
  if (line ~ /^[ ]*\t/ || line ~ /^\t/) { printf "UNPARSEABLE\t%s\t\ttab character in indentation\n", file; bad = 1 }
  if (line ~ /^[[:space:]]*$/ || line ~ /^[[:space:]]*#/) next

  # --- Parameters block: remember each parameter AllowedValues set ----------
  if (line ~ /^Parameters:[[:space:]]*$/) { inparams = 1; param = ""; collecting_allowed = 0; next }
  if (line ~ /^[A-Za-z]/) { inparams = 0 }
  if (inparams) {
    if (line ~ /^  [A-Za-z0-9]+:[[:space:]]*$/) {
      param = line; sub(/:.*$/, "", param); gsub(/[[:space:]]/, "", param)
      collecting_allowed = 0
      seen_param[param] = 1
      next
    }
    if (line ~ /^[[:space:]]*AllowedValues:[[:space:]]*$/) { collecting_allowed = 1; next }
    if (collecting_allowed) {
      if (line ~ /^[[:space:]]*-[[:space:]]*/) {
        v = line; sub(/^[[:space:]]*-[[:space:]]*/, "", v); v = unquote(v)
        allowed[param] = allowed[param] " " v
        next
      }
      collecting_allowed = 0
    }
  }

  # --- Resources ------------------------------------------------------------
  if (line ~ /^  [A-Za-z0-9]+:[[:space:]]*$/) { flushres(); res = line; sub(/:.*$/, "", res); gsub(/[[:space:]]/, "", res); next }
  if (line ~ /^[A-Za-z]/) { flushres(); next }
  if (res == "") next
  if (line ~ /Type:[[:space:]]*.?AWS::ECS::TaskDefinition/) istaskdef = 1

  # Container definitions are delimited by INDENT, not by "- Name:". An
  # Environment entry, a Secrets entry and a task-level Volumes entry are all
  # "- Name: x" too; keying on that string alone made every env var start a new
  # container and wiped the verdict of the real one.
  ind = indentof(line)
  if (cd_indent >= 0 && ind <= cd_indent && line !~ /^[[:space:]]*-/) cd_indent = -1
  if (line ~ /^[[:space:]]*ContainerDefinitions:[[:space:]]*$/) { cd_indent = ind; item_indent = -1; next }
  if (cd_indent >= 0 && ind > cd_indent && line ~ /^[[:space:]]*-[[:space:]]/) {
    # First key of a new list item under ContainerDefinitions.
    if (item_indent < 0 || ind <= item_indent) {
      item_indent = ind
      newcontainer()
      v = line
      if (v ~ /^[[:space:]]*-[[:space:]]*Name:/) { sub(/^[[:space:]]*-[[:space:]]*Name:[[:space:]]*/, "", v); cname = unquote(v) }
    }
  }
  if (line ~ /Image:.*axonflow-agent/) ckind = "agent"
  if (line ~ /Image:.*axonflow-orchestrator/) ckind = "orchestrator"
  # ANCHORED environment entry (#3170): "- Name: DEPLOYMENT_MODE" then "Value:".
  if (line ~ /^[[:space:]]*-?[[:space:]]*Name:[[:space:]]*"?DEPLOYMENT_MODE"?[[:space:]]*$/) { pending_mode = 1; next }
  if (pending_mode) {
    if (line ~ /^[[:space:]]*Value:/) {
      v = line; sub(/^[[:space:]]*Value:[[:space:]]*/, "", v); v = unquote(v)
      pending_mode = 0
      if (v ~ /^!Ref[[:space:]]/) {
        p = v; sub(/^!Ref[[:space:]]+/, "", p)
        cmode_state = "REF:" p
      } else if (v == "") {
        cmode_state = "empty value"
      } else if (v ~ /^!/) {
        cmode_state = "\"" v "\" uses an intrinsic this lint cannot resolve — use a literal or !Ref to a parameter with AllowedValues"
      } else if (v in recognised) {
        cmode_state = "ok"
      } else {
        cmode_state = "\"" v "\" is not a recognised DEPLOYMENT_MODE"
      }
      next
    }
    pending_mode = 0
  }
}
END {
  flushres()
  # Resolve !Ref verdicts now that the whole Parameters block has been read.
  if (declares && attributed == 0 && !bad) {
    printf "UNPARSEABLE\t%s\t\tdeclares an agent/orchestrator container image but no ECS task definition could be attributed\n", file
  }
  for (p in seen_param) {
    printf "PARAM\t%s\t%s\t%s\n", file, p, allowed[p]
  }
}
'

CFN_FILE_COUNT=0
while IFS= read -r cfnfile; do
  rel="${cfnfile#./}"
  CFN_FILE_COUNT=$((CFN_FILE_COUNT + 1))
  out=$(awk -v file="$rel" -v modes="$RECOGNISED_MODES_CSV" "$CFN_AWK" "$cfnfile" || true)
  [ -n "$out" ] && SURFACE_RECORDS="${SURFACE_RECORDS}${out}"$'\n'
done < <(grep -rl 'AWS::ECS::TaskDefinition' --include='*.yaml' --include='*.yml' . 2>/dev/null \
           | grep -v '/node_modules/' | sort || true)

# Resolve CFNREF records against the PARAM records from the same file.
CFN_REF_BAD=""
CFN_REF_OK=0
while IFS=$'\t' read -r tag file container kind param; do
  [ "$tag" = "CFNREF" ] || continue
  allowed=$(printf '%s' "$SURFACE_RECORDS" | awk -F'\t' -v f="$file" -v p="$param" '$1=="PARAM" && $2==f && $3==p {print $4}')
  if [ -z "${allowed// }" ]; then
    CFN_REF_BAD="${CFN_REF_BAD}${file}\t${container} (${kind})\tValue: !Ref ${param} — parameter has no AllowedValues, so any string reaches the container"$'\n'
    continue
  fi
  bad_values=""
  for v in $allowed; do
    case ",$RECOGNISED_MODES_CSV," in
      *",$v,"*) ;;
      *) bad_values="${bad_values}${bad_values:+, }$v" ;;
    esac
  done
  if [ -n "$bad_values" ]; then
    CFN_REF_BAD="${CFN_REF_BAD}${file}\t${container} (${kind})\tValue: !Ref ${param} — AllowedValues offers unrecognised mode(s): ${bad_values}"$'\n'
  else
    CFN_REF_OK=$((CFN_REF_OK + 1))
  fi
done < <(printf '%s' "$SURFACE_RECORDS" | grep -E '^CFNREF' || true)

# --- `docker run` launchers and published component READMEs -----------------
# #3170: five in-repo files launched the agent or the orchestrator with zero
# DEPLOYMENT_MODE, including scripts/marketplace/deploy-with-metering.sh — the
# AWS Marketplace production deploy path, which sets DATABASE_URL, so the
# container really does run the migration selector — and
# platform/orchestrator/README.md's published `kind: Deployment` manifest.
#
# Shell/workflow: a `docker run` invocation (line continuations joined) that
# names an agent or orchestrator image must carry a recognised DEPLOYMENT_MODE.
# README: a fenced code block that names an agent or orchestrator image must
# carry one, which covers both the `docker run` snippets and the Kubernetes
# manifest in the same rule.
LAUNCHER_AWK='
BEGIN {
  n = split(modes, modelist, ",")
  for (i = 1; i <= n; i++) recognised[modelist[i]] = 1
  buf = ""; startline = 0; varcount = 0; runtime_validated = 0
}
# Two-pass literal expansion of simple VAR="..." assignments in the same file.
# Without it the marketplace deploy path reads `docker run -d … $IMAGE`, whose
# literal value `${ECR_REGISTRY}/axonflow-agent:${VERSION}` is declared four
# lines above — invisible to a text scan, which is why #3170 called this feed
# vacuous. Names are substituted LONGEST FIRST so $IMAGE is not clobbered by a
# shorter $IMA; POSIX awk has no word-boundary operator to do it the other way.
function expand(t,   pass, i, k) {
  for (pass = 0; pass < 2; pass++) {
    for (i = 1; i <= varcount; i++) {
      k = varorder[i]
      gsub("[$][{]" k "[}]", vars[k], t)
      gsub("[$]" k, vars[k], t)
    }
  }
  return t
}
function record_var(name, value,   i, j, tmp) {
  if (name in vars) return
  vars[name] = value
  varorder[++varcount] = name
  # keep varorder sorted by descending name length (insertion sort; the files
  # this runs over have tens of assignments, not thousands)
  for (i = varcount; i > 1; i--) {
    if (length(varorder[i]) <= length(varorder[i-1])) break
    tmp = varorder[i]; varorder[i] = varorder[i-1]; varorder[i-1] = tmp
  }
}
function value_ok(v,   inner, dflt) {
  gsub(/^["'"'"']|["'"'"']$/, "", v)
  if (v == "") return 0
  if (v ~ /^[$][{][^}]*[}]$/) {
    inner = substr(v, 3, length(v) - 3)
    if (index(inner, ":-") == 0) return 0
    dflt = substr(inner, index(inner, ":-") + 2)
    gsub(/^["'"'"']|["'"'"']$/, "", dflt)
    return (dflt in recognised)
  }
  if (v ~ /[$]/) return 0
  return (v in recognised)
}
function check(   img, m, v, ebuf) {
  if (buf == "") return
  if (buf !~ /docker[[:space:]]+(run|create)/) { buf = ""; return }
  ebuf = expand(buf)
  # Only invocations that actually BOOT the platform are deployment surfaces.
  # `docker run --rm <image> --version` in a build smoke test neither serves
  # traffic nor reaches the migration selector; requiring a posture of it would
  # be noise, and noise is how a lint gets an exemption added. The criterion is
  # detached OR database-configured, because those are exactly the invocations
  # whose container runs getMigrationPaths and answers requests.
  # `-d`, `-di`, `-id`, `-dit`, `-itd`, `--detach`, `--detach=true` are all
  # ordinary spellings of detached, and `--restart` is an unambiguous
  # long-running signal. The short-flag cluster is restricted to the letters
  # docker actually combines with -d, because a permissive `-[A-Za-z]*d[A-Za-z]*`
  # matches the CONTAINER'"'"'s own arguments too — `docker run --rm img serve -debug`
  # is not a deployment, and that noise is how a lint gets an exemption added.
  if (ebuf !~ /docker[[:space:]]+create/ &&
      ebuf !~ /(^|[[:space:]])-[dit]*d[dit]*([[:space:]]|$)/ &&
      ebuf !~ /(^|[[:space:]])--detach([[:space:]=]|$)/ &&
      ebuf !~ /(^|[[:space:]])--restart([[:space:]=]|$)/ &&
      ebuf !~ /DATABASE_URL|DATABASE_HOST/) { buf = ""; return }
  # Which image? After expansion the answer is usually literal.
  if (ebuf !~ /axonflow[-\/](agent|orchestrator)/) {
    # Not the agent or the orchestrator — unless the image never resolved to a
    # literal name at all, in which case say so out loud rather than passing.
    if (match(ebuf, /(^|[[:space:]])[$][{]?[A-Za-z_][A-Za-z0-9_]*[}]?([[:space:]]|$)/) && ebuf ~ /[$]/)
      printf "UNRESOLVED\t%s\t%d\tdocker run with a non-literal image — this lint cannot tell whether it runs the agent or the orchestrator\n", file, startline
    buf = ""
    return
  }
  # ANCHORED. `-e NEXT_PUBLIC_DEPLOYMENT_MODE=community` must NOT satisfy this —
  # it is the exact fail-open #3170 named, and the first version of this
  # recogniser reproduced it while the Compose half was anchored.
  if (match(ebuf, /(^|[[:space:]]|["'"'"'=])DEPLOYMENT_MODE=[^[:space:]\\]+/)) {
    v = substr(ebuf, RSTART, RLENGTH)
    # Cut at the FIRST "DEPLOYMENT_MODE=" inside the match, by index rather than
    # a greedy sub(): the value itself is frequently ${DEPLOYMENT_MODE:-mode},
    # and /^.*DEPLOYMENT_MODE=/ eats through to the inner occurrence.
    v = substr(v, index(v, "DEPLOYMENT_MODE=") + 16)
    if (value_ok(v)) printf "LAUNCH\t%s\t%d\tok\n", file, startline
    else if (runtime_validated) printf "RUNTIMEVALIDATED\t%s\t%d\t%s\n", file, startline, v
    else printf "LAUNCH\t%s\t%d\tBADVALUE: DEPLOYMENT_MODE=%s\n", file, startline, v
  } else {
    printf "LAUNCH\t%s\t%d\tMISSING\n", file, startline
  }
  buf = ""
}
{
  line = $0
  # THE ONE ESCAPE HATCH for the launcher half, and it exempts only the VALUE,
  # never the presence. A deploy script that resolves the mode from its own
  # arguments or environment and then VALIDATES it against the recognised set is
  # strictly stronger than a static string check — but the static check cannot
  # see through the variable. Such a file declares itself on its own line:
  #
  #     # axonflow-lint: deployment-mode-validated
  #
  # The invocation must still name DEPLOYMENT_MODE, the exemption is greppable,
  # it has to be added by a human in a reviewed diff, and every use is printed
  # on every run.
  if (line ~ /axonflow-lint:[ ]*deployment-mode-validated/) runtime_validated = 1
  # Simple, unconditional VAR="literal" / VAR=literal assignments only. A value
  # containing a command substitution or a positional parameter is NOT recorded,
  # so it stays opaque and the invocation is reported UNRESOLVED rather than
  # silently classified as "not a surface".
  if (line ~ /^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=/) {
    aname = line
    sub(/^[[:space:]]*(export[[:space:]]+)?/, "", aname)
    avalue = aname
    sub(/=.*$/, "", aname)
    sub(/^[^=]*=/, "", avalue)
    sub(/[[:space:]]+#.*$/, "", avalue)
    gsub(/^["'"'"']|["'"'"']$/, "", avalue)
    if (avalue !~ /[$][(]|`|[$][0-9]/ && avalue != "") record_var(aname, avalue)
  }
  if (buf == "") {
    if (line ~ /docker[[:space:]]+(run|create)/) { buf = line; startline = NR }
    else next
  } else {
    buf = buf " " line
  }
  if (line ~ /\\[[:space:]]*$/) next      # continuation
  check()
}
END { check() }
'

README_AWK='
BEGIN {
  n = split(modes, modelist, ",")
  for (i = 1; i <= n; i++) recognised[modelist[i]] = 1
  infence = 0; buf = ""; startline = 0
}
function value_ok(v,   inner, dflt) {
  gsub(/^["'"'"']|["'"'"']$/, "", v)
  if (v == "") return 0
  if (v ~ /^[$][{][^}]*[}]$/) {
    inner = substr(v, 3, length(v) - 3)
    if (index(inner, ":-") == 0) return 0
    dflt = substr(inner, index(inner, ":-") + 2)
    return (dflt in recognised)
  }
  if (v ~ /[$]/) return 0
  return (v in recognised)
}
function check(   v) {
  if (buf !~ /axonflow[-\/](agent|orchestrator)/) { buf = ""; return }
  # A block that only BUILDS an image is not a deployment example. A block that
  # runs one, or declares a Kubernetes workload from one, is — and the
  # orchestrator README publishes exactly such a manifest with no env: block at
  # all (#3170).
  if (buf !~ /docker[[:space:]]+run/ && buf !~ /kind:[[:space:]]*(Deployment|StatefulSet|DaemonSet)/) { buf = ""; return }
  # Two shapes: `DEPLOYMENT_MODE=<v>` / `DEPLOYMENT_MODE: <v>` (shell, Compose)
  # and the Kubernetes env pair `- name: DEPLOYMENT_MODE` + `value: <v>`, which
  # the block-joining above renders as `DEPLOYMENT_MODE value: <v>`.
  # Anchored on both shapes for the same reason as the launcher recogniser:
  # NEXT_PUBLIC_DEPLOYMENT_MODE must not satisfy either.
  v = ""
  if (match(buf, /(^|[[:space:]]|["'"'"'])DEPLOYMENT_MODE[[:space:]]+value:[[:space:]]*[^[:space:]\\]+/)) {
    v = substr(buf, RSTART, RLENGTH)
    v = substr(v, index(v, "DEPLOYMENT_MODE") + 15)
    sub(/^[[:space:]]+value:[[:space:]]*/, "", v)
  } else if (match(buf, /(^|[[:space:]]|["'"'"'=])DEPLOYMENT_MODE[=:][[:space:]]*[^[:space:]\\]+/)) {
    v = substr(buf, RSTART, RLENGTH)
    v = substr(v, index(v, "DEPLOYMENT_MODE") + 15)
    sub(/^[=:][[:space:]]*/, "", v)
  }
  if (v != "") {
    if (value_ok(v)) printf "DOCBLOCK\t%s\t%d\tok\n", file, startline
    else printf "DOCBLOCK\t%s\t%d\tBADVALUE: %s\n", file, startline, v
  } else {
    printf "DOCBLOCK\t%s\t%d\tMISSING\n", file, startline
  }
  buf = ""
}
{
  if ($0 ~ /^```/) {
    if (infence) { check(); infence = 0 }
    else { infence = 1; buf = ""; startline = NR }
    next
  }
  if (infence) buf = buf " " $0
}
END { if (infence) check() }
'

is_excluded() {
  local p="${1#./}"
  local pref suf
  for pref in "${LAUNCHER_EXCLUDED_PREFIXES[@]}"; do
    case "$p" in "$pref"*) return 0 ;; esac
  done
  for suf in "${LAUNCHER_EXCLUDED_SUFFIXES[@]}"; do
    case "$p" in *"$suf") return 0 ;; esac
  done
  return 1
}

LAUNCHER_FILE_COUNT=0
while IFS= read -r f; do
  is_excluded "$f" && continue
  rel="${f#./}"
  LAUNCHER_FILE_COUNT=$((LAUNCHER_FILE_COUNT + 1))
  out=$(awk -v file="$rel" -v modes="$RECOGNISED_MODES_CSV" "$LAUNCHER_AWK" "$f" || true)
  [ -n "$out" ] && SURFACE_RECORDS="${SURFACE_RECORDS}${out}"$'\n'
done < <(grep -rl 'docker[[:space:]]*run' --include='*.sh' --include='*.yml' --include='*.yaml' . 2>/dev/null \
           | grep -v '/node_modules/' | sort || true)

README_FILE_COUNT=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  rel="${f#./}"
  README_FILE_COUNT=$((README_FILE_COUNT + 1))
  out=$(awk -v file="$rel" -v modes="$RECOGNISED_MODES_CSV" "$README_AWK" "$f" || true)
  [ -n "$out" ] && SURFACE_RECORDS="${SURFACE_RECORDS}${out}"$'\n'
done < <(printf '%s\n' ./platform/agent/README.md ./platform/orchestrator/README.md)

# --- Verdict ----------------------------------------------------------------
SURFACE_MISSING=$(printf '%s' "$SURFACE_RECORDS" | grep -E '^(SURFACE|LAUNCH|DOCBLOCK)\b' | grep -E '(MISSING|BADVALUE)' || true)
SURFACE_BAD=$(printf '%s' "$SURFACE_RECORDS" | grep -E '^UNPARSEABLE\b' || true)
SURFACE_OK_COUNT=$(printf '%s' "$SURFACE_RECORDS" | grep -cE '^(SURFACE|LAUNCH|DOCBLOCK)\b.*[[:space:]]ok$' || true)
SURFACE_OVERLAYS=$(printf '%s' "$SURFACE_RECORDS" | grep -E '^OVERLAY\b' || true)
SURFACE_UNRESOLVED=$(printf '%s' "$SURFACE_RECORDS" | grep -E '^UNRESOLVED\b' || true)
SURFACE_RUNTIME=$(printf '%s' "$SURFACE_RECORDS" | grep -E '^RUNTIMEVALIDATED\b' || true)

# --- Floor assertion (#3170) ------------------------------------------------
# Not a magnitude — named surfaces. A magnitude floor drifts, and a zero-file
# scan from the wrong directory would still have to beat it. Each entry below
# must be classified IF ITS FILE IS PRESENT, and at least two entries must be
# satisfied overall. The file-present condition is load-bearing rather than
# lax: this script is rsynced to the public community mirror, where `ee/` and
# `infrastructure/` do not exist, so an unconditional list would fail there for
# the wrong reason. The "at least two" floor is what catches the real class —
# a scan that saw no repository at all satisfies nothing.
FLOOR_MISSING=""
FLOOR_SATISFIED=0
if [ "$FIXTURE_MODE" -eq 0 ]; then
  while IFS='|' read -r wfile wsvc; do
    [ -n "$wfile" ] || continue
    [ -f "$wfile" ] || continue
    if printf '%s' "$SURFACE_RECORDS" | grep -qE "^(SURFACE|CFNREF)"$'\t'"$(printf '%s' "$wfile" | sed 's/[.[\*^$]/\\&/g')"$'\t'"$(printf '%s' "$wsvc" | sed 's/[.[\*^$]/\\&/g')"$'\t'; then
      FLOOR_SATISFIED=$((FLOOR_SATISFIED + 1))
    else
      FLOOR_MISSING="${FLOOR_MISSING}  ${wfile} → ${wsvc} (the file is present but no surface was attributed to it)"$'\n'
    fi
  done <<'FLOOR'
docker-compose.yml|axonflow-agent
docker-compose.yml|axonflow-orchestrator
docker-compose.enterprise.yml|axonflow-agent
docker-compose.enterprise.yml|axonflow-orchestrator
ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml|AgentTaskDefinition/agent
ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml|OrchestratorTaskDefinition/orchestrator
FLOOR
  if [ "$FLOOR_SATISFIED" -lt 2 ]; then
    FLOOR_MISSING="${FLOOR_MISSING}  only ${FLOOR_SATISFIED} of the expected root surfaces were found in $(pwd)"$'\n'
  fi
fi

if [ -n "$SURFACE_MISSING" ] || [ -n "$SURFACE_BAD" ] || [ -n "$CFN_REF_BAD" ] || [ -n "$FLOOR_MISSING" ]; then
  echo ""
  echo "❌ DEPLOYMENT_MODE surface check failed (Issues #3117, #3170, #3137)"
  echo ""
  if [ -n "$SURFACE_MISSING" ]; then
    echo "These surfaces run the agent or orchestrator WITHOUT a recognised DEPLOYMENT_MODE:"
    echo ""
    printf '%s\n' "$SURFACE_MISSING" | awk -F'\t' '{printf "  %-58s %s %s %s\n", $2, $3, $4, $5}'
    echo ""
  fi
  if [ -n "$CFN_REF_BAD" ]; then
    echo "These ECS container definitions take DEPLOYMENT_MODE from a CloudFormation"
    echo "parameter that can carry a value the platform does not recognise:"
    echo ""
    printf '%b' "$CFN_REF_BAD" | awk -F'\t' '{printf "  %-58s %s\n     %s\n", $1, $2, $3}'
    echo ""
  fi
  if [ -n "$SURFACE_BAD" ]; then
    echo "These files could not be classified with certainty (treated as failures, never skipped):"
    echo ""
    printf '%s\n' "$SURFACE_BAD" | awk -F'\t' '{printf "  %-58s %s\n", $2, $4}'
    echo ""
  fi
  if [ -n "$FLOOR_MISSING" ]; then
    echo "The scan did not find surfaces that must exist in this repository:"
    echo ""
    printf '%s' "$FLOOR_MISSING"
    echo ""
    echo "  A green result would be vacuous. Either the scan ran against the wrong"
    echo "  tree, or one of these surfaces was renamed — update the FLOOR list."
    echo ""
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "HOW TO FIX:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "Since #3096 an UNSET DEPLOYMENT_MODE is no longer Community — it is the"
  echo "enterprise posture, and since #3167 an UNRECOGNISED value is a hard boot"
  echo "failure rather than the widest migration set. Set it explicitly, to one of:"
  echo ""
  echo "  ${RECOGNISED_MODES[*]}"
  echo ""
  echo "  # Compose (map form)"
  echo "  environment:"
  echo "    DEPLOYMENT_MODE: \${DEPLOYMENT_MODE:-community}"
  echo ""
  echo "  # Compose (list form)"
  echo "  environment:"
  echo "    - DEPLOYMENT_MODE=\${DEPLOYMENT_MODE:-community}"
  echo ""
  echo "  # CloudFormation ECS container definition"
  echo "  - Name: DEPLOYMENT_MODE"
  echo "    Value: !Ref DeploymentMode      # parameter needs AllowedValues"
  echo ""
  echo "  # docker run"
  echo "  -e DEPLOYMENT_MODE=\${DEPLOYMENT_MODE:-in-vpc-enterprise}"
  echo ""
  echo "If the file is a Compose OVERRIDE that inherits the base file's"
  echo "environment, mark it explicitly with a line reading:"
  echo ""
  echo "  # axonflow-lint: compose-overlay"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 1
fi

if [ -n "$SURFACE_OVERLAYS" ]; then
  echo "ℹ️  Compose override files exempted by an explicit \`# axonflow-lint: compose-overlay\` marker:"
  printf '%s\n' "$SURFACE_OVERLAYS" | awk -F'\t' '{printf "     %s → %s (%s)\n", $2, $3, $4}'
fi
if [ -n "$SURFACE_RUNTIME" ]; then
  echo "ℹ️  These launchers pass a non-literal DEPLOYMENT_MODE and carry an explicit"
  echo "   \`# axonflow-lint: deployment-mode-validated\` marker — the file validates the"
  echo "   value against the recognised set itself. Presence is still enforced:"
  printf '%s\n' "$SURFACE_RUNTIME" | awk -F'\t' '{printf "     %s:%s — DEPLOYMENT_MODE=%s\n", $2, $3, $4}'
fi
if [ -n "$SURFACE_UNRESOLVED" ]; then
  echo "ℹ️  These \`docker run\` invocations boot a container whose image never resolved to a"
  echo "   literal name, so this lint could not rule in OR out that it is the agent or the"
  echo "   orchestrator. Reported, not failed — this is the residual gap, not a clean bill:"
  printf '%s\n' "$SURFACE_UNRESOLVED" | awk -F'\t' '{printf "     %s:%s — %s\n", $2, $3, $4}'
fi
echo "ℹ️  Launcher scan skipped these paths (test harnesses, not deployment surfaces):"
printf '     %s\n' "${LAUNCHER_EXCLUDED_PREFIXES[@]}" "*${LAUNCHER_EXCLUDED_SUFFIXES[0]}"
echo "✅ DEPLOYMENT_MODE surface check passed — ${SURFACE_OK_COUNT} surface(s) set a recognised DEPLOYMENT_MODE (${CFN_REF_OK} via a bounded CloudFormation parameter)"
echo "   scanned: ${COMPOSE_FILE_COUNT} compose file(s), ${CFN_FILE_COUNT} CloudFormation file(s), ${LAUNCHER_FILE_COUNT} launcher file(s), ${README_FILE_COUNT} component README(s)"
