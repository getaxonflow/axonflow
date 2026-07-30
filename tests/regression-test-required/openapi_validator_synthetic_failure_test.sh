#!/usr/bin/env bash
# Synthetic-failure proof for the OpenAPI validation gate
# (.github/workflows/validate-openapi.yml).
#
# A past regression surfaced that the workflow originally only linted
# policy-api.yaml — agent-api.yaml and orchestrator-api.yaml were
# silently exempt and accumulated 21 broken `Error` $refs plus a
# duplicate `PolicyMatch:` schema. After expansion to all three specs,
# without this test, a future cleanup that reverted the loop back to a
# single spec would silently undo the fix and the gate would go quiet
# again.
#
# This test does not invoke the workflow — it asserts the workflow file
# itself contains the loop (so a regression that drops a spec from the
# list fails this test) AND that swagger-cli + spectral actually reject
# a synthetic broken YAML (so a regression that swaps in a no-op
# linter also fails).
#
# ─────────────────────────────────────────────────────────────────────
# #3140 — THE TOOL CHECKS FAIL CLOSED
# ─────────────────────────────────────────────────────────────────────
# Sections 2-3 used to `exit 0` with `skip: swagger-cli not installed
# locally — CI runs the validator step on every PR`, and section 4 was
# wrapped in `if command -v spectral`. Both premises were false on the
# platform that matters:
#
#   * Neither tool ships on the GitHub-hosted runner image, and until
#     this change the `Run regression-test suite` job installed neither.
#     So once #3121 made this file actually execute in CI, the entire
#     synthetic-failure half — the part that proves the validator would
#     catch a broken spec rather than merely being configured — exited 0
#     without running. "16/16 passed" overstated coverage by one whole
#     test half.
#   * "CI runs the validator step on every PR" is about a DIFFERENT job
#     (validate-openapi.yml), and that job only proves the CURRENT specs
#     validate. It never proves the linter would REJECT a broken one,
#     which is the only thing sections 2-4 exist to establish.
#
# A missing tool is now a hard failure with an install hint, matching
# saas_perf_testing_env_config_test.sh's treatment of `yq` (#3138). The
# workflow installs both tools unconditionally, so in CI the assertions
# always run. Same class as #3098 and #3121: a skip that reads as a pass.
#
# Run locally (needs swagger-cli and spectral):
#   npm install -g @apidevtools/swagger-cli @stoplight/spectral-cli
#   bash tests/regression-test-required/openapi_validator_synthetic_failure_test.sh

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKFLOW="${REPO_ROOT}/.github/workflows/validate-openapi.yml"

# Anti-vacuity floor. Every assertion below bumps this; the tail refuses to
# report success unless all of them ran. Without it, a future edit that
# deletes a whole section shrinks the test silently rather than failing —
# which is the same defect class this file was rewritten to close.
#   [1] 4 specs referenced by the workflow            = 4
#   [2] swagger-cli rejects a broken $ref             = 1
#   [3] swagger-cli rejects a duplicate key           = 1
#   [4] spectral rejects a malformed example          = 1
#   [5] both tools ACCEPT a well-formed spec          = 2
EXPECTED_ASSERTIONS=9
ASSERTIONS_RUN=0
assert_ok() { ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1)); echo "  ok: $1"; }

# --- 1. Workflow loop covers all 4 specs ------------------------------

if [ ! -f "$WORKFLOW" ]; then
  echo "FAIL: workflow file not found at $WORKFLOW"
  exit 1
fi

# masfeat-api.yaml was orphaned from the gate until #2881 and was still
# missing from this guard afterwards — the same "the check under-covers
# what it claims to cover" shape the rest of this file is about. The list
# here must equal the list the workflow loops over.
required_specs=(
  "docs/api/agent-api.yaml"
  "docs/api/orchestrator-api.yaml"
  "docs/api/policy-api.yaml"
  "docs/api/masfeat-api.yaml"
)
for spec in "${required_specs[@]}"; do
  if ! grep -q "$spec" "$WORKFLOW"; then
    echo "FAIL: $WORKFLOW does not reference $spec — gate would skip it (#1759 regression)"
    exit 1
  fi
  assert_ok "workflow validates $spec"
done

# --- 2. swagger-cli rejects a broken-$ref fixture --------------------

# Hard failure, never a skip: see the #3140 note in the header.
if ! command -v swagger-cli >/dev/null 2>&1; then
  echo "FAIL: 'swagger-cli' is required by this test and is not on PATH."
  echo "      Install with: npm install -g @apidevtools/swagger-cli"
  echo "      A test that cannot run must not report success — this half of the"
  echo "      file is the only thing that proves the OpenAPI gate would REJECT a"
  echo "      broken spec rather than merely being pointed at one (#3140)."
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cat > "$tmp_dir/broken.yaml" <<'YAML'
openapi: 3.0.3
info:
  title: synthetic-failure-test
  version: 0.0.0
paths:
  /probe:
    get:
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                # This $ref points at a schema that doesn't exist —
                # swagger-cli must refuse to validate the file.
                $ref: '#/components/schemas/MissingSchema'
components:
  schemas:
    Existing:
      type: object
YAML

# Exit status alone would accept a swagger-cli that rejects everything, so the
# rejection is matched on its REASON — the same treatment section 4 needed.
broken_out="$(swagger-cli validate "$tmp_dir/broken.yaml" 2>&1)" && broken_rc=0 || broken_rc=$?
if [ "$broken_rc" -eq 0 ]; then
  echo "FAIL: swagger-cli accepted a broken-\$ref fixture — gate is a no-op"
  exit 1
fi
if ! grep -qi 'MissingSchema' <<<"$broken_out"; then
  echo "FAIL: swagger-cli rejected the fixture, but not for the dangling \$ref it contains."
  printf '%s\n' "$broken_out" | sed 's/^/      /'
  exit 1
fi
assert_ok "swagger-cli rejects a dangling \$ref, naming the missing schema"

# --- 3. swagger-cli rejects a duplicate-key fixture ------------------

cat > "$tmp_dir/dup.yaml" <<'YAML'
openapi: 3.0.3
info:
  title: synthetic-failure-test
  version: 0.0.0
paths: {}
components:
  schemas:
    Duplicated:
      type: object
      properties:
        a:
          type: string
    Duplicated:
      type: object
      properties:
        b:
          type: string
YAML

dup_out="$(swagger-cli validate "$tmp_dir/dup.yaml" 2>&1)" && dup_rc=0 || dup_rc=$?
if [ "$dup_rc" -eq 0 ]; then
  echo "FAIL: swagger-cli accepted a duplicate-key fixture — gate would have missed PolicyMatch"
  exit 1
fi
# NB this proves the YAML LOADER rejects the duplicate key, which is what caught
# the duplicate `PolicyMatch:` — not a schema-level check.
if ! grep -qiE 'duplicat' <<<"$dup_out"; then
  echo "FAIL: swagger-cli rejected the fixture, but not for the duplicated mapping key."
  printf '%s\n' "$dup_out" | sed 's/^/      /'
  exit 1
fi
assert_ok "swagger-cli rejects a duplicate schema key, naming the duplication"

# --- 4. spectral rejects a malformed-example fixture -----------------

# Hard failure, not `if command -v spectral`. The conditional was the same
# defect as the swagger-cli skip above: on a runner without spectral this
# section evaporated and the file still printed PASS (#3140).
if ! command -v spectral >/dev/null 2>&1; then
  echo "FAIL: 'spectral' is required by this test and is not on PATH."
  echo "      Install with: npm install -g @stoplight/spectral-cli"
  echo "      Without it nothing proves the --fail-severity error gate in"
  echo "      validate-openapi.yml would reject a malformed example (#3140)."
  exit 1
fi

# The fixture carries `operationId`, `description` and `tags` deliberately. The
# repo ruleset also raises `operation-operationId` to error, so a fixture
# missing it produces TWO errors — and an exit-status-only assertion would then
# stay green with `oas3-valid-media-example` switched off, which is precisely the
# regression this section exists to catch. The fixture is otherwise clean so the
# target rule is the only error, and the assertion greps for that rule BY NAME
# rather than trusting the exit status.
cat > "$tmp_dir/bad-example.yaml" <<'YAML'
openapi: 3.0.3
info:
  title: synthetic-failure-test
  version: 0.0.0
  description: Synthetic fixture for the OpenAPI validation gate.
  license:
    name: Proprietary
paths:
  /probe:
    get:
      summary: Probe
      description: Synthetic fixture for the OpenAPI validation gate.
      operationId: getProbeBadExample
      tags:
        - probe
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                type: object
                required:
                  - count
                properties:
                  count:
                    type: integer
              example:
                # Missing required 'count' — oas3-valid-media-example must fire.
                name: "synthetic"
components:
  schemas: {}
YAML

# --ruleset is passed explicitly, as validate-openapi.yml does. Spectral would
# auto-discover .spectral.yaml from the cwd anyway, but "the gate's ruleset" is
# the thing under test and it should not depend on where the test was invoked.
spectral_out="$(spectral lint "$tmp_dir/bad-example.yaml" --ruleset "${REPO_ROOT}/.spectral.yaml" --fail-severity error 2>&1)" && spectral_rc=0 || spectral_rc=$?
if [ "$spectral_rc" -eq 0 ]; then
  echo "FAIL: spectral accepted an example missing a required field — error-severity gate is broken"
  printf '%s\n' "$spectral_out" | sed 's/^/      /'
  exit 1
fi
if ! grep -q 'oas3-valid-media-example' <<<"$spectral_out"; then
  echo "FAIL: spectral exited non-zero, but NOT because of oas3-valid-media-example."
  echo "      Exit status alone is not the assertion: the repo ruleset raises several"
  echo "      rules to error, so a run can fail for an unrelated reason while the"
  echo "      example-validation rule is switched off — which is the regression this"
  echo "      section exists to catch."
  printf '%s\n' "$spectral_out" | sed 's/^/      /'
  exit 1
fi
assert_ok "spectral rejects an example missing a required field, naming oas3-valid-media-example"

# --- 5. POSITIVE CONTROLS: both tools ACCEPT a well-formed spec -------
#
# Sections 2-4 all assert "the tool exits non-zero". A tool that is broken,
# crashing, or a shim that exits non-zero unconditionally satisfies every
# one of them — the same "passes for the wrong reason" shape as the skips
# this file just removed. In particular, spectral's transitive dependency
# tree has a known crash class (see the pinned install in
# validate-openapi.yml: spectral-core 1.23.0 + nimma 0.2.3 die with
# `Cannot read properties of null`), and a crash is a non-zero exit.
# These controls make that observable instead of green.

# Warning-clean as well as error-clean under the repo ruleset, deliberately.
# The earlier version omitted servers/contact/license/description/tags, so
# raising any one of those to error — an ordinary ruleset tightening — made this
# CONTROL fail and reported "spectral is not discriminating", blaming the tool
# for a dirty fixture. The control has to be the thing that is above suspicion.
cat > "$tmp_dir/good.yaml" <<'YAML'
openapi: 3.0.3
info:
  title: synthetic-control
  version: 0.0.0
  description: Positive control for the OpenAPI synthetic-failure fixtures.
  contact:
    name: AxonFlow
  license:
    name: Proprietary
servers:
  - url: https://example.invalid
tags:
  - name: probe
    description: Synthetic control operations.
paths:
  /probe:
    get:
      summary: Probe
      description: Positive control for the synthetic-failure fixtures.
      operationId: getProbe
      tags:
        - probe
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Existing'
              example:
                count: 1
components:
  schemas:
    Existing:
      type: object
      required:
        - count
      properties:
        count:
          type: integer
YAML

if ! swagger-cli validate "$tmp_dir/good.yaml" >/dev/null 2>&1; then
  echo "FAIL: swagger-cli rejected a well-formed spec — it is not discriminating,"
  echo "      so sections 2-3 above passed for the wrong reason."
  swagger-cli validate "$tmp_dir/good.yaml" 2>&1 | sed 's/^/      /' || true
  exit 1
fi
assert_ok "CONTROL: swagger-cli accepts a well-formed spec"

if ! spectral lint "$tmp_dir/good.yaml" --ruleset "${REPO_ROOT}/.spectral.yaml" --fail-severity error >/dev/null 2>&1; then
  echo "FAIL: spectral rejected (or crashed on) a well-formed spec — it is not"
  echo "      discriminating, so section 4 above passed for the wrong reason."
  spectral lint "$tmp_dir/good.yaml" --ruleset "${REPO_ROOT}/.spectral.yaml" --fail-severity error 2>&1 | sed 's/^/      /' || true
  exit 1
fi
assert_ok "CONTROL: spectral accepts a well-formed spec"

# --- Assertion floor --------------------------------------------------

echo "Assertions run: ${ASSERTIONS_RUN} / expected: ${EXPECTED_ASSERTIONS}"
if [ "$ASSERTIONS_RUN" -ne "$EXPECTED_ASSERTIONS" ]; then
  echo "FAIL: assertion-count floor tripped — ran ${ASSERTIONS_RUN} of ${EXPECTED_ASSERTIONS}."
  echo "      A section stopped running, or one was added/removed without updating"
  echo "      EXPECTED_ASSERTIONS. Either way this run is not entitled to report success."
  exit 1
fi

echo "PASS: openapi validator gate has the right shape and rejects broken fixtures"
