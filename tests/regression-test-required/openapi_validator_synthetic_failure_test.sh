#!/usr/bin/env bash
# Synthetic-failure proof for the OpenAPI validation gate
# (.github/workflows/validate-openapi.yml).
#
# axonflow-enterprise#1759 surfaced that the workflow originally only
# linted policy-api.yaml — agent-api.yaml and orchestrator-api.yaml were
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
# Run locally:
#   bash tests/regression-test-required/openapi_validator_synthetic_failure_test.sh

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKFLOW="${REPO_ROOT}/.github/workflows/validate-openapi.yml"

# --- 1. Workflow loop covers all 3 specs ------------------------------

if [ ! -f "$WORKFLOW" ]; then
  echo "FAIL: workflow file not found at $WORKFLOW"
  exit 1
fi

required_specs=(
  "docs/api/agent-api.yaml"
  "docs/api/orchestrator-api.yaml"
  "docs/api/policy-api.yaml"
)
for spec in "${required_specs[@]}"; do
  if ! grep -q "$spec" "$WORKFLOW"; then
    echo "FAIL: $WORKFLOW does not reference $spec — gate would skip it (#1759 regression)"
    exit 1
  fi
done

# --- 2. swagger-cli rejects a broken-$ref fixture --------------------

if ! command -v swagger-cli >/dev/null 2>&1; then
  echo "skip: swagger-cli not installed locally — CI runs the validator step on every PR"
  exit 0
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

if swagger-cli validate "$tmp_dir/broken.yaml" >/dev/null 2>&1; then
  echo "FAIL: swagger-cli accepted a broken-\$ref fixture — gate is a no-op"
  exit 1
fi

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

if swagger-cli validate "$tmp_dir/dup.yaml" >/dev/null 2>&1; then
  echo "FAIL: swagger-cli accepted a duplicate-key fixture — gate would have missed PolicyMatch"
  exit 1
fi

# --- 4. spectral rejects a malformed-example fixture -----------------

if command -v spectral >/dev/null 2>&1; then
  cat > "$tmp_dir/bad-example.yaml" <<'YAML'
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

  if spectral lint "$tmp_dir/bad-example.yaml" --fail-severity error >/dev/null 2>&1; then
    echo "FAIL: spectral accepted an example missing a required field — error-severity gate is broken"
    exit 1
  fi
fi

echo "PASS: openapi validator gate has the right shape and rejects broken fixtures"
