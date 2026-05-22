#!/usr/bin/env bash
# Self-test for check-workflow-telemetry-marker.sh.
# Each fixture exercises one detection or one false-positive guard the
# hostile review of PR #2214 identified. The lint script's coverage is
# proven by the union of these fixtures passing/failing as expected.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LINT="${SCRIPT_DIR}/check-workflow-telemetry-marker.sh"

if [ ! -x "$LINT" ]; then
    echo "FAIL: lint script not executable: $LINT" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/workflows"

# ===== COMPLIANT FIXTURES — lint must NOT flag these =====

# C1: agent-running with AXONFLOW_TELEMETRY=off (quoted).
cat > "$WORK/workflows/c1-telemetry-off-quoted.yml" <<'EOF'
name: c1
on: workflow_dispatch
env:
  AXONFLOW_TELEMETRY: 'off'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
EOF

# C2: agent-running with internal license.
cat > "$WORK/workflows/c2-internal-license.yml" <<'EOF'
name: c2
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      AXONFLOW_LICENSE_KEY: ${{ secrets.AXONFLOW_INTERNAL_LICENSE_E2E }}
    steps:
      - run: docker compose up -d
EOF

# C3: escape-hatch with non-trivial reason.
cat > "$WORK/workflows/c3-escape-hatch.yml" <<'EOF'
name: c3
# telemetry-classification: legacy-stub-for-migration-validation
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
EOF

# C4: NOT agent-running — exempt regardless of marker.
cat > "$WORK/workflows/c4-no-agent.yml" <<'EOF'
name: c4
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "lint-only, no agent"
EOF

# C5 (hostile-review-driven): docker compose with multiple -f and --env-file flags.
cat > "$WORK/workflows/c5-multi-flag-compose.yml" <<'EOF'
name: c5
on: workflow_dispatch
env:
  AXONFLOW_TELEMETRY: 'off'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose -f a.yml -f b.yml --env-file .env.ci up -d
EOF

# C6 (hostile-review-driven): direct binary invocation with marker.
cat > "$WORK/workflows/c6-direct-binary.yml" <<'EOF'
name: c6
on: workflow_dispatch
env:
  AXONFLOW_TELEMETRY: 'off'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: ./platform/agent/agent --port 8080
EOF

# C7 (hostile-review-driven): docker compose start (not up).
cat > "$WORK/workflows/c7-compose-start.yml" <<'EOF'
name: c7
on: workflow_dispatch
env:
  AXONFLOW_TELEMETRY: 'off'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose start agent
EOF

# C8 (hostile-review-driven): docker compose run (one-shot).
cat > "$WORK/workflows/c8-compose-run.yml" <<'EOF'
name: c8
on: workflow_dispatch
env:
  AXONFLOW_TELEMETRY: 'off'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose run --rm agent /agent --version
EOF

# C9 (hostile-review-driven): docker run of published image.
cat > "$WORK/workflows/c9-docker-run-image.yml" <<'EOF'
name: c9
on: workflow_dispatch
env:
  AXONFLOW_TELEMETRY: 'off'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker run --rm -p 8080:8080 ghcr.io/getaxonflow/axonflow-agent:latest
EOF

# C10 (hostile-review-driven): go run of agent.
cat > "$WORK/workflows/c10-go-run-agent.yml" <<'EOF'
name: c10
on: workflow_dispatch
env:
  AXONFLOW_TELEMETRY: 'off'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go run ./cmd/agent/main.go
EOF

# ===== VIOLATION FIXTURES — lint MUST flag these =====

# V1: docker compose up without marker.
cat > "$WORK/workflows/v1-compose-up-no-marker.yml" <<'EOF'
name: v1
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
EOF

# V2: direct binary without marker.
cat > "$WORK/workflows/v2-direct-binary-no-marker.yml" <<'EOF'
name: v2
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: ./platform/agent/agent --port 8080
EOF

# V3 (H-3): comment-only license reference does NOT satisfy the marker.
cat > "$WORK/workflows/v3-comment-only-license.yml" <<'EOF'
name: v3
# This workflow doesn't actually wire AXONFLOW_LICENSE_KEY: ${{ secrets.AXONFLOW_INTERNAL_LICENSE_E2E }} —
# the comment is just documentation about a related workflow.
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
EOF

# V4 (H-4): empty escape-hatch reason rejected.
cat > "$WORK/workflows/v4-empty-escape-hatch.yml" <<'EOF'
name: v4
# telemetry-classification:
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
EOF

# V5 (H-4): too-short escape-hatch reason rejected (< 8 non-space chars).
cat > "$WORK/workflows/v5-short-escape-hatch.yml" <<'EOF'
name: v5
# telemetry-classification: idk
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
EOF

# V6 (H-1): docker compose start without marker — must catch.
cat > "$WORK/workflows/v6-compose-start-no-marker.yml" <<'EOF'
name: v6
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose start agent
EOF

# V7 (H-1): docker run published image without marker.
cat > "$WORK/workflows/v7-docker-run-no-marker.yml" <<'EOF'
name: v7
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker run --rm ghcr.io/getaxonflow/axonflow-agent:latest
EOF

# V8 (H-1): go run agent without marker.
cat > "$WORK/workflows/v8-go-run-no-marker.yml" <<'EOF'
name: v8
on: workflow_dispatch
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go run ./cmd/agent/
EOF

set +e
"$LINT" "$WORK/workflows" 2>"$WORK/lint.err"
rc=$?
set -e

# All 8 violations must be reported. None of the 10 compliant fixtures may
# false-positive.
expected_violations=("v1-compose-up-no-marker" "v2-direct-binary-no-marker" "v3-comment-only-license" "v4-empty-escape-hatch" "v5-short-escape-hatch" "v6-compose-start-no-marker" "v7-docker-run-no-marker" "v8-go-run-no-marker")
expected_compliant=("c1-telemetry-off-quoted" "c2-internal-license" "c3-escape-hatch" "c4-no-agent" "c5-multi-flag-compose" "c6-direct-binary" "c7-compose-start" "c8-compose-run" "c9-docker-run-image" "c10-go-run-agent")

if [ "$rc" -ne 1 ]; then
    echo "FAIL: expected exit 1 (8 violations present), got $rc" >&2
    cat "$WORK/lint.err" >&2
    exit 1
fi

# Each expected-violation fixture MUST be flagged.
missing=0
for v in "${expected_violations[@]}"; do
    if ! grep -q "${v}.yml" "$WORK/lint.err"; then
        echo "FAIL: lint missed violation fixture ${v}.yml" >&2
        missing=$((missing + 1))
    fi
done
if [ "$missing" -gt 0 ]; then
    cat "$WORK/lint.err" >&2
    exit 1
fi

# No compliant fixture may appear as a violation.
false_pos=0
for c in "${expected_compliant[@]}"; do
    if grep -q "${c}.yml" "$WORK/lint.err"; then
        echo "FAIL: false-positive on compliant fixture ${c}.yml" >&2
        false_pos=$((false_pos + 1))
    fi
done
if [ "$false_pos" -gt 0 ]; then
    cat "$WORK/lint.err" >&2
    exit 1
fi

# Now remove all violation fixtures and confirm lint passes.
for v in "${expected_violations[@]}"; do
    rm -f "$WORK/workflows/${v}.yml"
done
set +e
"$LINT" "$WORK/workflows" 2>"$WORK/lint.err"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
    echo "FAIL: expected exit 0 after removing violations, got $rc" >&2
    cat "$WORK/lint.err" >&2
    exit 1
fi

echo "All assertions passed (10 compliant + 8 violation fixtures). ✓"
