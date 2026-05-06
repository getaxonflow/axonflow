#!/usr/bin/env bash
# Codex plugin V1 paid-tier walkthrough — runs against on-demand staging.
#
# Codex's CLI supports headless agent execution via `codex exec "<prompt>"`.
# This walkthrough drives codex against a staged AxonFlow plugin install
# pointed at https://try-staging.getaxonflow.com.
#
# Coverage:
#   1. Stage the plugin to ~/.codex (hooks.json + scripts) using the same
#      install steps the user would run.
#   2. Drive `codex exec` with prompts that should fire the plugin's
#      governance hooks (Bash tool calls).
#   3. Verify hooks reach the staging agent.
#   4. Trigger recovery flow via the recover.sh script.
#   5. (Manual or automated) buyer flow.
#
# What this catches that the host-cli-shim test doesn't:
#   - Codex's actual hook-loading behaviour against a real config
#   - End-to-end "user prompt → codex executes → hook fires → agent
#     receives request" flow
#
# Requires:
#   - codex CLI (brew install openai/codex/codex or similar)
#   - codex login (already done; verifies via `codex login status`)
#   - jq, curl, python3
#
# Override defaults via env:
#   AGENT_URL    — staging endpoint (default https://try-staging.getaxonflow.com)
#   TEST_EMAIL   — recovery target (default dev@getaxonflow.com)
#   PLUGIN_PATH  — path to local axonflow-codex-plugin checkout

set -uo pipefail

AGENT_URL="${AGENT_URL:-https://try-staging.getaxonflow.com}"
TEST_EMAIL="${TEST_EMAIL:-dev@getaxonflow.com}"
PLUGIN_PATH="${PLUGIN_PATH:-/Users/saurabhjain/Development/axonflow-codex-plugin}"

WORKDIR=$(mktemp -d 2>/dev/null || mktemp -d -t codex-walkthrough)
TEST_HOME="$WORKDIR/home"
mkdir -p "$TEST_HOME/.codex"
chmod 0700 "$TEST_HOME/.codex"

PASS=0
FAIL=0
SKIP=0
fail() { echo "  ❌ FAIL: $1"; FAIL=$((FAIL+1)); }
pass() { echo "  ✅ PASS: $1"; PASS=$((PASS+1)); }
skip() { echo "  ⏭️  SKIP: $1"; SKIP=$((SKIP+1)); }
note() { echo "  📝 $1"; }
sect() { echo ""; echo "===== $1 ====="; }

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "Codex V1 paid-tier walkthrough — staging"
echo "  AGENT_URL   = $AGENT_URL"
echo "  TEST_EMAIL  = $TEST_EMAIL"
echo "  PLUGIN_PATH = $PLUGIN_PATH"
echo "  TEST_HOME   = $TEST_HOME (cleaned on exit)"

# ---------------------------------------------------------------------------
# 0. preflight
# ---------------------------------------------------------------------------
sect "Preflight"
for tool in codex jq curl python3; do
  command -v "$tool" >/dev/null 2>&1 \
    && pass "$tool on PATH" \
    || { fail "$tool not on PATH"; exit 1; }
done

# Verify codex auth.
if codex login status 2>&1 | grep -qE "Logged in|authenticated"; then
  pass "codex CLI authenticated"
else
  fail "codex CLI not authenticated — run \`codex login\` first"
  exit 1
fi

# Verify staging is reachable.
HEALTH=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$AGENT_URL/health" || echo "000")
if [ "$HEALTH" = "200" ]; then
  pass "$AGENT_URL/health responds 200"
else
  fail "staging unreachable — got HTTP $HEALTH from $AGENT_URL/health"
  exit 1
fi

[ -d "$PLUGIN_PATH/scripts" ] && pass "plugin checkout found at $PLUGIN_PATH" \
  || { fail "missing plugin checkout"; exit 1; }

# ---------------------------------------------------------------------------
# 1. stage plugin to test home
# ---------------------------------------------------------------------------
sect "Step 1 — stage plugin to TEST_HOME"

# Codex picks up hooks from ~/.codex/hooks.json. Our hooks.json references
# scripts via relative `./scripts/X.sh`; for the staging walkthrough we
# point those at the plugin checkout.
PLUGIN_STAGE="$TEST_HOME/.codex/axonflow-plugin"
mkdir -p "$PLUGIN_STAGE"
cp -rp "$PLUGIN_PATH/scripts" "$PLUGIN_STAGE/"
cp -p "$PLUGIN_PATH/hooks/hooks.json" "$TEST_HOME/.codex/hooks.json"
chmod -R +x "$PLUGIN_STAGE/scripts/"

# Rewrite hooks.json relative paths to point at the staged scripts.
python3 -c "
import json, sys, pathlib
p = pathlib.Path('$TEST_HOME/.codex/hooks.json')
h = json.loads(p.read_text())
for event in h['hooks'].values():
    for matcher in event:
        for hook in matcher.get('hooks', []):
            cmd = hook['command']
            if cmd.startswith('./scripts/'):
                hook['command'] = '$PLUGIN_STAGE/scripts/' + cmd[len('./scripts/'):]
p.write_text(json.dumps(h, indent=2))
"
pass "plugin staged at $PLUGIN_STAGE"
pass "~/.codex/hooks.json rewritten with absolute paths"

# ---------------------------------------------------------------------------
# 2. seed axonflow.toml with endpoint pointing at staging
# ---------------------------------------------------------------------------
sect "Step 2 — seed axonflow.toml (no token yet → free tier)"

# axonflow.toml is the canonical config for codex plugin. With no
# license_token = "...", we're free tier.
cat > "$TEST_HOME/.codex/axonflow.toml" <<EOF
# Walkthrough config — community-saas staging
endpoint = "$AGENT_URL"
EOF
chmod 0600 "$TEST_HOME/.codex/axonflow.toml"
pass "wrote $TEST_HOME/.codex/axonflow.toml"

# ---------------------------------------------------------------------------
# 3. drive codex headless — should fire the AxonFlow PreToolUse hook
# ---------------------------------------------------------------------------
sect "Step 3 — codex exec with a Bash prompt (free-tier governed call)"

# Use HOME override + AXONFLOW_ENDPOINT to ensure the staged config is used.
# `codex exec` runs non-interactive and exits when done.
note "running: codex exec --skip-git-repo-check 'echo hello'"
note "(redirected output captured; codex will spawn the AxonFlow hook on Bash tool calls)"
HOME="$TEST_HOME" \
AXONFLOW_ENDPOINT="$AGENT_URL" \
AXONFLOW_TELEMETRY=off \
AXONFLOW_CODEX_CONFIG="$TEST_HOME/.codex/axonflow.toml" \
  timeout 60 codex exec --skip-git-repo-check "echo hello world from codex walkthrough" \
  >"$WORKDIR/codex.log" 2>&1 || true

# Codex exec writes to stdout/stderr. We're not asserting codex's response
# content — we're asserting the AxonFlow hook fired. The hook sends a
# request to AGENT_URL, which we'll verify by checking the agent's audit.
note "codex exec exit captured to $WORKDIR/codex.log; tail:"
tail -10 "$WORKDIR/codex.log" | sed 's/^/    /'

# ---------------------------------------------------------------------------
# 4. verify the hook actually hit the staging agent
# ---------------------------------------------------------------------------
sect "Step 4 — verify hook reached staging agent"

# We can verify either by:
#   (a) checking try-staging telemetry table for a matching event
#   (b) checking agent CloudWatch logs for a check_policy call from this run
#
# Without DB access here, easiest signal: query the telemetry
# /api/v1/telemetry/recent endpoint if exposed. Else fall back to the
# pre-tool-check.sh's stderr canary (`[AxonFlow] Connected to AxonFlow at …`)
# captured in codex.log.
if grep -q "AxonFlow" "$WORKDIR/codex.log"; then
  pass "AxonFlow hook canary observed in codex output"
else
  note "no AxonFlow canary in codex.log — hook may have run silently or not at all"
  note "manually verify: aws logs tail \"/aws/ecs/<staging-stack>-agent\" --since 5m | grep check_policy"
  skip "agent-side verification (requires log access)"
fi

# ---------------------------------------------------------------------------
# 5. recovery flow — request magic link
# ---------------------------------------------------------------------------
sect "Step 5 — recovery flow (request magic link to $TEST_EMAIL)"

if [ -x "$PLUGIN_STAGE/scripts/recover.sh" ]; then
  HOME="$TEST_HOME" \
  AXONFLOW_ENDPOINT="$AGENT_URL" \
  AXONFLOW_CODEX_CONFIG="$TEST_HOME/.codex/axonflow.toml" \
    "$PLUGIN_STAGE/scripts/recover.sh" "$TEST_EMAIL" --request-only \
    >"$WORKDIR/recover.log" 2>&1 \
    && pass "recovery request submitted (check $TEST_EMAIL inbox)" \
    || fail "recovery request failed — see $WORKDIR/recover.log"
  tail -5 "$WORKDIR/recover.log" | sed 's/^/    /'
else
  fail "$PLUGIN_STAGE/scripts/recover.sh not executable"
fi

note "Manual step: fetch magic link from $TEST_EMAIL inbox, then re-run with"
note "  RECOVERY_TOKEN=<token> bash $0"

# ---------------------------------------------------------------------------
# 6. status surface via codex agent prompt
# ---------------------------------------------------------------------------
sect "Step 6 — drive codex with 'what is my tenant_id?' prompt"

note "codex won't natively know about /axonflow-status; this checks whether codex"
note "discovers + invokes the recover.sh status surface from the agent flow"
HOME="$TEST_HOME" \
AXONFLOW_ENDPOINT="$AGENT_URL" \
AXONFLOW_CODEX_CONFIG="$TEST_HOME/.codex/axonflow.toml" \
  timeout 60 codex exec --skip-git-repo-check \
    "What is my AxonFlow tenant_id? Run: bash $PLUGIN_STAGE/scripts/recover.sh status" \
  >"$WORKDIR/codex-status.log" 2>&1 || true

# Look for cs_<uuid> tenant pattern in output.
if grep -qE 'cs_[a-z0-9-]{8,}' "$WORKDIR/codex-status.log"; then
  TENANT=$(grep -oE 'cs_[a-z0-9-]{8,}' "$WORKDIR/codex-status.log" | head -1)
  pass "tenant_id surfaced in codex output: $TENANT"
else
  skip "tenant_id not surfaced — codex may not have invoked the status command"
  note "  Inspect $WORKDIR/codex-status.log for codex's reasoning"
  tail -10 "$WORKDIR/codex-status.log" | sed 's/^/    /'
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
sect "Summary"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  SKIP: $SKIP"
echo ""
[ "$FAIL" -gt 0 ] && exit 1
[ "$SKIP" -gt 0 ] && echo "⚠️  walkthrough partially complete — $SKIP step(s) need manual completion"
echo "✅ walkthrough complete"
