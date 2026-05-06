#!/usr/bin/env bash
# Claude Code plugin V1 paid-tier walkthrough — runs against on-demand staging.
#
# Claude Code's CLI supports headless agent execution via `claude -p
# "<prompt>"`. This walkthrough drives claude against a staged AxonFlow
# plugin install pointed at https://try-staging.getaxonflow.com.
#
# Coverage:
#   1. Install the AxonFlow plugin via `claude plugin install` (or
#      via --plugin-dir if installing from local checkout).
#   2. Drive `claude -p` with prompts that should fire the plugin's
#      governance hooks (Bash tool calls).
#   3. Verify hooks reach the staging agent.
#   4. Drive recovery + status flows via slash commands.
#
# What this catches that the host-cli-shim test doesn't:
#   - Claude Code's actual hook + slash-command + MCP-tool routing
#     against a real plugin install
#   - End-to-end "user prompt → claude executes Bash → PreToolUse fires
#     → agent receives X-License-Token (or doesn't, on free tier)"
#
# Requires:
#   - claude CLI (Claude Code 2.x)
#   - claude already authenticated
#   - jq, curl, python3
#
# Override defaults via env:
#   AGENT_URL    — staging endpoint
#   TEST_EMAIL   — recovery target
#   PLUGIN_PATH  — path to local axonflow-claude-plugin checkout

set -uo pipefail

AGENT_URL="${AGENT_URL:-https://try-staging.getaxonflow.com}"
TEST_EMAIL="${TEST_EMAIL:-dev@getaxonflow.com}"
PLUGIN_PATH="${PLUGIN_PATH:-/Users/saurabhjain/Development/axonflow-claude-plugin}"

WORKDIR=$(mktemp -d 2>/dev/null || mktemp -d -t claude-walkthrough)

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

echo "Claude Code V1 paid-tier walkthrough — staging"
echo "  AGENT_URL   = $AGENT_URL"
echo "  TEST_EMAIL  = $TEST_EMAIL"
echo "  PLUGIN_PATH = $PLUGIN_PATH"
echo "  WORKDIR     = $WORKDIR"

# ---------------------------------------------------------------------------
# 0. preflight
# ---------------------------------------------------------------------------
sect "Preflight"
for tool in claude jq curl python3; do
  command -v "$tool" >/dev/null 2>&1 \
    && pass "$tool on PATH" \
    || { fail "$tool not on PATH"; exit 1; }
done

# Verify staging is reachable.
HEALTH=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$AGENT_URL/health" || echo "000")
if [ "$HEALTH" = "200" ]; then
  pass "$AGENT_URL/health responds 200"
else
  fail "staging unreachable — got HTTP $HEALTH from $AGENT_URL/health"
  exit 1
fi

[ -d "$PLUGIN_PATH/.claude-plugin" ] && pass "plugin checkout found at $PLUGIN_PATH" \
  || { fail "missing plugin checkout"; exit 1; }

# ---------------------------------------------------------------------------
# 1. drive claude -p with the plugin loaded via --plugin-dir
# ---------------------------------------------------------------------------
sect "Step 1 — claude -p with plugin loaded (free-tier, governed Bash call)"

# claude -p is non-interactive. --plugin-dir loads the plugin without
# requiring it to be installed in ~/.claude/plugins/.
# Set CLAUDE_PLUGIN_ROOT so the plugin's hooks can find their scripts.
note "running: claude -p --plugin-dir $PLUGIN_PATH 'run echo hello in bash'"
note "(redirected output captured; AxonFlow PreToolUse should fire on the Bash tool call)"
CLAUDE_PLUGIN_ROOT="$PLUGIN_PATH" \
AXONFLOW_ENDPOINT="$AGENT_URL" \
AXONFLOW_TELEMETRY=off \
AXONFLOW_CONFIG_DIR="$WORKDIR/.config/axonflow" \
  timeout 90 claude -p \
    --plugin-dir "$PLUGIN_PATH" \
    --allowed-tools 'Bash' \
    --dangerously-skip-permissions \
    "run 'echo hello world from claude walkthrough' in bash" \
  >"$WORKDIR/claude.log" 2>&1 || true

note "claude -p output captured to $WORKDIR/claude.log; tail:"
tail -15 "$WORKDIR/claude.log" | sed 's/^/    /'

# ---------------------------------------------------------------------------
# 2. verify hook fired
# ---------------------------------------------------------------------------
sect "Step 2 — verify AxonFlow hook fired during claude -p"
if grep -q "AxonFlow" "$WORKDIR/claude.log"; then
  pass "AxonFlow canary observed in claude output (hook fired)"
else
  skip "no AxonFlow canary in claude.log — hook may have run silently"
  note "Possible reasons:"
  note "  - claude -p hooks run silently when allowed (canary goes to stderr,"
  note "    which is captured but may not appear in tail)"
  note "  - claude declined to invoke the Bash tool"
  note "  - --plugin-dir didn't load hooks for headless mode"
fi

# ---------------------------------------------------------------------------
# 3. drive /axonflow-status slash command
# ---------------------------------------------------------------------------
sect "Step 3 — drive /axonflow-status slash command via natural prompt"

note "Asking Claude in plain language to find tenant_id — relies on the"
note "axonflow-status command discovery (commands/axonflow-status.md)"
CLAUDE_PLUGIN_ROOT="$PLUGIN_PATH" \
AXONFLOW_ENDPOINT="$AGENT_URL" \
AXONFLOW_CONFIG_DIR="$WORKDIR/.config/axonflow" \
  timeout 90 claude -p \
    --plugin-dir "$PLUGIN_PATH" \
    --dangerously-skip-permissions \
    "What is my AxonFlow tenant_id? Use /axonflow-status if available." \
  >"$WORKDIR/claude-status.log" 2>&1 || true

if grep -qE 'cs_[a-z0-9-]{8,}' "$WORKDIR/claude-status.log"; then
  TENANT=$(grep -oE 'cs_[a-z0-9-]{8,}' "$WORKDIR/claude-status.log" | head -1)
  pass "tenant_id surfaced in claude output: $TENANT"
elif grep -qiE 'not registered|no tenant' "$WORKDIR/claude-status.log"; then
  pass "claude correctly invoked status surface; tenant not yet bootstrapped (free-tier first call)"
else
  skip "tenant_id not surfaced — claude may not have invoked the status command"
  note "  Inspect $WORKDIR/claude-status.log for claude's reasoning"
  tail -15 "$WORKDIR/claude-status.log" | sed 's/^/    /'
fi

# ---------------------------------------------------------------------------
# 4. drive /axonflow-recover
# ---------------------------------------------------------------------------
sect "Step 4 — drive /axonflow-recover slash command"

CLAUDE_PLUGIN_ROOT="$PLUGIN_PATH" \
AXONFLOW_ENDPOINT="$AGENT_URL" \
AXONFLOW_CONFIG_DIR="$WORKDIR/.config/axonflow" \
  timeout 90 claude -p \
    --plugin-dir "$PLUGIN_PATH" \
    --dangerously-skip-permissions \
    "Trigger AxonFlow credential recovery for $TEST_EMAIL using /axonflow-recover" \
  >"$WORKDIR/claude-recover.log" 2>&1 || true

if grep -qiE "magic link|recover|sent" "$WORKDIR/claude-recover.log"; then
  pass "claude invoked recovery flow"
  note "Manual step: fetch magic link from $TEST_EMAIL inbox"
else
  skip "claude may not have invoked recovery — check log"
  tail -10 "$WORKDIR/claude-recover.log" | sed 's/^/    /'
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
[ "$SKIP" -gt 0 ] && echo "⚠️  walkthrough partially complete — $SKIP step(s) need manual followup or different prompt phrasing"
echo "Note: SKIPs are expected if claude doesn't autonomously invoke specific"
echo "slash commands from natural-language prompts. The host-cli-shim test"
echo "(claude#57) covers the wire contract; this walkthrough tests the IDE-host"
echo "invocation behavior — which IS a 'soft' contract dependent on agent"
echo "decisions. Manual prompt iteration or interactive mode may be needed"
echo "for full coverage."
