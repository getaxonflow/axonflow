# Cursor V1 Paid-Tier Walkthrough — Manual

**Why manual:** Cursor's CLI launches the IDE; there's no reliable headless agent-mode for non-interactive driving. Buyer + recovery flows must be exercised by a human in the IDE, against the on-demand staging stack.

**Scope:** validates the user-facing flow Cursor users will experience post-V1 launch. The wire-contract is covered by the host-CLI shim CI (cursor#44 PR — merged); this walkthrough proves the IDE actually invokes the plugin's surfaces when a real user asks.

---

## Prerequisites

1. On-demand staging stack provisioned + reachable at `https://try-staging.getaxonflow.com` (`/health` returns 200)
2. Stripe Test Mode webhook endpoint configured at `https://try-staging.getaxonflow.com/api/v1/billing/stripe-webhook` with signing secret in `axonflow/community-saas-staging/stripe-webhook-signing-secret`
3. Stripe Test Mode Payment Link with `tenant_id` custom field
4. Resend API key in `axonflow/community-saas-staging/resend-api-key` (or shared from prod)
5. v7.7.0 image deployed to staging
6. Cursor IDE installed
7. Local checkout of `axonflow-cursor-plugin` at `/Users/saurabhjain/Development/axonflow-cursor-plugin`

---

## Setup (one-time per drill)

In Cursor, install the local plugin:

1. Open Cursor → Settings → Cursor Plugins → Install local plugin → select `/Users/saurabhjain/Development/axonflow-cursor-plugin`
2. Restart Cursor
3. Set the staging endpoint via shell env that Cursor inherits (or via a workspace `.env`):
   ```
   export AXONFLOW_ENDPOINT=https://try-staging.getaxonflow.com
   ```
4. Open a new chat in Cursor — verify the plugin's hook canary fires by asking Cursor to run a Bash command. The plugin's `pre-tool-check.sh` will write `[AxonFlow] Connected to AxonFlow at https://try-staging.getaxonflow.com (mode=self-hosted)` to stderr.

---

## Walkthrough A — Status surface

**Goal:** prove the user can find their `tenant_id` from inside Cursor.

1. In Cursor agent chat, type: **"What is my AxonFlow tenant_id?"**
2. Capture: did Cursor invoke the `axonflow-status` skill (or run `scripts/status.sh`)?
3. Capture: does the output include a `cs_<uuid>` tenant_id?

**Pass criteria:**
- ✅ Cursor invoked the status surface (visible as a tool call in chat)
- ✅ A `cs_<uuid>` tenant_id appears in chat
- ✅ License token is shown as `unset` or `AXON-...XXXX` (last-4 redacted) — never the full token

**Likely failure modes:**
- Cursor doesn't autonomously invoke the skill from a natural-language prompt → manual fallback: ask Cursor to run `bash scripts/status.sh` directly
- Hook script returns "(not registered)" → first call hasn't bootstrapped a tenant yet; trigger any governed Bash tool call first

---

## Walkthrough B — Recovery flow

**Goal:** prove a user who lost credentials can recover via the IDE.

1. Manually delete `~/.config/axonflow/try-registration.json`
2. In Cursor chat: **"I lost my AxonFlow credentials, please help me recover. My email is dev@getaxonflow.com"**
3. Capture: did Cursor invoke `scripts/recover-credentials.sh dev@getaxonflow.com`?
4. Capture: does the output mention "magic link sent"?
5. Check the `dev@getaxonflow.com` inbox (or Resend dashboard "Sent" log) for the magic-link email
6. In Cursor chat: **"Verify recovery with this token: <token from email>"**
7. Capture: does the recovery script complete and persist a fresh `try-registration.json`?

**Pass criteria:**
- ✅ Cursor invokes `recover-credentials.sh --request` step
- ✅ Email lands at `dev@getaxonflow.com`
- ✅ Cursor invokes `recover-credentials.sh --verify` step with the token
- ✅ `try-registration.json` is rewritten with mode 0600
- ✅ Next governed call authenticates as the recovered tenant

---

## Walkthrough C — Buyer flow

**Goal:** prove the full Stripe Test Mode → email → token-paste → Pro tier flow works through Cursor.

1. From walkthrough A, capture the `tenant_id`
2. Open the Stripe Test Mode Payment Link in your browser
3. Paste the `tenant_id` into the custom field
4. Pay with Stripe test card `4242 4242 4242 4242`, any future expiry, any CVV
5. Wait ~10s — webhook should fire
6. Check `dev@getaxonflow.com` inbox for the AXON-… token email (or Resend dashboard if domain DKIM isn't set up)
7. Configure Cursor with the token. Two options:
   - **Env**: `export AXONFLOW_LICENSE_TOKEN=AXON-…` then restart Cursor
   - **File**: `printf '%s' AXON-… > ~/.config/axonflow/license-token && chmod 0600 ~/.config/axonflow/license-token`
8. In Cursor chat: **"What's my AxonFlow tier now?"**
9. Capture: does status output show `tier: Pro` and `license: AXON-...XXXX (redacted)`?
10. Trigger a governed Bash call, observe agent CloudWatch logs (in CFN stack `axonflow-community-saas-staging-*`) — the request should carry `X-License-Token` and the response should reflect Pro context

**Pass criteria:**
- ✅ Stripe webhook fires (visible in Stripe Dashboard delivery log, 200 OK)
- ✅ AXON-… token arrives at `dev@getaxonflow.com`
- ✅ Cursor with token configured shows `tier: Pro` in status
- ✅ Agent staging logs show `X-License-Token` reaching the wire
- ✅ Agent response context includes Pro entitlements

---

## What to capture for the testing log

Paste into `axonflow-internal-docs/engineering/V1_LAUNCH_STAGING_WALKTHROUGH_LOG.md` (create if missing):

- Date + walkthrough version
- Plugin checkout SHA
- v7.7.0 ECR short-SHA
- `try-staging.getaxonflow.com` /health output
- Per-walkthrough: PASS/FAIL on each criterion above
- Any prompt phrasing that worked / didn't (so future drills can reuse)
- Any unexpected behavior (worth filing as a follow-up issue)

---

## Cleanup

After the drill:

```bash
# Clear staging credentials from your local config
rm -f ~/.config/axonflow/try-registration.json
rm -f ~/.config/axonflow/license-token

# (Optional) tear down the staging stack to stop billing
gh workflow run destroy-stack.yml -f environment=community-saas-staging -f confirm_destroy=DESTROY
```
