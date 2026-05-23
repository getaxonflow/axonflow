-- Migration 114: HITL outbound webhook callback URL
--
-- Adds optional notify_url column on hitl_approval_queue. When set on row
-- creation, the platform fires a signed HTTP POST to this URL after the row
-- reaches a terminal state (approved/rejected/expired/overridden) so a
-- workflow that paused on a webhook (n8n Wait-node "On Webhook Call",
-- ADK plugin polling-free resume) can resume without a polling sidecar.
--
-- Validation, scheme allowlist (https/http), envelope shape, signing key
-- selection, retry semantics, and async dispatch live in
-- platform/agent/hitl/webhook.go. This migration only stores the URL.
--
-- RLS posture: hitl_approval_queue is already ENABLE+FORCE RLS (mig 025 +
-- the v9 Phase 8 work). notify_url is a column add — no policy change.

ALTER TABLE hitl_approval_queue
    ADD COLUMN IF NOT EXISTS notify_url TEXT NULL;

COMMENT ON COLUMN hitl_approval_queue.notify_url IS
    'Optional outbound webhook URL fired async on terminal state transition';
