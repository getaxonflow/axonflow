-- Migration 188 (down): triggered_policy_id back to VARCHAR(100) and
-- triggered_policy_name back to VARCHAR(255) (core/025).
--
-- REFUSES, naming the count, when a row holds a longer value: narrowing would
-- fail on it anyway, and truncating would rewrite what a reviewer approved into
-- a policy set nobody asked for. Such a row is an approval requested by several
-- merged policies (188's header); after the down the agent can no longer queue
-- one, and decide refuses the call approval_required again, as before 188.
-- hitl_pending_summary is recreated with core/025's definition.

BEGIN;

DO $$
DECLARE
    had_summary BOOLEAN;
    too_long BIGINT;
BEGIN
    IF to_regclass('public.hitl_approval_queue') IS NOT NULL THEN
        SELECT count(*) INTO too_long FROM hitl_approval_queue
         WHERE length(triggered_policy_id) > 100 OR length(triggered_policy_name) > 255;
        IF too_long > 0 THEN
            RAISE EXCEPTION 'Migration 188 down refused: % hitl_approval_queue row(s) name a policy set longer than VARCHAR(100)/VARCHAR(255); narrowing would fail on them, and truncating would change what was approved', too_long;
        END IF;

        had_summary := to_regclass('public.hitl_pending_summary') IS NOT NULL;
        DROP VIEW IF EXISTS hitl_pending_summary;

        ALTER TABLE hitl_approval_queue
            ALTER COLUMN triggered_policy_id TYPE VARCHAR(100),
            ALTER COLUMN triggered_policy_name TYPE VARCHAR(255);

        COMMENT ON COLUMN hitl_approval_queue.triggered_policy_id IS NULL;

        IF had_summary THEN
            -- core/025's definition, unchanged.
            CREATE OR REPLACE VIEW hitl_pending_summary AS
            SELECT
                org_id,
                tenant_id,
                triggered_policy_name,
                severity,
                COUNT(*) as pending_count,
                MIN(created_at) as oldest_request,
                MAX(expires_at) as next_expiry
            FROM hitl_approval_queue
            WHERE status = 'pending'
            GROUP BY org_id, tenant_id, triggered_policy_name, severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END,
                oldest_request ASC;
        END IF;
    END IF;
END $$;

COMMIT;
