-- Migration 050: MAP execution plan_id index + expired status
-- Required for Bug C fix: direct plan_id lookup instead of O(n) scan
-- Required for Bug D fix: expired execution status

-- Index for direct MAP execution lookup by plan_id
-- Note: CONCURRENTLY removed because migration runner uses transactions.
-- For production, run this index creation separately outside a transaction.
CREATE INDEX IF NOT EXISTS idx_execution_history_plan_id
    ON execution_history ((metadata->>'plan_id'))
    WHERE metadata->>'plan_id' IS NOT NULL;

-- Add 'expired' to execution_status enum if not already present
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'expired'
                   AND enumtypid = 'execution_status'::regtype) THEN
        ALTER TYPE execution_status ADD VALUE 'expired';
    END IF;
EXCEPTION
    WHEN undefined_object THEN
        -- execution_status type may not exist if using text columns
        NULL;
END$$;
