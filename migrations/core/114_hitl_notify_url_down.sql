-- Down migration 114: drop HITL notify_url column.

ALTER TABLE hitl_approval_queue
    DROP COLUMN IF EXISTS notify_url;
