-- Migration 187 (down): nothing to undo. 187 changes no schema; its
-- schema_migrations row is the cut-over instant the orchestrator's step-mode
-- first-step backfill reads, and removing it only stops that pass (it does
-- nothing when 187 is not applied). Rows the pass wrote stay: each records a
-- first step that ran.

SELECT 1;
