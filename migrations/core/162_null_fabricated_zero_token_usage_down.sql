-- Migration 162 DOWN: no-op, deliberately
-- Pairs with: 162_null_fabricated_zero_token_usage.sql
--
-- Same reasoning as 161's down migration. The UP migration replaced a
-- fabricated value with the absence of one, and after the fact the rows it
-- touched are indistinguishable from the rows that were already NULL because
-- their writer correctly recorded nothing (every agent-plane row -- decide,
-- gateway pre-check, MCP -- has always written NULL here, because those writers
-- do not go through the orchestrator BatchWriter at all). `UPDATE ... SET
-- tokens_used = 0 WHERE tokens_used IS NULL` would not restore the prior state;
-- it would fabricate zeros across a far larger set of rows than the UP
-- migration cleared.
--
-- Rolling the CODE back is safe without rolling this data back. A pre-#3427
-- reader scans these columns into sql.Null* and takes .Int64 / .Float64
-- unconditionally, so it renders a NULL exactly as it rendered the 0 this
-- migration removed: as 0. The old behaviour is unchanged by the data change.
--
-- This file exists so the up/down pairing check stays satisfied and so the
-- reasoning is recorded next to the migration rather than in a PR.

BEGIN;

DO $$
BEGIN
    RAISE NOTICE 'Migration 162 DOWN: intentional no-op (a fabricated 0 is not recoverable from NULL, and a pre-#3427 reader renders both as 0)';
END $$;

COMMIT;
