-- Migration 161 DOWN: no-op, deliberately
-- Pairs with: 161_null_fabricated_zero_response_times.sql
--
-- The UP migration replaced a fabricated value with the absence of one. There
-- is no faithful inverse: the rows it touched are indistinguishable, after the
-- fact, from the rows that were ALREADY NULL because their writer correctly
-- recorded nothing (the decide plane before #3424 threaded its measurement,
-- the MCP static-block and redaction writers, and every /audit/export row a
-- pre-#3424 reader emitted). `UPDATE ... SET response_time_ms = 0 WHERE
-- response_time_ms IS NULL` would therefore not restore the prior state; it
-- would fabricate zeros on a far larger set of rows than the UP migration
-- cleared, and re-introduce the defect on rows that never had it.
--
-- Rolling back the CODE is safe without rolling back this data. The pre-#3424
-- reader predicate is `response_time_ms IS NOT NULL AND response_time_ms > 0`,
-- which excludes 0 and NULL identically, so an old reader running against a
-- migrated table computes exactly the same aggregate it would have computed
-- before. Nothing downstream distinguishes the two values.
--
-- This file exists so the up/down pairing check stays satisfied and so the
-- reasoning above is recorded next to the migration rather than in a PR.

BEGIN;

DO $$
BEGIN
    RAISE NOTICE 'Migration 161 DOWN: intentional no-op (a fabricated 0 is not recoverable from NULL, and the pre-#3424 reader excludes both identically)';
END $$;

COMMIT;
