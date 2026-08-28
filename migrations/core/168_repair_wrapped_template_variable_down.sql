-- Migration 168 Down: deliberately a no-op.
--
-- The up migration is a DATA REPAIR: it rewrites a defective builtin template
-- value into the form the evaluator can actually match. Re-wrapping the value
-- on rollback would re-break the template - restoring a defect is not a
-- rollback, it is vandalism with a version number. A deployment that must
-- return to the pre-168 schema state loses nothing by keeping the repaired
-- value: the repaired form is exactly what core/024 now seeds on a fresh
-- install.
DO $$
BEGIN
    RAISE NOTICE 'Migration 168 down: no-op by design; the data repair is not reverted (re-breaking a template is not a rollback).';
END
$$;
