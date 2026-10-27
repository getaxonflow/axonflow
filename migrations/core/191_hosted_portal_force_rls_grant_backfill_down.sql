-- Migration 191 down is deliberately a no-op.
--
-- GRANT is not reference-counted. Revoking here could remove privileges that
-- core/098 or community-saas/190 established independently and would break a
-- healthy deployment. Operators who need to remove these privileges must do so
-- as an explicit access-policy change after verifying no Portal task uses them.

BEGIN;

DO $$
BEGIN
    RAISE NOTICE 'Migration 191 down: no-op; access grants are not revoked automatically';
END
$$;

COMMIT;
