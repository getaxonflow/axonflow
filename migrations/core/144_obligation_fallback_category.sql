-- Migration 144: allow the 'obligation_fallback' detection-posture category
-- Date: 2026-07-17
-- Issue: #2958 (seam-capability-aware obligations — PDP-decided fallback posture)
--
-- WHY ----------------------------------------------------------------------
-- /api/v1/decide emits a request-phase redact_pii OBLIGATION on an allow
-- verdict, and the PEP discharges it by calling the engine. A HEADERS-ONLY seam
-- (Envoy ext_authz) cannot rewrite a body, so it cannot discharge that
-- obligation at all — and until #2958 the adapter resolved that locally by
-- turning the PDP's `allow` into a client-facing 403. That is a policy decision
-- made in the PEP, which ADR-056 forbids (the adapter's charter is ZERO policy
-- logic), and at a design partner it took LLM-plane chat down.
--
-- #2958 moves the decision back to the PDP: the caller advertises what its seam
-- can fulfill, and the PDP applies the ORG's obligation-fallback posture to any
-- obligation it therefore withholds — `log` (default: allow, emit no
-- obligation, record the suppressed redaction + detected categories on the
-- canonical audit row) or `block` (deny with a clear reason).
--
-- WHY A NEW CATEGORY RATHER THAN REUSING 'pii' -----------------------------
-- The posture could NOT ride the existing `pii` category. `pii=block` makes
-- every PII match block outright — ModeDetectionConfig.BuildActionOverrides
-- fans the lever onto every PII category, and convertSharedResultToStatic only
-- sets RequiresRedaction when the result is NOT blocked — so a redact
-- obligation can never coexist with `pii=block`. Reading `pii` here would have
-- produced a lever whose `block` branch is unreachable by construction: a
-- config knob that silently does nothing. This category is the smallest thing
-- that makes the posture real.
--
-- SCOPE: relaxes ONE CHECK constraint on detection_action_overrides (mig 120)
-- to admit the new category value. No new table, no new column, no data
-- rewrite, no lock beyond the brief ACCESS EXCLUSIVE of the constraint swap on
-- a small config table. A deployment that never writes an obligation_fallback
-- row behaves byte-identically to before (the resolver's default is `log`,
-- which reproduces #2958's intended behavior with no row present).
--
-- ACTION VALUES: the column-level action CHECK (block|redact|warn|log) is
-- UNCHANGED and deliberately not narrowed per-category — a per-category action
-- constraint would need a CASE expression that every future category has to
-- edit. Only block|log are meaningful for obligation_fallback; the portal write
-- path (ee/platform/customer-portal/posture) rejects redact|warn for it, and
-- the agent resolver treats any other stored value as the documented default
-- `log` with a rate-limited WARN (fail toward the default, never toward denying
-- live traffic on a config typo).

BEGIN;

-- DROP + re-ADD (rather than ALTER) because Postgres has no "alter constraint
-- predicate". IF EXISTS so a re-run against an already-migrated database is a
-- no-op rather than an error.
ALTER TABLE detection_action_overrides
    DROP CONSTRAINT IF EXISTS detection_action_overrides_category_chk;

ALTER TABLE detection_action_overrides
    ADD CONSTRAINT detection_action_overrides_category_chk
    CHECK (category IN ('pii', 'sqli', 'dangerous_query', 'dangerous_command',
                        'obligation_fallback'));

-- Keep the column comment truthful — it enumerates the legal categories
-- (mig 120 wrote the original four).
COMMENT ON COLUMN detection_action_overrides.category IS
    'Detection posture category: pii | sqli | dangerous_query | dangerous_command | obligation_fallback. obligation_fallback (#2958) is not a detector — it is what to do when a policy decided to redact a request body but the calling PEP''s seam cannot fulfill that (block | log; default log when absent).';

-- Verification — fail loudly if the constraint did not land (Principle 3).
--
-- Asserted by reading the constraint's actual predicate rather than by probing
-- with a real INSERT: detection_action_overrides is ENABLE + FORCE ROW LEVEL
-- SECURITY (mig 120), so an INSERT with no app.current_org_id GUC set would be
-- rejected by the RLS WITH CHECK — not by the CHECK constraint — under any
-- non-superuser migration role (e.g. axonflow_platform_admin when
-- AXONFLOW_DB_USE_APP_ROLE is on). That failure mode would be indistinguishable
-- from the one we are testing for. pg_get_constraintdef reads the predicate the
-- planner will actually enforce, with no row written and no RLS interaction.
DO $$
DECLARE
    def TEXT;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def
    FROM pg_constraint
    WHERE conname = 'detection_action_overrides_category_chk'
      AND conrelid = 'detection_action_overrides'::regclass;

    IF def IS NULL THEN
        RAISE EXCEPTION 'Migration 144 failed: detection_action_overrides_category_chk not present';
    END IF;
    IF def NOT LIKE '%obligation_fallback%' THEN
        RAISE EXCEPTION 'Migration 144 failed: category CHECK does not admit obligation_fallback (definition: %)', def;
    END IF;
    -- The pre-existing four must survive the swap — a typo that dropped one
    -- would silently break every org already holding that posture.
    IF def NOT LIKE '%pii%' OR def NOT LIKE '%sqli%'
       OR def NOT LIKE '%dangerous_query%' OR def NOT LIKE '%dangerous_command%' THEN
        RAISE EXCEPTION 'Migration 144 failed: category CHECK lost a pre-existing category (definition: %)', def;
    END IF;
    RAISE NOTICE 'Migration 144 verified: category CHECK admits obligation_fallback and retains the original four';
END
$$;

COMMIT;
