-- Migration 181: typed_policy_audit, the audit row for every typed-policy publish, promote and rollback
-- Date: 2026-09-12
-- Purpose: Record one append-only row for every publication, promotion and
--          rollback of an organization's typed policy, written in the SAME
--          TRANSACTION as the artifact insert or the activation append it
--          records, so that a write whose audit row cannot be recorded does
--          not happen, on any transport.
-- Related: PRD v11 §1.12 and #4023 (self-approval "records the reason and the
--          fact on the audit row"), #3746 (W3-I items 7 and 8),
--          migrations/core/176 (the tables it audits),
--          migrations/core/178 (organization root only).
--
-- EDITION: COMMUNITY (mirrored). It audits core/176's tables, which ship on
-- every edition, and a Community publish is audited like any other. PRD §1.12
-- records self_approved wherever the approvers equal the author, and a
-- Community sole administrator publishes that way today.
--
-- ---------------------------------------------------------------------------
-- WHY A TABLE OF ITS OWN
-- ---------------------------------------------------------------------------
--
-- Measured before this file (W3-I census, 2026-09-12): no transport wrote an
-- audit row for a publish, a promote or a rollback. The portal logged a line;
-- the orchestrator wrote the activation ledger and nothing else. What existed:
--
--   * the artifact, whose signed provenance names the author and the
--     approvers, readable as a fact only after the artifact is re-verified;
--   * typed_policy_activations, which records promote and rollback, never
--     publish, and nothing about how a version was approved.
--
-- Neither records that a publish was self-approved, which §1.12 requires. The
-- existing audit tables do not fit: admin_audit_log is enterprise-only and
-- written best-effort, config_audit_log keys on a UUID and CHECKs a vocabulary
-- these actions are not in, and audit_logs is the decision audit.
--
-- ---------------------------------------------------------------------------
-- THE KEY IS THE EVENT
-- ---------------------------------------------------------------------------
--
-- A publish happens once per artifact digest, the key of
-- typed_policy_artifacts, so its row carries activation_seq 0. An activation
-- happens once per sequence number of typed_policy_activations, so its row
-- carries that number: one digest can be rolled back to more than once, and
-- each time is its own event. The primary key therefore names the event, a
-- second row for one event is refused rather than left for a reader to
-- deduplicate, and no sequence object needs a grant.
--
-- There is no foreign key to the audited tables. Each migration's down file
-- stays independent of the other's, and the same-transaction write is what
-- ties a row to its artifact or activation.
--
-- approvers is JSONB rather than TEXT[] because the Go writer passes it as text
-- without importing a driver's array type: platform/policy/authoringstore
-- deliberately compiles against lib/pq and pgx alike.

BEGIN;

CREATE TABLE IF NOT EXISTS typed_policy_audit (
    org_id           VARCHAR(255) NOT NULL,
    root             VARCHAR(32)  NOT NULL,
    action           VARCHAR(16)  NOT NULL,
    digest           VARCHAR(128) NOT NULL,
    activation_seq   INTEGER      NOT NULL DEFAULT 0,
    previous_digest  VARCHAR(128) NOT NULL DEFAULT '',
    document_id      VARCHAR(255) NOT NULL,
    document_version INTEGER      NOT NULL,
    actor            VARCHAR(512) NOT NULL,
    approvers        JSONB        NOT NULL DEFAULT '[]'::jsonb,
    self_approved    BOOLEAN      NOT NULL DEFAULT false,
    reason           TEXT         NOT NULL DEFAULT '',
    occurred_at      TIMESTAMPTZ  NOT NULL,
    recorded_at      TIMESTAMPTZ  NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, root, action, digest, activation_seq),
    CONSTRAINT typed_policy_audit_org_nonempty_chk   CHECK (org_id <> ''),
    CONSTRAINT typed_policy_audit_root_chk           CHECK (root = 'organization'),
    CONSTRAINT typed_policy_audit_action_chk         CHECK (action IN ('publish', 'promote', 'rollback')),
    CONSTRAINT typed_policy_audit_digest_form_chk    CHECK (digest LIKE 'sha256:%'),
    CONSTRAINT typed_policy_audit_prev_form_chk      CHECK (previous_digest = '' OR previous_digest LIKE 'sha256:%'),
    CONSTRAINT typed_policy_audit_version_chk        CHECK (document_version >= 1),
    CONSTRAINT typed_policy_audit_actor_nonempty_chk CHECK (actor <> ''),
    CONSTRAINT typed_policy_audit_approvers_form_chk CHECK (jsonb_typeof(approvers) = 'array'),
    -- A publish is not an activation: it has no sequence number and no
    -- previous digest. An activation always has a sequence number.
    CONSTRAINT typed_policy_audit_event_shape_chk
        CHECK ((action = 'publish' AND activation_seq = 0 AND previous_digest = '')
            OR (action <> 'publish' AND activation_seq >= 1)),
    -- Approvers and self-approval are facts about a PUBLICATION. An
    -- activation row carrying them would be claiming an approval that
    -- happened somewhere else.
    CONSTRAINT typed_policy_audit_approval_on_publish_chk
        CHECK (action = 'publish' OR (jsonb_array_length(approvers) = 0 AND NOT self_approved)),
    -- Self-approval is "the approvers are the author", so it needs one.
    CONSTRAINT typed_policy_audit_self_approval_chk
        CHECK (NOT self_approved OR jsonb_array_length(approvers) >= 1),
    CONSTRAINT typed_policy_audit_rollback_reason_chk
        CHECK (action <> 'rollback' OR reason <> '')
);

CREATE INDEX IF NOT EXISTS idx_typed_policy_audit_trail
    ON typed_policy_audit (org_id, root, recorded_at);

COMMENT ON TABLE typed_policy_audit IS
    'Typed-policy audit row (PRD v11 §1.12): one per publish, promote and rollback, written in the same transaction as the write it records. Append-only.';

-- ---------------------------------------------------------------------------
-- Row-level security, the same shape as core/176's tables
-- ---------------------------------------------------------------------------

ALTER TABLE typed_policy_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE typed_policy_audit FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS typed_policy_audit_org_isolation ON typed_policy_audit;
CREATE POLICY typed_policy_audit_org_isolation ON typed_policy_audit
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

-- ---------------------------------------------------------------------------
-- Append-only triggers
--
-- ITS OWN FUNCTION, NOT core/176's typed_policy_append_only(). 176's down file
-- drops that function, and a trigger here depending on it would make 176's
-- down fail on every deployment that has applied this file.
--
-- The privilege revoke below does not bind the table OWNER; the trigger does,
-- which is why both exist.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION typed_policy_audit_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Table % is append-only: % is refused. An audit row is a record, not a mutable row (PRD v11 §1.12).',
        TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS typed_policy_audit_no_update_delete ON typed_policy_audit;
CREATE TRIGGER typed_policy_audit_no_update_delete
    BEFORE UPDATE OR DELETE ON typed_policy_audit
    FOR EACH ROW EXECUTE FUNCTION typed_policy_audit_append_only();

DROP TRIGGER IF EXISTS typed_policy_audit_no_truncate ON typed_policy_audit;
CREATE TRIGGER typed_policy_audit_no_truncate
    BEFORE TRUNCATE ON typed_policy_audit
    FOR EACH STATEMENT EXECUTE FUNCTION typed_policy_audit_append_only();

-- ---------------------------------------------------------------------------
-- Grants: read and append, nothing else, for both application roles
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON typed_policy_audit FROM axonflow_app_role;
        GRANT SELECT, INSERT ON typed_policy_audit TO axonflow_app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON typed_policy_audit FROM axonflow_platform_admin;
        GRANT SELECT, INSERT ON typed_policy_audit TO axonflow_platform_admin;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Self-verification BEFORE COMMIT, the pattern of core/176
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    r   TEXT;
    n   INTEGER;
    def TEXT;
BEGIN
    IF to_regclass('typed_policy_audit') IS NULL THEN
        RAISE EXCEPTION 'migration 181 self-verification: typed_policy_audit was not created';
    END IF;

    SELECT COUNT(*) INTO n
    FROM pg_catalog.pg_class c
    WHERE c.oid = to_regclass('typed_policy_audit') AND c.relrowsecurity AND c.relforcerowsecurity;
    IF n <> 1 THEN
        RAISE EXCEPTION 'migration 181 self-verification: typed_policy_audit does not have ENABLE + FORCE ROW LEVEL SECURITY';
    END IF;

    SELECT COUNT(*) INTO n FROM pg_catalog.pg_policies
    WHERE schemaname = 'public' AND tablename = 'typed_policy_audit'
      AND policyname = 'typed_policy_audit_org_isolation';
    IF n <> 1 THEN
        RAISE EXCEPTION 'migration 181 self-verification: typed_policy_audit is missing its org-isolation policy';
    END IF;

    SELECT COUNT(*) INTO n FROM pg_catalog.pg_trigger
    WHERE tgrelid = to_regclass('typed_policy_audit') AND NOT tgisinternal;
    IF n <> 2 THEN
        RAISE EXCEPTION 'migration 181 self-verification: typed_policy_audit carries % append-only triggers, expected 2', n;
    END IF;

    SELECT pg_get_constraintdef(oid) INTO def FROM pg_catalog.pg_constraint
    WHERE conname = 'typed_policy_audit_root_chk';
    IF def IS NULL OR def LIKE '%system%' OR def NOT LIKE '%organization%' THEN
        RAISE EXCEPTION 'migration 181 self-verification: typed_policy_audit_root_chk is %, not organization-only', COALESCE(def, 'absent');
    END IF;

    FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
        CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
        IF has_table_privilege(r, 'typed_policy_audit', 'UPDATE')
           OR has_table_privilege(r, 'typed_policy_audit', 'DELETE')
           OR has_table_privilege(r, 'typed_policy_audit', 'TRUNCATE') THEN
            RAISE EXCEPTION 'migration 181 self-verification: % can UPDATE, DELETE or TRUNCATE typed_policy_audit', r;
        END IF;
        IF NOT has_table_privilege(r, 'typed_policy_audit', 'SELECT')
           OR NOT has_table_privilege(r, 'typed_policy_audit', 'INSERT') THEN
            RAISE EXCEPTION 'migration 181 self-verification: % lacks SELECT/INSERT on typed_policy_audit', r;
        END IF;
        IF has_column_privilege(r, 'typed_policy_audit', 'org_id', 'UPDATE') THEN
            RAISE EXCEPTION 'migration 181 self-verification: % holds a column UPDATE on typed_policy_audit', r;
        END IF;
    END LOOP;

    RAISE NOTICE 'Migration 181 verified: typed_policy_audit is org-isolated, FORCE-RLS, organization-root only and append-only.';
END $$;

COMMIT;
