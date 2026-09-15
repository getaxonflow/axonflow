-- Migration 176: Typed authoring persistence in CORE — artifacts, activations, signing keys
-- Date: 2026-09-10
-- Purpose: Give ADR-065 typed authoring durable storage on EVERY deployment
--          mode, so a published policy version, its activation record and the
--          key that signs it outlive the process that produced them.
-- Related: #3975 (Community loses everything on restart), #3776 (the tables,
--          first shipped as migrations/enterprise/155), #3786, ADR-065
--          "Policy lifecycle", #3605 (KMS custody chain — owns the PRIVATE key).
--
-- EDITION: COMMUNITY (mirrored). This is a CATEGORY MOVE of
-- migrations/enterprise/155, not a new schema.
--
-- ---------------------------------------------------------------------------
-- WHY THIS FILE EXISTS, WHICH IS NOT "COMMUNITY DESERVES A FEATURE"
-- ---------------------------------------------------------------------------
--
-- #3975, measured on a booted Community stack: the typed-authoring write route
-- #3943 added to the ORCHESTRATOR publishes and activates successfully, and
-- `GET /api/v1/typed-policies/active` returns 404 `nothing_active` after a
-- restart, while the legacy `static_policies` / `dynamic_policies` rows it is
-- meant to replace survive. `deploymode` declares Community as
-- `enterpriseSchema: false`, so migrations/enterprise/155 never ran and the
-- three tables did not exist.
--
-- DURABILITY IS NOT THE PAID FEATURE; ORGANIZATION-ROOT AUTHORING IS. A store
-- that empties on restart is not a lesser tier of storage, it is broken
-- storage, and #3906 already withdrew the reading under which "organization
-- root" meant "Enterprise only". The edition boundary is which CONSTRUCTS a
-- policy may use, carried per document by authoring.Profile at publication —
-- not which rows a deployment is allowed to keep. Enforcing it in the SCHEMA
-- puts an edition boundary where no ruling puts one.
--
-- 155's own header said "the community binary has no authoring surface to
-- persist". That was true when it was written and #3943 made it false.
--
-- ---------------------------------------------------------------------------
-- THIS IS A NO-OP ON ANY DEPLOYMENT THAT ALREADY APPLIED enterprise/155
-- ---------------------------------------------------------------------------
--
-- MEASURED, not read (2026-09-10, in the capture harness): 155 applied three
-- times to one database — 0 schema objects before, 15 after the first
-- application (3 tables, 3 org-isolation policies, 3 FORCE-RLS flags, 6
-- append-only triggers), exit 0 with zero ERROR lines on the second, and an
-- identical catalog snapshot. The instrument was proved able to report a
-- difference by dropping one policy between snapshots and watching it be named,
-- and the third application repaired the dropped policy. Every statement below
-- is `IF NOT EXISTS`, `CREATE OR REPLACE`, or a `DROP ... IF EXISTS` followed by
-- a create, so re-application converges rather than errors.
--
-- ORDERING. The runner sorts every selected category's files by version number
-- globally (collectMigrations in platform/agent/migration_helpers.go), so on a
-- deployment applying both categories, enterprise/155 runs BEFORE this file and
-- this file is the no-op; on Community only this file runs and it does the work.
-- Neither order can produce a different schema, which is what the measurement
-- above establishes.
--
-- enterprise/155 is deliberately LEFT IN PLACE and still says what it applied on
-- the deployments that ran it. Its DOWN is now a no-op, because with two
-- migrations creating one set of tables the first rollback would destroy the
-- other's state; this file's down is the single rollback path. See
-- migrations/enterprise/155_typed_authoring_persistence_down.sql.
--
-- ---------------------------------------------------------------------------
-- THREE TABLES, AND WHY THE THIRD ONE EXISTS
-- ---------------------------------------------------------------------------
--
-- typed_policy_artifacts     — the admitted, signed, digest-pinned versions.
-- typed_policy_activations   — the audited activation history per authority
--                              root. A record, not a log line.
-- typed_policy_signing_keys  — the PUBLIC half of every key authorized to sign
--                              under a root.
--
-- The third is what makes the first two worth persisting. An artifact carries
-- an ed25519 signature and the verifier resolves the public key from a trust
-- store; #3762 built that trust store per PROCESS. Persisting an artifact
-- without persisting the authorization produces a durable row no later process
-- can verify — worse than not persisting it, because it looks like policy
-- history and is not checkable.
--
-- IT DOES NOT PERSIST A PRIVATE KEY, DELIBERATELY. Durable signing IDENTITY is
-- #3605's KMS custody chain. Each process mints its own key and records the
-- public half: every process can VERIFY everything, each can only SIGN as
-- itself, and no second key-custody surface competes with #3605.
--
-- ---------------------------------------------------------------------------
-- APPEND-ONLY, AND THE ACTIVATION SEQUENCE AS CONCURRENCY CONTROL
-- ---------------------------------------------------------------------------
--
-- All three tables are append-only, enforced three ways in core/171's pattern:
-- a BEFORE UPDATE OR DELETE trigger (which binds the table OWNER, whom a
-- privilege revoke does not), a BEFORE TRUNCATE trigger, and REVOKE
-- UPDATE/DELETE/TRUNCATE from both application roles.
--
-- typed_policy_activations carries `seq`, unique per (org_id, root). Promotion
-- is a read-then-write and a mutex makes it atomic in ONE process only; two
-- replicas can both read active digest D, both find their candidate's parent is
-- D, and both write. UNIQUE (org_id, root, seq) makes the second fail, which is
-- the durable form of the in-memory parent check. The ACTIVE version is derived
-- from this table (highest seq), never stored beside it.
--
-- ---------------------------------------------------------------------------
-- THE CONNECTION THIS IS WRITTEN FOR IS THE APP ROLE, NOT THE OWNER
-- ---------------------------------------------------------------------------
--
-- authoringstore runs every statement inside rls.WithOrgScope, which sets
-- app.current_org_id for the transaction so the FORCE-RLS policies below bind.
-- That is only true for a NON-OWNER: FORCE RLS binds the owner too, but the
-- orchestrator connects with agent.OpenAppRoleConnection, and it must, because
-- an owner connection with no GUC set would read zero rows and look empty
-- rather than refused. The grants below are what make that connection able to
-- work at all.
--
-- ---------------------------------------------------------------------------
-- WHY THE GRANT BLOCK IS IN THIS FILE AND NOT ONLY IN enterprise/155
-- ---------------------------------------------------------------------------
--
-- TestEveryForceRLSTableHasAnApplicationGrant keys each table on the FIRST
-- migration (in sorted path order) that FORCES row-level security on it, and
-- `core/176...` sorts before `enterprise/155...`. So this file becomes the
-- census's owner of all three tables, and its edition arm requires that a
-- CORE-forced table is granted by a CORE file: migrations/core ships to the
-- community mirror and migrations/enterprise does not, so a grant living only
-- in the enterprise file is absent in the mirror tree, where the same census
-- runs and fails. That is not theoretical — it happened to `customers` on
-- #3636. The grants are therefore literal statements, not format(...%I...)
-- inside a loop, because the census reads SOURCE and a grant assembled at
-- runtime is invisible to it.
--
-- ---------------------------------------------------------------------------
-- REVISIT WHEN
-- ---------------------------------------------------------------------------
--
-- 1. ARTIFACT RETENTION. These tables only grow and nothing here deletes. The
--    per-organization cap REFUSES a publication at 64 artifacts; it has never
--    evicted. Revisit when typed_policy_artifacts exceeds 10,000 rows on any
--    deployed stack, and resolve it under ADR-058's audit retention direction
--    rather than by granting DELETE here.
-- 2. SIGNING-KEY RETENTION, which no cap bounds. Each process mints a key per
--    organization workspace and records its public half; LoadTrust reads every
--    unrevoked row on every rebuild. Revisit when typed_policy_signing_keys
--    exceeds 500 rows for any single organization. The fix is #3605's custody
--    chain or a revocation sweep, not a DELETE grant.
-- 3. SIGNING IDENTITY. When #3605's KMS custody chain lands, a process should
--    stop minting its own key and the INSERT path here should narrow to
--    whatever #3605 makes the authorizing act.
--
-- ---------------------------------------------------------------------------

BEGIN;

-- ---------------------------------------------------------------------------
-- typed_policy_artifacts
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS typed_policy_artifacts (
    org_id           VARCHAR(255) NOT NULL,
    root             VARCHAR(32)  NOT NULL,
    digest           VARCHAR(128) NOT NULL,
    -- source_digest is the digest of the AUTHORING DOCUMENT, which does not
    -- move when the same document is published again; the artifact digest does,
    -- because it covers the publication timestamp. Anything that has to be
    -- idempotent across runs keys on this column, so it is indexed.
    source_digest    VARCHAR(128) NOT NULL,
    document_id      VARCHAR(255) NOT NULL,
    document_version INTEGER      NOT NULL,
    key_id           VARCHAR(255) NOT NULL,
    -- artifact is the transport form the Go code marshals and re-loads. Carried
    -- whole rather than shredded into columns because every claim it makes is
    -- re-derived on load — signature, digest, module lint, gauntlet report, and
    -- a recompile of the carried source — and a shredded copy would be a
    -- second, unverified representation of the same artifact.
    artifact         JSONB        NOT NULL,
    admitted_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, root, digest),
    CONSTRAINT typed_policy_artifacts_org_nonempty_chk   CHECK (org_id <> ''),
    CONSTRAINT typed_policy_artifacts_root_chk           CHECK (root IN ('system', 'organization')),
    CONSTRAINT typed_policy_artifacts_digest_form_chk    CHECK (digest LIKE 'sha256:%'),
    CONSTRAINT typed_policy_artifacts_source_form_chk    CHECK (source_digest LIKE 'sha256:%'),
    CONSTRAINT typed_policy_artifacts_version_chk        CHECK (document_version >= 1),
    CONSTRAINT typed_policy_artifacts_key_nonempty_chk   CHECK (key_id <> '')
);

CREATE INDEX IF NOT EXISTS idx_typed_policy_artifacts_source
    ON typed_policy_artifacts (org_id, root, source_digest);

COMMENT ON TABLE typed_policy_artifacts IS
    'ADR-065 typed authoring: admitted, signed, digest-pinned policy versions. Append-only (#3776, moved to core by #3975).';

-- ---------------------------------------------------------------------------
-- typed_policy_activations
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS typed_policy_activations (
    org_id           VARCHAR(255) NOT NULL,
    root             VARCHAR(32)  NOT NULL,
    seq              INTEGER      NOT NULL,
    kind             VARCHAR(16)  NOT NULL,
    digest           VARCHAR(128) NOT NULL,
    -- previous_digest is '' for the first activation under a root. It is what
    -- makes the history a chain rather than a list.
    previous_digest  VARCHAR(128) NOT NULL DEFAULT '',
    document_id      VARCHAR(255) NOT NULL,
    document_version INTEGER      NOT NULL,
    actor            VARCHAR(512) NOT NULL,
    activated_at     TIMESTAMPTZ  NOT NULL,
    reason           TEXT         NOT NULL DEFAULT '',
    PRIMARY KEY (org_id, root, seq),
    CONSTRAINT typed_policy_activations_org_nonempty_chk   CHECK (org_id <> ''),
    CONSTRAINT typed_policy_activations_root_chk           CHECK (root IN ('system', 'organization')),
    CONSTRAINT typed_policy_activations_kind_chk           CHECK (kind IN ('promote', 'rollback')),
    CONSTRAINT typed_policy_activations_seq_chk            CHECK (seq >= 1),
    CONSTRAINT typed_policy_activations_digest_form_chk    CHECK (digest LIKE 'sha256:%'),
    CONSTRAINT typed_policy_activations_prev_form_chk      CHECK (previous_digest = '' OR previous_digest LIKE 'sha256:%'),
    -- An activation that names no actor defeats the audited history that is the
    -- stated reason emergency policy changes are tolerable at all.
    CONSTRAINT typed_policy_activations_actor_nonempty_chk CHECK (actor <> ''),
    -- A rollback records a reason. Promotion does not have to.
    CONSTRAINT typed_policy_activations_rollback_reason_chk
        CHECK (kind <> 'rollback' OR reason <> ''),
    -- The first activation under a root has seq 1 and no parent; every later one
    -- has both. Stated here so the chain cannot be broken by a writer that
    -- forgot, rather than only by the Go code that usually remembers.
    CONSTRAINT typed_policy_activations_chain_chk
        CHECK ((seq = 1 AND previous_digest = '') OR (seq > 1 AND previous_digest <> ''))
);

CREATE INDEX IF NOT EXISTS idx_typed_policy_activations_tip
    ON typed_policy_activations (org_id, root, seq DESC);

COMMENT ON TABLE typed_policy_activations IS
    'ADR-065 typed authoring: the audited activation history per authority root. Append-only; seq is the cross-replica parent check (#3776, moved to core by #3975).';

-- ---------------------------------------------------------------------------
-- typed_policy_signing_keys
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS typed_policy_signing_keys (
    org_id        VARCHAR(255) NOT NULL,
    root          VARCHAR(32)  NOT NULL,
    key_id        VARCHAR(255) NOT NULL,
    public_key    BYTEA        NOT NULL,
    authorized_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    authorized_by VARCHAR(512) NOT NULL DEFAULT '',
    revoked_at    TIMESTAMPTZ,
    revoked_reason TEXT,
    PRIMARY KEY (org_id, root, key_id),
    CONSTRAINT typed_policy_signing_keys_org_nonempty_chk CHECK (org_id <> ''),
    CONSTRAINT typed_policy_signing_keys_root_chk         CHECK (root IN ('system', 'organization')),
    CONSTRAINT typed_policy_signing_keys_key_nonempty_chk CHECK (key_id <> ''),
    -- An ed25519 public key is exactly 32 bytes. A column that accepts any
    -- length accepts a truncated key, which fails verification later and much
    -- less legibly.
    CONSTRAINT typed_policy_signing_keys_pubkey_len_chk   CHECK (octet_length(public_key) = 32),
    CONSTRAINT typed_policy_signing_keys_revocation_chk
        CHECK ((revoked_at IS NULL AND revoked_reason IS NULL)
            OR (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL AND revoked_reason <> ''))
);

COMMENT ON TABLE typed_policy_signing_keys IS
    'ADR-065 typed authoring: the PUBLIC half of every key authorized to sign under an authority root. Insert-only; the sole permitted update is a revocation (#3776, private-key custody is #3605, moved to core by #3975).';

-- ---------------------------------------------------------------------------
-- Row-level security — strict org equality, on all three
-- ---------------------------------------------------------------------------

ALTER TABLE typed_policy_artifacts    ENABLE ROW LEVEL SECURITY;
ALTER TABLE typed_policy_artifacts    FORCE  ROW LEVEL SECURITY;
ALTER TABLE typed_policy_activations  ENABLE ROW LEVEL SECURITY;
ALTER TABLE typed_policy_activations  FORCE  ROW LEVEL SECURITY;
ALTER TABLE typed_policy_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE typed_policy_signing_keys FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS typed_policy_artifacts_org_isolation ON typed_policy_artifacts;
CREATE POLICY typed_policy_artifacts_org_isolation ON typed_policy_artifacts
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

DROP POLICY IF EXISTS typed_policy_activations_org_isolation ON typed_policy_activations;
CREATE POLICY typed_policy_activations_org_isolation ON typed_policy_activations
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

DROP POLICY IF EXISTS typed_policy_signing_keys_org_isolation ON typed_policy_signing_keys;
CREATE POLICY typed_policy_signing_keys_org_isolation ON typed_policy_signing_keys
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

-- ---------------------------------------------------------------------------
-- Append-only triggers
--
-- The privilege revoke below does not bind the table OWNER, and a migration or
-- an operator session usually IS the owner. The trigger does bind it, which is
-- why both exist rather than either being redundant.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION typed_policy_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Table % is append-only: % is refused. ADR-065 policy history is a record, not a mutable row (#3776).',
        TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION typed_policy_signing_keys_revoke_only() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'typed_policy_signing_keys is insert-only: DELETE is refused. De-authorize a key by revoking it (#3776).'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.org_id        IS DISTINCT FROM OLD.org_id
       OR NEW.root       IS DISTINCT FROM OLD.root
       OR NEW.key_id     IS DISTINCT FROM OLD.key_id
       OR NEW.public_key IS DISTINCT FROM OLD.public_key
       OR NEW.authorized_at IS DISTINCT FROM OLD.authorized_at
       OR NEW.authorized_by IS DISTINCT FROM OLD.authorized_by THEN
        RAISE EXCEPTION
            'typed_policy_signing_keys: the only permitted update is a revocation; the key authorization itself is immutable (#3776).'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION
            'typed_policy_signing_keys: key %/%/% is already revoked; un-revoking a key is not an operation.',
            OLD.org_id, OLD.root, OLD.key_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION
            'typed_policy_signing_keys: an update to this table must set revoked_at (#3776).'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS typed_policy_artifacts_no_update_delete ON typed_policy_artifacts;
CREATE TRIGGER typed_policy_artifacts_no_update_delete
    BEFORE UPDATE OR DELETE ON typed_policy_artifacts
    FOR EACH ROW EXECUTE FUNCTION typed_policy_append_only();

DROP TRIGGER IF EXISTS typed_policy_artifacts_no_truncate ON typed_policy_artifacts;
CREATE TRIGGER typed_policy_artifacts_no_truncate
    BEFORE TRUNCATE ON typed_policy_artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION typed_policy_append_only();

DROP TRIGGER IF EXISTS typed_policy_activations_no_update_delete ON typed_policy_activations;
CREATE TRIGGER typed_policy_activations_no_update_delete
    BEFORE UPDATE OR DELETE ON typed_policy_activations
    FOR EACH ROW EXECUTE FUNCTION typed_policy_append_only();

DROP TRIGGER IF EXISTS typed_policy_activations_no_truncate ON typed_policy_activations;
CREATE TRIGGER typed_policy_activations_no_truncate
    BEFORE TRUNCATE ON typed_policy_activations
    FOR EACH STATEMENT EXECUTE FUNCTION typed_policy_append_only();

DROP TRIGGER IF EXISTS typed_policy_signing_keys_revoke_only ON typed_policy_signing_keys;
CREATE TRIGGER typed_policy_signing_keys_revoke_only
    BEFORE UPDATE OR DELETE ON typed_policy_signing_keys
    FOR EACH ROW EXECUTE FUNCTION typed_policy_signing_keys_revoke_only();

DROP TRIGGER IF EXISTS typed_policy_signing_keys_no_truncate ON typed_policy_signing_keys;
CREATE TRIGGER typed_policy_signing_keys_no_truncate
    BEFORE TRUNCATE ON typed_policy_signing_keys
    FOR EACH STATEMENT EXECUTE FUNCTION typed_policy_append_only();

-- ---------------------------------------------------------------------------
-- Grants
--
-- Literal statements, not format(...%I...) inside a loop: the RLS grant census
-- (platform/agent/migration_rls_grant_census_test.go) reads migration SOURCE,
-- and a grant assembled at runtime is invisible to it. See the header for why
-- the grant must live in THIS file rather than only in enterprise/155.
--
-- core/098's ALTER DEFAULT PRIVILEGES has already granted UPDATE and DELETE on
-- every new table to both roles by the time this runs, so a narrow GRANT is not
-- enough: the REVOKE has to come first and is what actually removes them.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON typed_policy_artifacts    FROM axonflow_app_role;
        REVOKE UPDATE, DELETE, TRUNCATE ON typed_policy_activations  FROM axonflow_app_role;
        REVOKE UPDATE, DELETE, TRUNCATE ON typed_policy_signing_keys FROM axonflow_app_role;
        GRANT SELECT, INSERT ON typed_policy_artifacts    TO axonflow_app_role;
        GRANT SELECT, INSERT ON typed_policy_activations  TO axonflow_app_role;
        GRANT SELECT, INSERT ON typed_policy_signing_keys TO axonflow_app_role;
        GRANT UPDATE (revoked_at, revoked_reason) ON typed_policy_signing_keys TO axonflow_app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON typed_policy_artifacts    FROM axonflow_platform_admin;
        REVOKE UPDATE, DELETE, TRUNCATE ON typed_policy_activations  FROM axonflow_platform_admin;
        REVOKE UPDATE, DELETE, TRUNCATE ON typed_policy_signing_keys FROM axonflow_platform_admin;
        GRANT SELECT, INSERT ON typed_policy_artifacts    TO axonflow_platform_admin;
        GRANT SELECT, INSERT ON typed_policy_activations  TO axonflow_platform_admin;
        GRANT SELECT, INSERT ON typed_policy_signing_keys TO axonflow_platform_admin;
        GRANT UPDATE (revoked_at, revoked_reason) ON typed_policy_signing_keys TO axonflow_platform_admin;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Self-verification BEFORE COMMIT
--
-- Every claim this migration makes is re-derived from the catalog here, in the
-- same transaction, so a migration that reported success while half-applying is
-- not a state this deployment can reach. The pattern is core/171's.
--
-- It verifies the SCHEMA, not who created it: on a deployment that applied
-- enterprise/155 first this file changed nothing, and the assertions below must
-- still hold — that is what makes "this is a safe no-op there" checked on every
-- such deployment rather than asserted once in a harness.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    t   TEXT;
    r   TEXT;
    n   INTEGER;
BEGIN
    FOREACH t IN ARRAY ARRAY['typed_policy_artifacts', 'typed_policy_activations', 'typed_policy_signing_keys'] LOOP
        IF to_regclass(t) IS NULL THEN
            RAISE EXCEPTION 'Migration 176 failed: table % was not created', t;
        END IF;

        SELECT COUNT(*) INTO n
        FROM pg_catalog.pg_class c
        WHERE c.oid = to_regclass(t) AND c.relrowsecurity AND c.relforcerowsecurity;
        IF n <> 1 THEN
            RAISE EXCEPTION 'Migration 176 failed: % does not have ENABLE + FORCE ROW LEVEL SECURITY', t;
        END IF;

        SELECT COUNT(*) INTO n FROM pg_catalog.pg_policies
        WHERE schemaname = 'public' AND tablename = t AND policyname = t || '_org_isolation';
        IF n <> 1 THEN
            RAISE EXCEPTION 'Migration 176 failed: % is missing its org-isolation policy', t;
        END IF;

        -- Two triggers per table: the row-level guard and the TRUNCATE guard.
        SELECT COUNT(*) INTO n FROM pg_catalog.pg_trigger
        WHERE tgrelid = to_regclass(t) AND NOT tgisinternal;
        IF n <> 2 THEN
            RAISE EXCEPTION 'Migration 176 failed: % carries % append-only triggers, expected 2', t, n;
        END IF;

        FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
            CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
            IF has_table_privilege(r, t, 'DELETE') OR has_table_privilege(r, t, 'TRUNCATE') THEN
                RAISE EXCEPTION 'Migration 176 failed: % still holds DELETE/TRUNCATE on %', r, t;
            END IF;
            IF NOT has_table_privilege(r, t, 'SELECT') OR NOT has_table_privilege(r, t, 'INSERT') THEN
                RAISE EXCEPTION 'Migration 176 failed: % lacks SELECT/INSERT on %', r, t;
            END IF;
            -- Table-wide UPDATE is gone everywhere. typed_policy_signing_keys
            -- keeps it on exactly two columns; the others keep it on none.
            IF has_table_privilege(r, t, 'UPDATE') THEN
                RAISE EXCEPTION 'Migration 176 failed: % still holds table-wide UPDATE on %', r, t;
            END IF;
            IF t = 'typed_policy_signing_keys' THEN
                IF NOT has_column_privilege(r, t, 'revoked_at', 'UPDATE')
                   OR NOT has_column_privilege(r, t, 'revoked_reason', 'UPDATE') THEN
                    RAISE EXCEPTION 'Migration 176 failed: % cannot revoke a signing key', r;
                END IF;
                IF has_column_privilege(r, t, 'public_key', 'UPDATE') THEN
                    RAISE EXCEPTION 'Migration 176 failed: % can rewrite a public key on %', r, t;
                END IF;
            ELSE
                IF has_column_privilege(r, t, 'org_id', 'UPDATE') THEN
                    RAISE EXCEPTION 'Migration 176 failed: % holds a column UPDATE on %', r, t;
                END IF;
            END IF;
        END LOOP;
    END LOOP;

    RAISE NOTICE 'Migration 176 verified: typed_policy_artifacts, typed_policy_activations and typed_policy_signing_keys are org-isolated, FORCE-RLS and append-only on every deployment mode.';
END $$;

COMMIT;
