-- Migration 169: trust-realm persistence (#3550, ADR-065, session v10.3-D)
-- Date: 2026-08-31
-- Purpose: Persist the organization-scoped trust realms that
--          platform/shared/identity's RealmRegistry has held in memory since
--          #3556. A trust realm is CONFIGURATION - which credentials an
--          organization accepts from one identity source, what they may
--          assert, whether the source carries a group graph, and whether
--          anything in it can answer a question - and an in-memory registry
--          means every replica has to be told the same configuration by some
--          other channel, and a restart forgets it.
--
--          Deliberately a SECOND PR after #3582/#3596, as that PR's own
--          closeout said: the registry's contract does not change when its
--          backing store does, and putting a migration in a
--          behaviour-changing PR puts two independently-revertable risks on
--          one commit.
--
-- EDITION: core. platform/shared/identity/realm.go carries no build tag, so
--          the realm vocabulary is compiled into the community binary too,
--          and the store follows the type it stores. The migration number was
--          allocated by master in the core tree (#3550, confirmed on #3604);
--          it was not self-picked.
--
-- EXISTENCE PROBES USE pg_catalog, NEVER information_schema (#3463): a
--          privilege-filtered probe answers "absent" for a relation the role
--          merely cannot see, and a guarded statement then silently skips.
--
-- ════════════════════════════════════════════════════════════════════════════
-- THE JSONB BLOB IS THE RECORD; THE COLUMNS ARE THE INDEX
-- ════════════════════════════════════════════════════════════════════════════
--
-- `config` holds the whole TrustRealm. kind, canonical_issuer, enabled and
-- version are PROJECTIONS of fields inside it, present only so the database
-- can enforce the issuer constraint and so an operator can read the table.
-- The store loads realms from `config` and from nothing else.
--
-- That asymmetry is deliberate. A schema that spread twenty-odd realm fields
-- across twenty-odd columns would need a migration for every field ADR-065
-- adds, and - worse - a field somebody forgot to add would be silently
-- DEFAULTED on read. Every tri-state field on TrustRealm reserves its zero
-- value for "not declared" and Register REFUSES a realm that leaves one there
-- (that is EX-47, a fail-open produced entirely by omission), so a column set
-- that quietly loses a field would reintroduce exactly the defect the type
-- system was shaped to prevent. Round-tripping the whole value cannot lose a
-- field, and identity.TestEveryTrustRealmFieldSurvivesTheRoundTrip fails on a
-- new one that does not survive.
--
-- ════════════════════════════════════════════════════════════════════════════
-- THE ISSUER IS UNIQUE PER ORGANIZATION, IN THE DATABASE
-- ════════════════════════════════════════════════════════════════════════════
--
-- RealmRegistry.Register already refuses a realm whose canonical issuer is
-- already claimed by a DIFFERENT realm in the same organization, because an
-- issuer resolving to two realms has no determinate answer and picking one
-- would be arbitrary. That check is per-process. With several replicas writing
-- through, two of them can pass it concurrently and store two realms claiming
-- one issuer; the constraint below is what makes that unconstructible rather
-- than unlikely.
--
-- It is scoped PER ORGANIZATION on purpose, not globally: two customers can
-- legitimately both federate the same public IdP, and a global unique index
-- would let whichever of them registered first lock the other out.

BEGIN;

CREATE TABLE IF NOT EXISTS identity_trust_realms (
    org_id           VARCHAR(255) NOT NULL,
    -- 512, chosen against identity.maxPrincipalComponent, the bound
    -- ValidateRealmID actually enforces. The two units are NOT the same and
    -- the difference is in the safe direction: VARCHAR(512) counts CHARACTERS
    -- while maxPrincipalComponent counts BYTES (it is a len() on the string),
    -- so every id the validator admits fits, and some the column would admit
    -- the validator will not. At VARCHAR(255) a realm id that the
    -- type accepted and encodeRealm accepted failed at the INSERT with a raw
    -- `value too long for type character varying(255)` - a driver error with
    -- none of the explanation every other refusal here carries, and no test
    -- covered it. Fails closed either way (Postgres errors rather than
    -- truncating), so this is a correctness and diagnosability fix; the column
    -- now agrees with the validator instead of contradicting it.
    realm_id         VARCHAR(512) NOT NULL,
    kind             VARCHAR(64)  NOT NULL,
    canonical_issuer TEXT         NOT NULL,
    enabled          BOOLEAN      NOT NULL,
    version          BIGINT       NOT NULL,
    config           JSONB        NOT NULL,
    updated_by       VARCHAR(255),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT identity_trust_realms_pkey PRIMARY KEY (org_id, realm_id),
    CONSTRAINT identity_trust_realms_issuer_uniq UNIQUE (org_id, canonical_issuer),
    -- A realm id is colon-free BY CONSTRUCTION (RealmID's doc comment), and
    -- that is not cosmetic: it is what makes the canonical principal wire form
    -- parseable when a subject id contains colons. A colon smuggled in here
    -- would produce principals nothing can parse back.
    CONSTRAINT identity_trust_realms_realm_id_colon_free_chk
        CHECK (position(':' IN realm_id) = 0),
    CONSTRAINT identity_trust_realms_realm_id_nonempty_chk CHECK (btrim(realm_id) <> ''),
    CONSTRAINT identity_trust_realms_issuer_nonempty_chk   CHECK (btrim(canonical_issuer) <> ''),
    -- Version must ADVANCE on a re-registration: a no-graph closure derives
    -- its recorded source version from it, so two materially different
    -- declarations sharing a version produce closures that are
    -- indistinguishable in a decision proof and in replay. Zero would document
    -- nothing.
    CONSTRAINT identity_trust_realms_version_chk CHECK (version >= 1),
    CONSTRAINT identity_trust_realms_config_is_object_chk CHECK (jsonb_typeof(config) = 'object')
);

-- identity_realm_epochs holds ONE row per organization: the identity epoch a
-- decision proof binds.
--
-- A SEPARATE TABLE RATHER THAN max(version), because the epoch must advance on
-- every mutation INCLUDING A DELETE, and a maximum over the surviving rows
-- goes DOWN when the highest-versioned realm is removed. An epoch that can go
-- backwards makes a stale cached closure look current again, which is the one
-- thing the epoch exists to prevent.
--
-- It is PER ORGANIZATION where RealmRegistry's counter is per process. That is
-- a strengthening: one organization's realm change should not invalidate
-- another's cached closures, and in-process the two are indistinguishable only
-- because a single-tenant process never noticed.
CREATE TABLE IF NOT EXISTS identity_realm_epochs (
    org_id     VARCHAR(255) NOT NULL,
    epoch      BIGINT       NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT identity_realm_epochs_pkey PRIMARY KEY (org_id),
    CONSTRAINT identity_realm_epochs_epoch_chk CHECK (epoch >= 1)
);

-- Organization isolation, enforced by the storage engine.
--
-- ENABLE *and* FORCE on both, matching enterprise/135, enterprise/146 and
-- enterprise/147. `ENABLE` alone exempts the table OWNER from every policy,
-- which is the posture hitl_approval_queue carries and which has already
-- produced RLS assertions that passed no matter what the policy said.
--
-- current_setting(..., true) is NULL when the GUC is unset, and
-- `org_id = NULL` is NULL, so a read that forgets its scope returns NOTHING.
-- For this table that failure mode is specifically the safe one: a realm
-- lookup that returns nothing is UNKNOWN_REALM, which denies. A store that
-- returned another organization's realms would accept its issuers.
ALTER TABLE identity_trust_realms ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_trust_realms FORCE  ROW LEVEL SECURITY;
ALTER TABLE identity_realm_epochs ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_realm_epochs FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS identity_trust_realms_org_isolation ON identity_trust_realms;
CREATE POLICY identity_trust_realms_org_isolation ON identity_trust_realms
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

DROP POLICY IF EXISTS identity_realm_epochs_org_isolation ON identity_realm_epochs;
CREATE POLICY identity_realm_epochs_org_isolation ON identity_realm_epochs
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON TABLE identity_trust_realms IS
    'ADR-065 organization-scoped trust realms (#3550). One row per (org, realm); `config` is the whole TrustRealm and is the authoritative record, while kind/canonical_issuer/enabled/version are projections of it kept for the issuer constraint and for operator legibility.';
COMMENT ON COLUMN identity_trust_realms.config IS
    'The whole TrustRealm. Read back in full: every tri-state field reserves its zero value for "not declared" and registration refuses one left there (EX-47), so a column set that silently defaulted a missing field would reintroduce that fail-open.';
COMMENT ON TABLE identity_realm_epochs IS
    'The per-organization ADR-065 identity epoch. Advances on every realm mutation INCLUDING a delete, which is why it is a stored counter rather than max(version) - a maximum goes down when the highest-versioned realm is removed, and an epoch that goes backwards makes a stale cached closure look current again.';

-- Verification: fail loudly if any artifact is missing.
DO $$
DECLARE
    t           text;
    want_check  text;
    issuer_cols text;
    pkey_cols   text;
    check_def   text;
BEGIN
    FOREACH t IN ARRAY ARRAY['identity_trust_realms', 'identity_realm_epochs'] LOOP
        IF to_regclass(t) IS NULL THEN
            RAISE EXCEPTION 'Migration 169 failed: table % not created', t;
        END IF;
        IF NOT (SELECT relrowsecurity AND relforcerowsecurity
                  FROM pg_catalog.pg_class WHERE oid = t::regclass) THEN
            RAISE EXCEPTION 'Migration 169 failed: RLS not ENABLEd + FORCEd on %', t;
        END IF;
        -- Joined on the RESOLVED oid, not on an unqualified relname: a
        -- same-named table in another schema carrying a same-named policy
        -- would otherwise satisfy this. And the policy's EXPRESSION is
        -- checked, not only its name - a policy called
        -- `<table>_org_isolation` with `USING (true)` is no isolation at all
        -- and would have passed a name-only probe.
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p
                       WHERE p.polrelid = t::regclass
                         AND p.polname = t || '_org_isolation'
                         AND pg_get_expr(p.polqual, p.polrelid) LIKE '%app.current_org_id%'
                         AND pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%app.current_org_id%') THEN
            RAISE EXCEPTION 'Migration 169 failed: isolation policy missing on %, or its USING / WITH CHECK expression does not consult app.current_org_id', t;
        END IF;
    END LOOP;

    -- PRESENCE first, then - for the CHECKs that carry behaviour - the
    -- DEFINITION.
    --
    -- A name-only probe is defeated by keeping the name and neutering the
    -- expression: `CHECK (true)` under the right conname satisfies it, and the
    -- NOTICE below would still report "all CHECKs installed". That is the same
    -- argument this block already makes about a policy named `..._org_isolation`
    -- with `USING (true)`, and it applied here too.
    FOREACH want_check IN ARRAY ARRAY[
        'identity_trust_realms_issuer_uniq',
        'identity_trust_realms_realm_id_colon_free_chk',
        'identity_trust_realms_realm_id_nonempty_chk',
        'identity_trust_realms_issuer_nonempty_chk',
        'identity_trust_realms_version_chk',
        'identity_trust_realms_config_is_object_chk'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                       WHERE conrelid = 'identity_trust_realms'::regclass
                         AND conname = want_check) THEN
            RAISE EXCEPTION 'Migration 169 failed: constraint % missing on identity_trust_realms', want_check;
        END IF;
    END LOOP;

    -- Each behavioural CHECK must still mention what it constrains. Matching
    -- on the definition rather than comparing it verbatim, so PostgreSQL's own
    -- normalisation of the expression across versions does not turn a correct
    -- schema into a failed migration.
    FOR want_check, check_def IN
        SELECT conname, pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint
         WHERE conrelid = 'identity_trust_realms'::regclass AND contype = 'c'
    LOOP
        IF want_check = 'identity_trust_realms_realm_id_colon_free_chk'
           AND check_def NOT LIKE '%realm_id%' THEN
            RAISE EXCEPTION 'Migration 169 failed: the colon-free CHECK no longer constrains realm_id (%). A realm id containing a colon makes the canonical principal wire form unparseable.', check_def;
        END IF;
        IF want_check = 'identity_trust_realms_version_chk'
           AND check_def NOT LIKE '%version%' THEN
            RAISE EXCEPTION 'Migration 169 failed: the version CHECK no longer constrains version (%).', check_def;
        END IF;
        IF want_check = 'identity_trust_realms_config_is_object_chk'
           AND check_def NOT LIKE '%config%' THEN
            RAISE EXCEPTION 'Migration 169 failed: the config CHECK no longer constrains config (%).', check_def;
        END IF;
    END LOOP;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                   WHERE conrelid = 'identity_realm_epochs'::regclass
                     AND conname = 'identity_realm_epochs_epoch_chk'
                     AND pg_get_constraintdef(oid) LIKE '%epoch%') THEN
        RAISE EXCEPTION 'Migration 169 failed: the epoch CHECK is missing or no longer constrains epoch.';
    END IF;

    -- The issuer constraint must be scoped to the ORGANIZATION, not global.
    -- Two customers can legitimately federate the same public IdP, and a
    -- global unique index would let whichever registered first lock the other
    -- out - a cross-tenant denial of service written as a schema decision.
    --
    -- THE COLUMN NAMES ARE RESOLVED, not just counted. An earlier version of
    -- this probe checked ARITY alone while its message asserted the columns
    -- had been checked, so `UNIQUE (org_id, kind)` - two columns, and
    -- catastrophically wrong - would have satisfied it.
    SELECT string_agg(a.attname, ',' ORDER BY a.attname)
      INTO issuer_cols
      FROM pg_catalog.pg_constraint c
      JOIN pg_catalog.pg_attribute a
        ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
     WHERE c.conrelid = 'identity_trust_realms'::regclass
       AND c.conname = 'identity_trust_realms_issuer_uniq';
    -- The PRIMARY KEY is load-bearing for the store's upsert: DBRealmStore's
    -- `ON CONFLICT (org_id, realm_id)` has no arbiter without exactly this
    -- key and fails hard at runtime rather than at apply time.
    SELECT string_agg(a.attname, ',' ORDER BY a.attname)
      INTO pkey_cols
      FROM pg_catalog.pg_constraint c
      JOIN pg_catalog.pg_attribute a
        ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
     WHERE c.conrelid = 'identity_trust_realms'::regclass AND c.contype = 'p';
    IF pkey_cols IS DISTINCT FROM 'org_id,realm_id' THEN
        RAISE EXCEPTION 'Migration 169 failed: the primary key covers (%) and must cover exactly (org_id, realm_id); the store''s ON CONFLICT (org_id, realm_id) has no arbiter otherwise.', COALESCE(pkey_cols, 'nothing');
    END IF;

    IF issuer_cols IS DISTINCT FROM 'canonical_issuer,org_id' THEN
        RAISE EXCEPTION 'Migration 169 failed: the issuer uniqueness constraint covers (%), not (org_id, canonical_issuer). A global one lets one customer''s registration lock another out of a shared public IdP.', COALESCE(issuer_cols, 'nothing - the constraint is missing');
    END IF;

    -- The primary key is what upsertRealmSQL''s ON CONFLICT (org_id, realm_id)
    -- targets; without it every write fails at run time rather than here.
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                   WHERE conrelid = 'identity_trust_realms'::regclass
                     AND conname = 'identity_trust_realms_pkey' AND contype = 'p') THEN
        RAISE EXCEPTION 'Migration 169 failed: identity_trust_realms_pkey missing; the store''s ON CONFLICT (org_id, realm_id) target does not exist';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                   WHERE conrelid = 'identity_realm_epochs'::regclass
                     AND conname = 'identity_realm_epochs_epoch_chk') THEN
        RAISE EXCEPTION 'Migration 169 failed: epoch CHECK missing';
    END IF;

    RAISE NOTICE 'Migration 169 verified: identity_trust_realms + identity_realm_epochs present, all CHECKs installed, issuer uniqueness is per-organization, RLS enabled+FORCED on both, isolation policies installed';
END
$$;

COMMIT;
