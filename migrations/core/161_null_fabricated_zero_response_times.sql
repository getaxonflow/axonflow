-- Migration 161: audit_logs.response_time_ms = 0 becomes NULL
-- Date: 2026-08-22
-- Issue: #3424 (round 2 blocker + the sub-millisecond majority)
--
-- Until this release NO writer could produce a response_time_ms of 0 as a
-- MEASUREMENT. Every stored 0 was fabricated by a writer that had nothing to
-- record and bound the int64 zero value anyway:
--
--   * orchestrator BatchWriter -- seven of its eight AuditEntry producers
--     (blocked request / response / media, failed request, workflow, plan and
--     tool-call rows) never set ResponseTime at all.
--   * the HITL approval writer -- bound a hardcoded 0 for an async human
--     decision that has no enforcement latency.
--
-- Those zeros were harmless only because the reader's predicate happened to be
-- `response_time_ms IS NOT NULL AND response_time_ms > 0`. #3424 relaxes that
-- predicate to `IS NOT NULL` so that a decision faster than the column's 1ms
-- resolution can be recorded honestly as the 0 the clock produced instead of
-- disappearing (measured live: 19 of 20 ordinary ALLOW decisions recorded no
-- sample under the old rule). The instant that predicate relaxes, every
-- fabricated zero already in the table becomes a "measured 0ms" sample and
-- drags the portal's Avg Latency tile towards zero -- the exact defect #3424
-- exists to remove, re-created from history.
--
-- So the relaxation and this backfill are one change and must ship together.
-- Migrations run before the new readers serve traffic, which is the required
-- order: this statement must land BEFORE any reader admits a 0.
--
-- It is also what makes the tile's row-level neighbour honest. /audit/search
-- now emits response_time_ms as a nullable field and the portal renders NULL
-- as "-", so a legacy row that keeps a fabricated 0 would render "0ms" in the
-- Latency column directly underneath a summary tile that (correctly) refuses
-- to count it.
--
-- Scope: whole-table, deliberately not tenant-scoped. The value is wrong for
-- every tenant. audit_logs has no RLS (the tenant boundary is the SQL
-- predicate off the stamped header), so this runs as a plain UPDATE.
--
-- THE ROLLING-DEPLOY WINDOW, which this migration does NOT close and must not
-- pretend to. Migrations run before the new images serve traffic, but the OLD
-- images keep serving until they drain, and an old orchestrator's BatchWriter
-- still binds a literal 0 for its seven measurement-less producers. Every such
-- row written between this UPDATE and the last old task exiting is read by the
-- new reader as a measured 0ms sample, permanently, because nothing re-runs
-- this statement.
--
-- That is accepted rather than engineered around, and the reasoning is worth
-- recording because the alternatives are worse:
--
--   * The blast radius is bounded. Only the BatchWriter's
--     lifecycle/workflow/plan/tool-call/blocked/failed producers and the HITL
--     approval writer emit a fabricated 0. On an MCP or agentic install the
--     tool-call producer is NOT low-rate, so this is a bound on the window
--     rather than on the row count: it lasts until the last old task exits,
--     and a roll-BACK reopens it for as long as the old image serves (this
--     migration does not re-run on roll-forward). Sizing it is a deployment
--     question, not a schema one.
--   * The failure is a MILD under-report of an average, not a wrong verdict or
--     a lost record, and it decays: those rows age out of any range an
--     operator looks at, and out of the table entirely at the retention floor.
--   * A repeated sweep (a scheduled job, or a trigger) would cost a permanent
--     moving part to fix a transient, and a trigger on audit_logs is on the
--     write path of every governed decision.
--   * Deploying the reader relaxation a release AFTER the writer change would
--     close it, at the cost of shipping a fix in two halves whose first half
--     is invisible to the operator the issue was filed by.
--
-- THE TIME BOUND (#3427 R3, carried over from migration 162). The statement is
-- bounded to `timestamp < NOW()` -- inside this transaction NOW() is the
-- transaction's start, so it cannot reach a row written after the migration
-- began. 162 gained this bound first, but the argument applies at least as
-- strongly here: an unbounded re-run of 162 replaces zeros that no measurement
-- backs, while an unbounded re-run of THIS statement nulls the genuine
-- sub-millisecond samples described below. The more destructive of the two was
-- the unbounded one.
--
-- THE BOUND IS PINNED TO UTC (`SET LOCAL TimeZone = 'UTC'`, below), for the
-- reason migration 162's header sets out in full: migration 142 makes this
-- column timestamptz and the comparison is then absolute, but on a database
-- where audit_logs was created at runtime and never got 142 the column is
-- timestamp WITHOUT time zone and NOW() is compared through the SESSION zone.
-- Unpinned, that shift reaches INTO THE FUTURE east of UTC -- measured on that
-- shape on Postgres 16, an Asia/Kolkata session matched rows dated up to 5h30
-- ahead. Pinned, every session zone selects the same rows. The bound also
-- skips a row with a NULL timestamp (`timestamp < NOW()` is NULL, not true);
-- unreachable on a canonical schema, since 059 declares
-- `timestamp TIMESTAMP NOT NULL`, and stated here rather than assumed.
--
-- The bound narrows the scope to history. It is NOT what makes the statement
-- safe: `response_time_ms = 0` is, because it can only ever replace a
-- fabricated 0 with NULL and can never touch a measured value.
--
-- THE BOUND AND THE PIN WERE ADDED TO THIS FILE IN PLACE, after it had already
-- landed on main, and that is safe here only because of release timing. 161
-- landed on main via #3429 (e5c4e7b0f) and is in NO released tag (verified
-- absent from v9.19.0 and v9.18.0), so no deployment has ever applied the
-- unbounded, unpinned version and no operator can be sitting on it. The edit
-- therefore reaches every deployment that will ever run this migration.
--
-- Do not generalise that. An in-place edit is normally NOT picked up: the
-- runner keys getAppliedMigrations on (version, name) alone
-- (platform/agent/migration_helpers.go), and while schema_migrations carries a
-- checksum column the runner never writes it and never compares it, so a
-- migration whose row is already present is skipped however the file changes.
-- For a data backfill that skip is the CORRECT behaviour and is relied on
-- below: it is what stops a redeploy from re-running this statement against a
-- live deployment, which is precisely what the next section forbids. The cost
-- of it is that a correction to an ALREADY-APPLIED migration has to ship as a
-- new version, and the only reason this one did not is the timing above.
--
-- DO NOT RE-RUN THIS STATEMENT AFTER THE NEW WRITERS ARE LIVE. It is
-- idempotent only against the data it was written for, and the bound does not
-- change that: a second run picks up a LATER NOW() and so covers everything
-- written since. Once sharedaudit.MeasuredLatencyMs is storing the 0 a
-- sub-millisecond decision produces -- by this change's own measurement, 19 of
-- 20 ordinary ALLOW decisions -- `WHERE response_time_ms = 0` matches every one
-- of those GENUINE samples, and nulling them destroys the measurements this
-- work exists to create, unrecoverably, leaving the tile averaging only the
-- slow tail.
--
-- An operator who wants the drain-window residue cleared later must supply the
-- cutover explicitly rather than re-running this file:
--
--   UPDATE audit_logs SET response_time_ms = NULL
--    WHERE response_time_ms = 0
--      AND timestamp < TIMESTAMPTZ '<the moment the last old task exited>';
--
-- COST. One sequential scan of audit_logs. audit_logs.response_time_ms carries
-- no index (059_runtime_tables_to_migrations.sql declares it as a bare BIGINT),
-- so there is nothing to seek on, and while idx_audit_logs_timestamp exists,
-- `timestamp < NOW()` selects essentially the whole table, so the planner will
-- seq-scan regardless -- the bound is here for correctness, not for speed.
--
-- THIS IS THE LARGER OF THE TWO BACKFILLS, and its population is a strict
-- SUPERSET of 162's. 162 additionally requires that the row NAMED one of the
-- usage columns (`tokens_used IS NOT NULL OR cost IS NOT NULL`), which excludes
-- every writer that does not bind them: the HITL approval writer above binds a
-- literal 0 for response_time_ms and names neither tokens_used nor cost, so its
-- rows are in THIS statement's population and not in 162's. Seeded as the
-- pre-#3424 writers actually stored history, this statement matched 140 rows
-- and 162 matched 100 of those same rows, with none matching 162 alone. So
-- size the `statement_timeout` and the expected bloat off THIS migration
-- rather than off 162.
--
-- It is a single statement in one transaction, so it takes ROW
-- EXCLUSIVE on the table for its duration and writes a new row version for
-- every matched row; expect bloat proportional to the match count until
-- autovacuum catches up. On a deployment with a `statement_timeout` small
-- enough to abort it, the migration runner records the failure in
-- schema_migrations and platform/agent/run.go calls log.Fatalf -- a boot loop,
-- not a skip. Raise statement_timeout for the migration session on a large
-- audit_logs.
--
-- THE GUARD BELOW COVERS THE COLUMNS, NOT JUST THE TABLE (#3427 R3) -- both
-- response_time_ms and, since the statement gained its time bound, timestamp.
-- PL/pgSQL plans a statement lazily, at first execution, so guarding only the
-- table's existence leaves a database where audit_logs exists WITHOUT one of
-- them raising at run time inside the DO block - and the migration runner
-- responds with log.Fatalf (platform/agent/run.go), a boot loop rather than a
-- skip. That
-- shape is not hypothetical: 059 creates audit_logs with `CREATE TABLE IF NOT
-- EXISTS` and then ALTERs org_id in specifically "for existing deployments
-- where audit_logs was created at runtime". The attribute probe keys off the
-- resolved pg_class OID rather than the relation name, so it cannot match a
-- same-named table in another schema, and pg_catalog is used rather than
-- information_schema because the latter is privilege-filtered and fails OPEN.

BEGIN;

-- Pins the time bound below to UTC for this transaction only (reverts at
-- COMMIT). Inert on the canonical timestamptz column; on a pre-142
-- timestamp-without-zone column it is what stops the operator's session zone
-- from moving the bound. See "THE BOUND IS PINNED TO UTC" above.
SET LOCAL TimeZone = 'UTC';

DO $$
DECLARE
    nulled_count INTEGER;
    audit_oid    OID;
    col_count    INTEGER;
BEGIN
    SELECT c.oid INTO audit_oid
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname = 'audit_logs' AND c.relkind = 'r';

    IF audit_oid IS NULL THEN
        RAISE NOTICE 'Migration 161: skipped, public.audit_logs does not exist yet (#3424)';
        RETURN;
    END IF;

    SELECT count(*) INTO col_count
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = audit_oid
       AND NOT a.attisdropped
       AND a.attnum > 0
       AND a.attname IN ('response_time_ms', 'timestamp');

    IF col_count <> 2 THEN
        RAISE NOTICE 'Migration 161: skipped, public.audit_logs is missing one of response_time_ms/timestamp (found % of 2) (#3424)', col_count;
        RETURN;
    END IF;

    UPDATE audit_logs
    SET response_time_ms = NULL
    WHERE response_time_ms = 0
      AND timestamp < NOW();
    GET DIAGNOSTICS nulled_count = ROW_COUNT;
    RAISE NOTICE 'Migration 161: nulled % fabricated zero response_time_ms row(s) (#3424)', nulled_count;
END $$;

COMMIT;
