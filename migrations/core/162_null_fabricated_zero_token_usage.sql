-- Migration 162: audit_logs.tokens_used / cost = 0 becomes NULL on rows that
-- recorded no provider usage
-- Date: 2026-08-22
-- Issue: #3427 (sub-finding M19)
--
-- The token and cost twins of migration 161, for the two columns #3424 did not
-- cover.
--
-- ONE AuditEntry PRODUCER RECORDS provider usage -- the orchestrator's
-- LogSuccessfulRequest, which records a delivered LLM response. (The cowork
-- OTLP ingest in platform/agent also records usage, but it INSERTs into
-- audit_logs directly rather than through an AuditEntry, and it already nulls
-- its own zeros; see guard 2.) Every other AuditEntry producer
-- leaves AuditEntry.TokensUsed and .Cost nil, and while those were plain value
-- types their zero VALUES were bound into the INSERT as literal 0s. The read
-- paths then scanned the columns into sql.Null* and took .Int64 / .Float64
-- without checking .Valid, so a governed BLOCK left the orchestrator as
-- `"tokens_used": 0, "cost": 0`, and the portal's expanded detail panel --
-- whose `!= null` guards exist precisely for the absent case, and were
-- therefore unreachable -- rendered "Tokens 0" and "Cost $0.0000" under a row
-- that recorded no provider usage. Both halves are fixed in #3427; this
-- statement clears the zeros the old writers already stored.
--
-- "RECORDS usage" IS NOT "HAS A ProviderInfo", and an earlier draft of this
-- header said the second. LogBlockedResponse also takes a *ProviderInfo, and it
-- runs AFTER the forward (the request reached the model; only the response was
-- withheld), so its rows are round trips that were paid for and discarded. It
-- records none of that usage, which is a gap in that writer tracked separately.
-- The consequence for THIS statement is only that its rows are in scope for the
-- same reason as the rest: they carry fabricated 0s that no measurement backs.
-- The consequence for the published contract is bigger and is fixed there --
-- docs/api/orchestrator-api.yaml no longer tells a reader that an omitted token
-- count means no provider was called.
--
-- THE PREDICATE, and why it cannot destroy a measurement. Two independent
-- guards, either of which would be sufficient:
--
--   1. Both columns must already be zero or absent
--      (COALESCE(...) = 0 on each, ANDed). This statement can therefore only
--      ever replace a 0 with NULL - it can never touch a non-zero value, in any
--      column, on any row, whatever the rest of the predicate does. An earlier
--      draft used `tokens_used = 0 OR cost = 0`, which on a hypothetical row
--      carrying (tokens 512, cost 0) would have nulled the 512 as collateral.
--      No writer in tree produces that shape, but a migration whose safety
--      rests on a census of today's writers is one new writer away from being
--      wrong.
--
--   2. The row must carry NEITHER a provider NOR a model. An earlier draft
--      justified this with "only LogSuccessfulRequest populates those", which
--      is false: platform/agent/cowork_otel_ingest.go also INSERTs into
--      audit_logs with provider "cowork_otel" and an OTLP-reported model. The
--      predicate is unaffected, because the property it actually needs is the
--      other direction -- EVERY writer that records usage also stamps a
--      provider. Both of them do (LogSuccessfulRequest binds the provider and
--      model it called; the cowork writer binds a constant "cowork_otel" on
--      every row, and already nulls its own zero tokens and cost). Every
--      remaining audit_logs writer -- the decide plane, the MCP writers, the
--      BatchWriter's block/failure/workflow/plan/tool-call producers and the
--      HITL approval writer (which names response_time_ms and neither usage
--      column) -- omits the usage columns entirely. That is the COMPLETE
--      census, not an illustrative list: outside tests, `INSERT INTO
--      audit_logs` resolves to five writers -- the orchestrator's
--      audit_logger.go (LogSuccessfulRequest plus the BatchWriter's
--      producers), platform/agent/cowork_otel_ingest.go, the decide plane in
--      decision_handler.go, the MCP writers in mcp_richer_context.go and
--      ee/platform/agent/hitl/repository.go -- and only the first two record
--      usage. So a row carrying neither a provider nor a
--      model passed through no writer that had usage to record, and its zeros
--      can only be a writer's zero value. This is also what keeps a GENUINE
--      zero: a locally hosted or free-tier model really does cost 0.0000, and
--      such a row keeps its provider, its model and its zeros.
--
-- Scope: whole-table, deliberately not tenant-scoped -- the value is wrong for
-- every tenant. audit_logs has no RLS (the tenant boundary is the SQL predicate
-- off the stamped header), so this runs as a plain UPDATE.
--
-- THE ROLLING-DEPLOY WINDOW is the same one migration 161 documents and this
-- migration does not close either: old images keep binding literal 0s until
-- they drain. The consequence here is milder than 161's, because nothing
-- AVERAGES these two columns -- they are rendered per row -- so a drain-window
-- row shows "Tokens 0" on one record rather than skewing an aggregate.
--
-- THE TIME BOUND, and why "re-run it freely" was wrong. An earlier draft of
-- this header said re-running was unconditionally safe because "a measured row
-- always names its provider and model". That is an argument from today's writer
-- census, and it is exactly the kind of argument guard 1 above exists because we
-- do not trust. The statement is therefore bounded to `timestamp < NOW()` --
-- inside this transaction NOW() is the transaction's start, so on the canonical
-- schema the statement cannot touch a row written after the migration began.
--
-- THE BOUND IS PINNED TO UTC, and an earlier draft's reasoning about why it did
-- not need to be was measured FALSE. Migration 142 makes this column
-- timestamptz and 142 sorts before this one, so the canonical shape compares
-- two absolute instants and no session setting can move it. But on a database
-- where audit_logs was created at runtime and never got 142 the column is
-- timestamp WITHOUT time zone, and comparing it to NOW() converts it by
-- interpreting the stored wall clock in the SESSION zone. That draft claimed
-- the resulting shift "only ever CLEARS FEWER rows, so the error is in the safe
-- direction". It does not: west of UTC it clears fewer, but EAST of UTC the
-- bound extends INTO THE FUTURE by the offset. Measured on exactly that shape,
-- Postgres 16, four UTC-stored rows at now-6h / now-1min / now+1min / now+3h:
-- session UTC matched 2, America/New_York matched 1, and Asia/Kolkata matched
-- all 4 -- including rows dated up to 5h30 ahead. Asia/Kolkata is not
-- hypothetical for this platform.
--
-- So the transaction pins its own zone (`SET LOCAL TimeZone = 'UTC'`, below).
-- That removes the operator's session zone from the result entirely: on the
-- pre-142 shape the stored wall clock is now read as the UTC it was written as,
-- and on the canonical timestamptz shape the setting is inert because that
-- comparison was never zone-dependent. Re-measured after the pin, all three
-- session zones match the same 2 of 4 rows.
--
-- WHAT THE BOUND IS AND IS NOT LOAD-BEARING FOR. Even pinned, the bound rests
-- on the pre-142 rows having been written as UTC: lib/pq binds the wall clock
-- of the writer's time.Location and a timestamp-without-zone column keeps it
-- verbatim. All five audit_logs writers in tree do bind UTC explicitly
-- (`time.Now().UTC()` in the orchestrator BatchWriter, the decide plane, the
-- MCP writers, the cowork OTLP ingest and the HITL approval writer, which is
-- out of THIS statement's population but wrote plenty of the history a
-- runtime-created table holds), so the premise is checked rather
-- than assumed -- but it is a premise about history, and history is what a
-- runtime-created table holds. SAFETY DOES NOT REST ON IT. Guards 1 and 2
-- above are what make this statement unable to destroy a measurement, and they
-- hold whatever the bound admits: guard 1 means only a 0 can ever be replaced,
-- guard 2 means only a row no usage-recording writer produced. The bound limits
-- the statement to history so that a future writer's rows are out of scope by
-- construction; it is a scope narrowing, not the safety argument.
--
-- IT ALSO SKIPS A NULL TIMESTAMP. `timestamp < NOW()` is NULL, not true, for a
-- row with no timestamp, so such a row keeps its fabricated zeros. Unreachable
-- on any canonical schema -- 059 declares `timestamp TIMESTAMP NOT NULL` and
-- nothing drops that constraint -- and recorded here only so the healed
-- population is stated rather than assumed.
--
-- A RE-RUN IS NOT AUTOMATICALLY SAFE, for the same reason 161's is not: a
-- second run picks up a LATER NOW() and so covers everything written since,
-- including whatever a future writer may have stored. The migration RUNNER
-- will not do that to you: it keys applied migrations on (version, name) alone
-- and never writes or compares schema_migrations.checksum, so this file runs
-- exactly once per database and a later edit to it is silently skipped
-- (161's header sets out why that skip is the behaviour a data backfill
-- wants). The risk is an operator running the file by hand. One clearing
-- drain-window residue later must supply the cutover explicitly, exactly as 161
-- instructs:
--
--   UPDATE audit_logs SET tokens_used = NULL, cost = NULL
--    WHERE COALESCE(tokens_used, 0) = 0 AND COALESCE(cost, 0) = 0
--      AND (tokens_used IS NOT NULL OR cost IS NOT NULL)
--      AND (provider IS NULL OR provider = '') AND (model IS NULL OR model = '')
--      AND timestamp < TIMESTAMPTZ '<the moment the last old task exited>';
--
-- COST. One sequential scan of audit_logs. None of the four columns this
-- statement reads or writes carries an index (059_runtime_tables_to_migrations
-- declares tokens_used as a bare INTEGER and cost as a bare DECIMAL(10,6)), and
-- while idx_audit_logs_timestamp exists, `timestamp < NOW()` selects
-- essentially the whole table, so the planner will seq-scan regardless -- the
-- bound is here for correctness, not for speed.
--
-- THIS IS THE SMALLER OF THE TWO BACKFILLS, and its population is a strict
-- SUBSET of 161's. Guard 1's `tokens_used IS NOT NULL OR cost IS NOT NULL`
-- limb requires the row to have NAMED one of the usage columns, which excludes
-- every writer that does not bind them: the HITL approval writer names
-- response_time_ms and neither usage column, and bound a literal 0 into it, so
-- its rows are in 161's population and not in this one. Seeded as the
-- pre-#3427 writers actually stored history, 161 matched 140 rows and this
-- statement matched 100 of those same rows, with none matching this statement
-- alone. So size the `statement_timeout` and the expected bloat off 161, which
-- is both the larger of the two and the one that runs first.
--
-- It is a
-- single statement in one transaction, so it takes ROW EXCLUSIVE on the table
-- for its duration and writes a new row version for every matched row; expect
-- bloat proportional to the match count until autovacuum catches up. On a
-- deployment with a `statement_timeout` small enough to abort it, the migration
-- runner records the failure in schema_migrations and platform/agent/run.go
-- calls log.Fatalf -- a boot loop, not a skip. Raise statement_timeout for the
-- migration session on a large audit_logs.

-- WRAPPED IN A pg_catalog EXISTENCE GUARD, on the TABLE and on all five
-- COLUMNS the statement names (tokens_used, cost, provider, model, timestamp).
-- Guarding the table alone is not enough: PL/pgSQL plans a statement lazily,
-- at first execution, so a database where audit_logs exists WITHOUT one of
-- these columns raises at run time inside the DO block. 059 creates audit_logs
-- with `CREATE TABLE IF NOT EXISTS` and then ALTERs in org_id specifically
-- "for existing deployments where audit_logs was created at runtime" -- so a
-- table with a different column set is a shape this repo has already met, not
-- a hypothetical. The failure mode is the boot loop described above, which is
-- strictly worse than skipping a backfill. Migration 161 carries the same
-- column-level guard over the TWO columns IT names, response_time_ms and
-- timestamp, and reports `found % of 2` (#3427 R3 extended it from a
-- table-only guard, and extended it again to cover timestamp when 161 gained
-- its time bound; two earlier drafts of this header understated it, first
-- saying 161 guarded the table only and then that it guarded one column).
-- information_schema is NOT used for the probe because it
-- is privilege-filtered and would fail OPEN, reporting "absent" for a table the
-- role merely cannot see and silently skipping the backfill; the attribute
-- probe keys off the resolved pg_class OID rather than the relation name, so it
-- cannot match a same-named table in another schema.
--
-- The row count is raised because a data migration that reports nothing gives
-- an operator no way to tell "no rows needed clearing" from "the predicate
-- matched nothing it should have" - and this predicate is deliberately narrow
-- enough that the difference matters. The skip is raised too, for the same
-- reason: a silent skip and a zero-row run look identical in the log.

BEGIN;

-- Pins the time bound below to UTC for this transaction only (reverts at
-- COMMIT). Inert on the canonical timestamptz column; on a pre-142
-- timestamp-without-zone column it is what stops the operator's session zone
-- from moving the bound -- east of UTC an unpinned bound reaches into the
-- future by the offset. See "THE BOUND IS PINNED TO UTC" above.
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
        RAISE NOTICE 'Migration 162: skipped, public.audit_logs does not exist yet (#3427)';
        RETURN;
    END IF;

    SELECT count(*) INTO col_count
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = audit_oid
       AND NOT a.attisdropped
       AND a.attnum > 0
       AND a.attname IN ('tokens_used', 'cost', 'provider', 'model', 'timestamp');

    IF col_count <> 5 THEN
        RAISE NOTICE 'Migration 162: skipped, public.audit_logs is missing one of tokens_used/cost/provider/model/timestamp (found % of 5) (#3427)', col_count;
        RETURN;
    END IF;

    UPDATE audit_logs
    SET tokens_used = NULL,
        cost = NULL
    WHERE COALESCE(tokens_used, 0) = 0
      AND COALESCE(cost, 0) = 0
      AND (tokens_used IS NOT NULL OR cost IS NOT NULL)
      AND (provider IS NULL OR provider = '')
      AND (model IS NULL OR model = '')
      AND timestamp < NOW();
    GET DIAGNOSTICS nulled_count = ROW_COUNT;
    RAISE NOTICE 'Migration 162: nulled % fabricated zero tokens_used/cost row(s) (#3427)', nulled_count;
END $$;

COMMIT;
