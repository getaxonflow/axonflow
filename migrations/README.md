# Database migrations

This directory holds SQL migrations applied by the agent's migration runner
(`platform/agent/migration_helpers.go` → `collectMigrations` and friends). Each
migration is a numbered `.sql` file with an optional paired `_down.sql`. The
runner tracks applied migrations in the `schema_migrations` table keyed by
`(version, name)`.

## Directory layout

| Directory              | Versions          | When it runs (DEPLOYMENT_MODE)                                |
| ---------------------- | ----------------- | ------------------------------------------------------------- |
| `core/`                | 001 – ~099, 100+  | Every deployment mode.                                        |
| `enterprise/`          | 100 – 199         | `saas`, `in-vpc-*`. Not run in `community`/`community-saas`.  |
| `community-saas/`      | 085+              | `community-saas` only (try.getaxonflow.com hosted infra).     |
| `industry/healthcare/` | 250 – 299         | `saas`, `in-vpc-healthcare`.                                  |
| `industry/banking/`    | 300 – 349, 400+   | `saas`, `in-vpc-banking`.                                     |
| `industry/travel/`     | 200 – 249         | `saas`, `in-vpc-travel`.                                      |

See `platform/agent/migration_helpers.go` for the full DEPLOYMENT_MODE matrix.

Cross-directory version overlap is intentional (`core/100_*` and
`enterprise/100_*` apply under different modes). In-directory overlap is
NOT — see "Picking a migration number" below.

## Picking a migration number

The migration runner uses a `(version, name)` composite UNIQUE on
`schema_migrations` (post-PR #2249). That makes it tolerant of two files at
the same version with different names, BUT the apply order is
non-deterministic across runs and the runner cannot reason about
dependencies between same-version files. The v9 epic hit this bug three
times — two parallel sessions each branched off `origin/main`, each picked
the same next-available version, and both PRs merged before either rebased.

Before claiming a number:

1. **Branch off `origin/main` immediately before claiming**. Don't reuse a
   number you wrote down hours ago; another session may have landed
   between then and now.

2. **Run this in your target directory** to see what's already taken:

   ```bash
   ls migrations/core/ | grep -oE '^[0-9]+' | sort -u -n | tail -5
   ```

   Take the next integer after the last one printed.

3. **Open the PR draft EARLY** — even before the SQL is final. Other
   sessions discover your reservation via:

   ```bash
   gh pr list --search "migrations/core/NNN" --state open
   ```

4. **If `TestCoreMigrationDir_HasNoVersionDuplicates` fails when you push**,
   another session beat you to the number. Bump to the next available and
   rename your file with `git mv` (so history is preserved). Update any
   internal `-- Migration NNN:` headers and inline references.

## Down migrations

Every `NNN_<name>.sql` should ship with a paired `NNN_<name>_down.sql` that
reverses it. The runner does not auto-apply down migrations — they exist
for manual rollback during incident response. Keep them idempotent (DROP
... IF EXISTS, ALTER ... DROP NOT NULL guarded by an information_schema
probe, etc.).

## The historical same-version-different-name pairs

`migrations/core/` has four pairs from before the composite-key fix:

- `025_decision_chain.sql` + `025_hitl_oversight_queue.sql`
- `042_singapore_pii_patterns.sql` + `042_unified_execution_history.sql`
- `059_dangerous_command_policies.sql` + `059_runtime_tables_to_migrations.sql`
- `076_community_saas_recovery_tokens.sql` + `076_critical_system_policies_no_override.sql`

These are documented in `knownIntentionalVersionPairs` in
`platform/agent/migration_version_collision_test.go`. They work via the
composite `(version, name)` key, but they are historical baggage, not a
pattern to copy. New same-version pairs fail the
`TestCoreMigrationDir_HasNoVersionDuplicates` guard.
