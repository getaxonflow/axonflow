-- Migration 168: repair the wrapped list variable in the Content Safety Filter
-- Date: 2026-08-27
-- Purpose: One guarded data repair. The builtin template
--          `tpl_general_content_filter` (seeded by core/024) wrote its list
--          variable as `"value": ["{{prohibited_patterns}}"]`. Whole-string
--          variable references substitute with their type preserved, so that
--          shape substitutes to an array NESTED inside an array; the condition
--          evaluator stringifies the single inner element, and a
--          `contains_any` over it can never match. The template was inert on
--          every deployment that applied it.
--
-- WHY A NEW CORE MIGRATION AND NOT THE 024 EDIT ALONE
--
--   The seed source was corrected in place (core/024 now writes the unwrapped
--   `"value": "{{prohibited_patterns}}"`), which fixes every FRESH deployment
--   of any edition. But 024's seed is `ON CONFLICT DO NOTHING` and the
--   migration runner keys applied migrations on (version, name), so an
--   EXISTING deployment neither re-runs 024 nor rewrites the seeded row.
--   Enterprise-set deployments were repaired by enterprise/139 section 4b;
--   `community` and `community-saas` never run an enterprise migration
--   (platform/agent/migration_helpers.go), so this is the core-set repair for
--   the one community-reachable row. Same guarded-UPDATE shape as 139 4b:
--   the WHERE matches only the defective value, so a re-run, or a run on a
--   deployment that never seeded the row, is a no-op.
--
-- RLS: no new table, no new column; a data UPDATE on policy_templates only.

BEGIN;

UPDATE policy_templates
SET template = jsonb_set(template, '{conditions,0,value}', '"{{prohibited_patterns}}"'::jsonb),
    updated_at = NOW()
WHERE id = 'tpl_general_content_filter'
  AND template #> '{conditions,0,value}' = '["{{prohibited_patterns}}"]'::jsonb;

-- Verification: SCOPED TO THE ONE ROW THIS MIGRATION OWNS, deliberately.
--
-- Ownership scoping, not ordering: the runner merges every selected category
-- into ONE slice sorted by (version, name) (platform/agent/migration_helpers.go),
-- so in a mixed batch enterprise/139 (139) actually applies BEFORE this file
-- (168) and the 109 rows are already repaired when we run. The narrow scope is
-- kept anyway, as defence in depth: this migration asserts only the row whose
-- repair it owns, so no future re-ordering, partial set, or sibling defect can
-- make it abort an upgrade on rows that are another migration's job. (139's own
-- wide sweep is NOTICE-only; this check aborts, which is another reason it must
-- not look beyond its own row.)
--
-- The check reads the row's WHOLE document while the UPDATE touches one path:
-- a row edited by raw SQL to carry a wrapped variable at some other path fails
-- here loudly rather than shipping inert - there is no API write path to
-- policy_templates, so only a raw-SQL edit can produce that state.
DO $$
DECLARE
    wrapped INTEGER;
BEGIN
    SELECT COUNT(*) INTO wrapped FROM policy_templates
        WHERE id = 'tpl_general_content_filter'
          AND template::text LIKE '%["{{%';
    IF wrapped > 0 THEN
        RAISE EXCEPTION 'Migration 168: tpl_general_content_filter still carries a wrapped list variable after the repair'
            USING HINT = 'Inspect: SELECT template #> ''{conditions,0,value}'' FROM policy_templates WHERE id = ''tpl_general_content_filter''; the guarded UPDATE above should have rewritten exactly that value.';
    END IF;
    RAISE NOTICE 'Migration 168 verified: tpl_general_content_filter carries no wrapped list variable';
END
$$;

-- ---------------------------------------------------------------------------
-- Backfill: policies applied from templates BEFORE ApplyTemplate stamped a
-- category (#3528 item 2). Those rows landed with an empty category:
-- unfilterable in the portal, and a state the direct-create API refuses. The
-- affected population is exactly recoverable: policy_template_usage records
-- (template_id, policy_id) for every apply, and the mapping is the same
-- one-line rule the code now uses: 'dynamic-' + the template's catalog
-- category (empty catalog maps to general). Guarded on the empty category, so
-- rows a customer has since edited, and rows created by any other path, are
-- untouched; re-runs are no-ops.
UPDATE dynamic_policies dp
SET category = 'dynamic-' || COALESCE(NULLIF(pt.category, ''), 'general'),
    updated_at = NOW()
FROM (
    SELECT DISTINCT ptu.policy_id, ptu.template_id
    FROM policy_template_usage ptu
    WHERE ptu.policy_id IS NOT NULL
) u
JOIN policy_templates pt ON pt.id = u.template_id
WHERE dp.policy_id = u.policy_id
  AND COALESCE(dp.category, '') = '';

-- Backfill verification, scoped to the population the backfill owns: rows that
-- came from a template apply. Empty-category rows with NO usage record are not
-- this migration's to judge (the import path can still write them; routed on
-- epic #3528).
DO $$
DECLARE
    remaining INTEGER;
BEGIN
    SELECT COUNT(*) INTO remaining
      FROM dynamic_policies dp
     WHERE COALESCE(dp.category, '') = ''
       AND EXISTS (SELECT 1 FROM policy_template_usage ptu
                    WHERE ptu.policy_id = dp.policy_id);
    IF remaining > 0 THEN
        RAISE EXCEPTION 'Migration 168: % template-applied dynamic_policies row(s) still carry an empty category after the backfill', remaining;
    END IF;
    RAISE NOTICE 'Migration 168 verified: every template-applied policy row carries a category';
END
$$;

COMMIT;
