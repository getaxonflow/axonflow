-- Migration 173: seed the five sys_media_* governance policies
-- Date: 2026-09-08
-- Purpose: Put the platform's media governance rules in a migration, where
--          every other platform-shipped policy already lives.
-- Related: #3786 (one authoring model), migrations/core/172 (the revoke that
--          makes this necessary), v11 decision D1.
--
-- EDITION: COMMUNITY (mirrored). These are platform-shipped rules and they
-- govern both editions.
--
-- ---------------------------------------------------------------------------
-- WHY THIS EXISTS, AND WHY IT IS NOT A SECTION OF 172
-- ---------------------------------------------------------------------------
--
-- These five rows have never been in a migration. They are seeded ONLY by
-- platform/orchestrator/db_dynamic_policies.go's seedSystemMediaPolicies, on
-- the application connection, and its caller treats a failure as a log line:
--
--     log.Printf("Warning: failed to seed default data: %v", err)
--
-- migrations/core/172 makes dynamic_policies SELECT-only to the application
-- roles, so on a deployment connecting as one that INSERT is refused. On an
-- EXISTING stack nothing changes - the Go seeder succeeded long ago and
-- ON CONFLICT DO NOTHING has been a no-op ever since. On a FRESH stack the
-- five rows would simply never appear, and NSFW blocking, violence warning,
-- biometric logging, media PII blocking and sensitive-document warning would
-- silently not exist.
--
-- That is the shape worth naming: invisible on every stack anyone would
-- inspect, because every stack anyone would inspect already has the rows, and
-- it bites only deployments created after the upgrade.
--
-- IT IS ITS OWN MIGRATION because 172's down is a REAL rollback - it restores
-- privileges core/098 granted - and a data seed inside it would make that down
-- ambiguous. Deleting these rows on a rollback would remove policies every
-- existing stack legitimately holds; not deleting them would mean 172's down
-- no longer reverses 172's up. A privilege change and a data seed have
-- different rollback semantics and do not belong in one file.
--
-- ---------------------------------------------------------------------------
-- FIDELITY
-- ---------------------------------------------------------------------------
--
-- Every value below is transcribed from seedSystemMediaPolicies, which is the
-- only thing that has ever created these rows: the same policy identifiers,
-- names, descriptions, categories, conditions, actions and priorities, the
-- same `media` policy_type and `system` tier, and the same 'global' wildcard
-- sentinel in tenant_id, client_id and org_id - which the read side recognises
-- as matching every tenant.
--
-- ON CONFLICT DO NOTHING, so this is a no-op wherever the Go seeder already
-- ran, and re-appliable.
--
-- The Go seeder is deliberately LEFT IN PLACE. Removing it is a change to a
-- running orchestrator's boot path and belongs with the wider retirement of
-- that seed path (#3565), not with a migration whose job is to make sure the
-- rows exist. Both are idempotent on the same identifiers, so they cannot
-- disagree.

BEGIN;

INSERT INTO dynamic_policies (
    policy_id, name, description, policy_type, category, tier,
    conditions, actions, tenant_id, client_id, org_id, priority, enabled,
    version, created_by, updated_by, created_at, updated_at
) VALUES
    ('sys_media_nsfw_block', 'NSFW Content Blocking',
     'Blocks media with high NSFW confidence scores', 'media', 'media-safety', 'system',
     '[{"field":"media.nsfw_score","operator":"greater_than","value":0.8}]'::jsonb,
     '[{"type":"block","config":{"reason":"Media blocked: NSFW content detected (score > 0.8)"}}]'::jsonb,
     'global', 'global', 'global', 1000, true, 1, 'system', 'system', NOW(), NOW()),
    ('sys_media_violence_warn', 'Violence Content Warning',
     'Alerts on media with high violence scores', 'media', 'media-safety', 'system',
     '[{"field":"media.violence_score","operator":"greater_than","value":0.7}]'::jsonb,
     '[{"type":"alert","config":{"message":"Violence detected in media (score > 0.7)"}},{"type":"log","config":{}}]'::jsonb,
     'global', 'global', 'global', 950, true, 1, 'system', 'system', NOW(), NOW()),
    ('sys_media_biometric_log', 'Biometric Data Audit',
     'Logs media containing biometric data for compliance audit', 'media', 'media-biometric', 'system',
     '[{"field":"media.has_biometric_data","operator":"equals","value":true}]'::jsonb,
     '[{"type":"log","config":{"message":"Biometric data detected in media"}}]'::jsonb,
     'global', 'global', 'global', 900, true, 1, 'system', 'system', NOW(), NOW()),
    ('sys_media_pii_block', 'Image PII Blocking',
     'Blocks media containing personally identifiable information', 'media', 'media-pii', 'system',
     '[{"field":"media.has_pii","operator":"equals","value":true}]'::jsonb,
     '[{"type":"block","config":{"reason":"Media blocked: PII detected in image content"}}]'::jsonb,
     'global', 'global', 'global', 950, true, 1, 'system', 'system', NOW(), NOW()),
    ('sys_media_sensitive_doc_warn', 'Sensitive Document Detection',
     'Alerts when sensitive documents are detected in media', 'media', 'media-document', 'system',
     '[{"field":"media.is_sensitive_document","operator":"equals","value":true}]'::jsonb,
     '[{"type":"alert","config":{"message":"Sensitive document detected in media"}},{"type":"log","config":{}}]'::jsonb,
     'global', 'global', 'global', 900, true, 1, 'system', 'system', NOW(), NOW())
ON CONFLICT (policy_id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Self-verification BEFORE COMMIT
--
-- NO row_security SETTING HERE, and the reason is worth stating because the
-- obvious defensive line is wrong in both directions.
--
-- dynamic_policies is ENABLE (not FORCE) ROW LEVEL SECURITY (core/018), and a
-- migration runs as the table OWNER - for whom an un-FORCEd policy does not
-- apply at all. So the COUNT below sees every row without any setting, and an
-- earlier version of this block said the opposite ("a bare COUNT would report
-- 0 on a populated table"), which is measurably false.
--
-- `SET LOCAL row_security = off` would also be the wrong remedy if it were
-- needed. It does not bypass RLS: for a role that IS bound, it converts the
-- affected query into `ERROR: query would be affected by row-level security
-- policy` (42501), as migrations/enterprise/142's down migration already
-- records. It is a no-op for the population that runs this file and a hard
-- error for the population that would need it.
--
-- REVISIT WHEN dynamic_policies gains FORCE ROW LEVEL SECURITY. This tree has
-- been adding it steadily (core/099, 105, 106, 107, enterprise/155), and on
-- that day the owner IS bound, this COUNT starts returning 0, and the
-- verification below fails loudly - which is the correct outcome and the
-- reason not to pre-emptively silence it here.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    n INTEGER;
BEGIN
    SELECT COUNT(*) INTO n FROM dynamic_policies
    WHERE policy_id IN ('sys_media_nsfw_block', 'sys_media_violence_warn',
                        'sys_media_biometric_log', 'sys_media_pii_block',
                        'sys_media_sensitive_doc_warn');
    IF n <> 5 THEN
        RAISE EXCEPTION 'Migration 173 failed: % of 5 system media policies are present', n;
    END IF;
    RAISE NOTICE 'Migration 173 verified: all 5 system media governance policies are present.';
END $$;

COMMIT;
