# OJK module: organization-scope upgrade note (#3242)

**Applies to:** deployments that already hold `ojk_breach_notifications` rows AND
send a `X-Org-ID` that differs from their `X-Tenant-ID`.

**Action required:** one operator-run `UPDATE`, below. Everything else in the
change is backward compatible.

---

## What changed

Every durable surface the OJK module owns is keyed on the ORGANIZATION: the
`ojk_*` tables declare `org_id`, their row-level-security policies read
`current_setting('app.current_org_id')`, and the module's `withOrgScope` helper
sets exactly that.

The HTTP handler's identity resolver did not match. It returned `X-Tenant-ID`
FIRST and fed it into all of them. On a deployment fronted by the AxonFlow agent
both headers are always present and, under a v9 enterprise license, hold
DIFFERENT values ([#3071]) - so the module wrote a TENANT identifier into an
ORG-labelled column and scoped every read by it.

`resolveOrgID` now resolves, in order:

1. `X-Org-ID`, trimmed. The agent Sets it from the cryptographically validated
   client credential, so a caller cannot choose it.
2. `X-Tenant-ID`, trimmed - ONLY when `X-Org-ID` is absent. Unreachable on the
   proxied path; it exists for direct-to-orchestrator callers in
   single-identifier deployments, where the two values are the same.

A request with neither header, or with a whitespace-only value, is refused with
HTTP 400 `missing_org`. No query runs with a blank scope.

## Who is affected

You are affected only if ALL THREE hold:

1. You have rows in `ojk_breach_notifications` (you have used
   `POST /api/v1/ojk/breach/notify`), AND
2. your deployment is fronted by the AxonFlow agent (the normal enterprise
   posture), AND
3. your organization identifier and your tenant identifier are DIFFERENT values.

Check (1) and (3) with:

```sql
SELECT DISTINCT org_id, tenant_id
  FROM ojk_breach_notifications
 ORDER BY org_id;
```

If that returns no rows, you are not affected. If `org_id` matches the
`X-Org-ID` your deployment sends, you are not affected.

## What breaks if you do nothing

Rows written under the previous behaviour are stored with the TENANT value in
`org_id`. The org-scoped read will not find them, so those breach notifications
become invisible to:

- the `breach_notifications` export section,
- the dashboard's breach counts,
- the Breach Notification readiness check, and
- `POST /api/v1/ojk/breach/acknowledge` (a 404).

The rows are not lost. They are mis-keyed.

## The repair

There is no reliable automated mapping - the stored row records the same value in
both columns, so the platform cannot tell an intentional single-identifier row
from a mis-keyed one. Run this yourself, substituting your identifiers:

```sql
-- Preview first. This must list ONLY rows you expect to re-key.
SELECT id, org_id, tenant_id, discovery_time, status
  FROM ojk_breach_notifications
 WHERE org_id = '<your-tenant-identifier>';

-- Then re-key them to the organization.
BEGIN;
UPDATE ojk_breach_notifications
   SET org_id = '<your-organization-identifier>'
 WHERE org_id = '<your-tenant-identifier>';
-- Confirm the count matches the preview before committing.
COMMIT;
```

Run it as the migration/owner role, not `axonflow_app_role`: the table is
RLS-enabled on `org_id`, so an app-role connection cannot see the rows it needs
to change unless `app.current_org_id` is set to the OLD value first.

`tenant_id` on those rows is descriptive only and needs no change.

## Not affected

- `audit_logs`-backed sections (policy violations, LLM calls, decision chains,
  cross-border transfers). Those rows carry the real organization in `org_id`,
  written by the agent and orchestrator audit writers, and the module's shared
  predicate additionally reaches rows with NO organization attribution by their
  tenant - so the single-identifier corpus stays visible.
- `indonesia_pii_detection_events` (new in enterprise migration 137 - there is no
  prior data).
- `hitl_approval_queue`, which the platform has always keyed on `org_id`.

[#3071]: https://github.com/getaxonflow/axonflow-enterprise/issues/3071
