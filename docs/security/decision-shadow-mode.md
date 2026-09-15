# Decision Mode and the Decision Shadow (retired in v11)

**Platform Version:** v11.0.0. v11.0.0 retires the decision mode: it and its shadow observer shipped in v10.3.0, and v10.4.0 added `enforce`.

**Status:** Retired. This page states what replaced them and what a deployment that configured them has to change.

**Applies To:** All deployment modes (Community and Enterprise), on both the agent and the orchestrator.

---

## What Changed

In v10.3 and v10.4 the legacy engines decided every plane. The decision mode chose, per organization, whether the ADR-065 decision plane was only observed beside them (`shadow`) or authored the verdict (`enforce`), and the shadow observer recorded where the two engines differed.

**v11 has no decision mode and no comparison.** The ADR-065 decision plane authors the verdict on every scope it enforces, on every deployment and edition, and nothing selects or observes another engine. There is no `off`, no `shadow`, no `enforce`, no per-organization opt-in or opt-out, and no process flag (PRD v11 §1.1, §1.3). The two engines are different models, so a shipped policy that behaves differently from v10.x is documented rather than reconciled.

Which scopes the plane authors is reported by the running process rather than listed here:

```bash
curl -s http://localhost:8080/health | jq .decision
# { "enforcing_planes": ["decide", "gateway_request", "mcp:response", "openai_compatible", "proxy_request"] }
```

A scope that is not listed is still decided by the legacy engines until it cuts over ([#3564](https://github.com/getaxonflow/axonflow-enterprise/issues/3564)). `/api/request` is one anchored pass since #4253: its second pass, the legacy tier engine, is retired with the `proxy_tier` plane, so no scope the agent enforces carries a legacy verdict, and no response, audit row or counter says `engine=legacy`.

## If You Configured the Mode

| What you set | What v11 does | What to do |
|---|---|---|
| Any of `AXONFLOW_DECISION_SHADOW_MODE`, `_PLANES`, `_SAMPLE_RATE`, `_QUEUE_DEPTH`, `_WORKERS`, `_MATCH_LOG_EVERY`, `_REALM`, `_CONTENT_TARGET`, set to a non-empty value on the agent or the orchestrator | **The process refuses to boot**, and the message names every one that is set | Remove the variable. An empty value is accepted, because earlier compose files and templates pass these variables through empty |
| The CloudFormation parameters `DecisionShadowMode`, `DecisionShadowPlanes`, `DecisionShadowSampleRate`, `DecisionShadowWorkers`, `DecisionShadowQueueDepth`, `DecisionShadowMatchLogEvery` | Removed from both templates. CloudFormation rejects a stack update that passes a parameter the template does not declare | Remove them from your parameter overrides before the update |
| `decision_shadow_mode` or `decision_shadow_planes` in `PUT /api/v1/admin/organizations/{org_id}/identity-settings` (Enterprise) | **Refused with a 400** that names the field | Remove the field from the request |
| A stored per-organization `decision_shadow_mode` or `decision_shadow_planes` value | Ignored. The columns stay in the schema, unread, and are dropped in v12: during a rolling deploy a v10.4 customer portal, which writes both columns by name, still runs against the migrated schema | Nothing |
| Dashboards or alerts on `axonflow_decision_shadow_*` | The series are no longer exported | Remove the panels and alerts |

The variables are refused rather than ignored for a reason. Each one chose what decided a request, or whether two engines were compared. A deployment that sets one believes it still does that. A container that will not start is noticed at once; a variable ignored with a log line leaves the deployment running in a posture its own configuration misdescribes.

## Reading Who Decided a Verdict

Every response on an enforcing scope carries three fields, and the decision's audit row carries the same three:

| Field | Values | Meaning |
|---|---|---|
| `engine` | `anchored`; `legacy` only on `/api/request` | which engine authored the verdict |
| `subject_type` | `User`, `Client`, `Service` | the kind of principal the decision was evaluated for |
| `policy_bundle` | a digest | the bundle that decided: the organization's published document, or its implicit bundle |

The OpenAI-compatible route returns them as the headers `X-AxonFlow-Engine`, `X-AxonFlow-Subject-Type` and `X-AxonFlow-Policy-Bundle`, because its body is OpenAI's. The `mode` field is gone from the wire and from the audit row, and nothing replaces it: there is no mode to report.

When a tool's registered capability excludes a detector from a request, the audit row also carries `capability_scoped`, naming the tool and the detectors that did not apply. A control that reads such a detector is decided as not matching, and the row says why.

## Callers With Only a Client Credential

Where a deployment verifies no per-user identity (Community, Community-SaaS), or a request carries none, the **client credential is the principal** the decision is evaluated for. It is recorded as `subject_type=Client` (PRD v11 §1.6). On Community and Community-SaaS a user token is not an identity at all, and a token sent there is ignored. The OpenAI-compatible route does not honour OpenAI's `user` member as an identity.

**A user token that fails verification is still refused.** Admission is for the absence of a user identity, never for a bad one. A deployment that verifies user tokens answers a token that does not verify with a 401 at authentication. The decision plane's user door refuses the same token even when it reaches the plane: the credential is never admitted in its place.

## An Organization That Has Published Nothing

An organization with no active typed policy document is decided by its **implicit bundle**, from its first request. The bundle is:
- the shipped system corpus, restricted to the controls that bind on the scope;
- the deployment's baseline permission pack;
- the organization policy template, restricted to the same scope.

It is composed and signed per process, and never persisted. Its digest is the `policy_bundle` on the wire.

Publishing a document replaces the implicit bundle by digest, with two rules:
- **The baseline permission pack is composed beside every document.** The pack's policies that the document does not already carry are added to it.
- **The template is not added to a published document.** A document carries exactly the template controls its author kept. The publish and promote responses report the ones it omits (`template_omissions`).

## Related

- `technical-docs/product/PRD_V11_POLICY_DECISION_PLANE.md` §1: the v11 definition this page implements (enterprise repository)
- ADR-065, amendment 2026-09-11 (third): no decision mode, credential-only callers admitted
- `docs/security/identity-compat-mode.md`: the identity comparison's retirement
- `CHANGELOG.md`, v11.0.0
