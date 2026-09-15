# PII Detection System

AxonFlow's PII (Personally Identifiable Information) detection system provides comprehensive protection for sensitive data in LLM interactions. The system uses a hybrid approach combining fast regex-based pattern matching with intelligent validation to minimize false positives while maintaining sub-millisecond latency.

> **What decides the runtime outcome of a PII match?** The action stored on the matched `pii-*` policy, unless the organization has recorded a `pii` detection-posture override, which replaces it. Since v11 (#3961) no environment variable or profile sets it: `PII_ACTION` and `AXONFLOW_PROFILE` are ignored with a boot WARN. See [Policy Actions and Detection-Posture Overrides](../governance/policy-action-authority.md) for the per-plane matrix, the shipped stored actions and the #3360 displacement advisory.

## What decides a PII match

A PII match is a FACT, not a verdict. The detectors find it; the anchored decision engine decides what happens to it
(PRD v11 §1.1, ADR-065). One evaluation decides each request, and one decides each LLM response on the orchestrator
response plane, so a match on its own neither blocks nor redacts anything: the organization's activated policy set
does, and the decision names the policy it acted on.

Redaction is an OBLIGATION that decision discharges, not a per-user permission lookup. When the decision carries a
content-redaction obligation, the plane that can satisfy it masks the matched spans and releases the content; a plane
that cannot satisfy it refuses instead of releasing unredacted content. The organization's typed policy document
carries the constraints and their obligations, and a recorded detection-posture override can replace the stored action
for a category (see the note above). A response the plane cannot decide is withheld, with the cause named, rather than
released by default.

Pattern matching and its validation live in the shared policy engine, not in a per-service detector:
`platform/shared/policy/validators.go` carries the semantic validators (Luhn for cards, the SSN area/group/serial
rules, MOD 97 for IBAN, the ABA routing checksum, Aadhaar, PAN, Singapore NRIC/FIN/UEN and postal), and
`platform/shared/policy/evaluator.go` carries the context-aware confidence scoring that keeps an order number from
reading as an SSN. Every plane runs the same scan over the same patterns, and every occurrence is validated rather
than only the first.

Images are the documented exception: OCR-extracted text is not PII-scanned on the production path today. See #4300.

## Where the detail lives

- [Policy Actions and Detection-Posture Overrides](../governance/policy-action-authority.md) - the per-plane matrix,
  the shipped stored actions, and what an organization override replaces.
- The typed policy authoring pages on the documentation site - how an organization's document carries constraints and
  obligations, and how an activation is built from it.
- ADR-065 and PRD v11 §1.1 - the decision plane itself: one engine authors every verdict, detectors author none.

> **This page is deliberately short.** It previously documented the orchestrator's regex `EnhancedPIIDetector`, which
> was removed in #4291 as dead code, together with the permission-based redaction model that went with it. Rather than
> leave a half-corrected page whose performance table and extension instructions referred to deleted files, the body
> was reduced to the model above. The full rewrite, including the supported-type table, the validation algorithms, the
> Singapore PII section and the compliance mapping, is tracked in #4301.
