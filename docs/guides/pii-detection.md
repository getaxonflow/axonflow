# PII Detection System

AxonFlow detects PII (Personally Identifiable Information) in the requests and responses it governs. Each detector is a pattern plus a validator: the pattern finds candidates, and the validator (a checksum, a format rule, or a label required next to the value) decides which candidates count.

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
`platform/shared/policy/validators.go` carries the validators: the checksums (Luhn for cards, MOD 97 for IBAN, the
ABA routing checksum for bank accounts), the format rules (the SSN area/group/serial rules, PAN's entity letter), and
the label gates (Aadhaar, passport, date of birth, Singapore NRIC/FIN, numeric UEN and postal code count only with a
label next to the value; the shipped Aadhaar row runs no Verhoeff check). `platform/shared/policy/evaluator.go`
carries the one scan (`ScanAccepted`), which hands each validator 50 characters of context either side, so an order
number does not read as an SSN. Every plane runs the same scan over the same patterns, and every occurrence is
validated rather than only the first.

Images: text the local OCR analyzer extracts is scanned by the same detectors (#4300). The production factory injects
`NewEnginePIIDetector` (`platform/orchestrator/media/local_ocr.go:158`), which runs the shared engine over the text PII
categories and yields a media signal (`platform/orchestrator/media/pii_scan.go:87`); the decision over it is the
anchored engine's (`sys_media_pii_block`). The cloud image analyzers return no extracted text, so nothing is scanned
for PII there.

## Where the detail lives

- [Policy Actions and Detection-Posture Overrides](../governance/policy-action-authority.md) - the per-plane matrix,
  the shipped stored actions, and what an organization override replaces.
- The typed policy authoring pages on the documentation site - how an organization's document carries constraints and
  obligations, and how an activation is built from it.
- ADR-065 and PRD v11 §1.1 - the decision plane itself: one engine authors every verdict, detectors author none.
- The documentation site's PII Detection & Redaction page (`/docs/security/pii-detection/`, from v11.1.0) - the
  supported-type table with what each validator requires, the label gates, the Singapore section, the code-backed
  India and Indonesia validators, and the compliance mapping (#4301).

> **This page is deliberately short.** It previously documented the orchestrator's regex `EnhancedPIIDetector`, which
> was removed in #4291 as dead code, together with the permission-based redaction model that went with it. Rather than
> leave a half-corrected page whose performance table and extension instructions referred to deleted files, the body
> was reduced to the model above. The full page - the supported-type table, the validation rules, the Singapore PII
> section and the compliance mapping - is the documentation site's (#4301).
