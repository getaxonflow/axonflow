# Detection corpus fixtures (schema v1)

Labeled FP/TP corpus for detection-quality scoring, **per detector category**
(#2815: recall and FP-rate are gated per category, never blended). These
fixtures are the shared contract between:

- the Go regression tests in `platform/shared/policy/capability_test.go` and
  `platform/agent/capability_scope_realpg_test.go` (#2801), and
- the corpus scoring script + CI gate (#2806 / #2815).

First-to-land sets this schema; later corpus additions extend these files (or
add sibling `<category>.json` files) rather than inventing a new shape.

## File shape

One JSON file per detector category:

```json
{
  "schema_version": 1,
  "category": "security-sqli",
  "description": "…",
  "cases": [ { …case… } ]
}
```

## Case fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique within the file. Kebab-case, prefixed `benign-` or `attack-`. |
| `label` | yes | `benign` (legitimate traffic) or `attack` (real payload). |
| `statement` | yes | The exact content evaluated. |
| `tool_identity` | yes | The identity the case realistically flows under (capability scoping input, #2801). `""` = no identity (full evaluation). |
| `expect` | yes | `allow`, `block`, or `detect` (= at least one policy match regardless of posture action; used for PII, whose action is posture-driven redact/warn/block). |
| `expected_policy_id` | no | The policy the case is built around; asserted when present. |
| `must_trigger_without_scoping` | no | `true` on benign cases that MUST still trigger their detector under an unclassified identity — self-validates that the corpus text still matches the pattern (i.e. the case is passing because of capability scoping, not because the detector rotted). |
| `source` | no | Provenance (e.g. `partner-report-2026-07-03-finding-1`). No partner names — these files sync to the public mirror. |

## Scoring semantics (#2815 — pin the denominator)

- **FP-rate-on-benign** = `label=benign` cases whose observed outcome is
  `block` ÷ all `label=benign` cases. Benign cases carry the tool identity
  the traffic realistically flows under.
- **Recall** = `label=attack` cases whose observed outcome satisfies `expect`
  ÷ all `label=attack` cases.
- `must_trigger_without_scoping` is a corpus-health check, not part of either
  metric: it re-runs the benign statement with an unclassified identity and
  requires a trigger.
- Posture: scoring assumes a blocking posture for the category under test
  (`SQLI_ACTION=block`, `PII_ACTION=block` for `expect: block` PII cases);
  under warn-postures `block` expectations degrade to `detect`.
