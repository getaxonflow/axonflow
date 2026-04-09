# Governance Profiles Example

Demonstrates the v6.2.0 `AXONFLOW_PROFILE` env var by running the same
test query against an agent in `dev`, `default`, `strict`, and
`compliance` profiles, and showing how the response changes.

## What this example shows

- **`dev` profile** — every detection is logged but nothing blocks. PII
  in the query is visible in the response. Useful for local evaluation.
- **`default` profile** — PII detection warns (visible in response
  metadata) but the data flows through unchanged. SQLi patterns warn
  but do not block. Dangerous shell commands like `rm -rf /` are
  blocked.
- **`strict` profile** — PII is blocked. SQLi patterns are blocked.
  Equivalent to the v6.1.0 default behavior.
- **`compliance` profile** — strict + hard-block on regulated PII
  (HIPAA / GDPR / PCI / RBI / MAS FEAT).

See `docs/guides/governance-profiles.md` for the full action matrix.

## Prerequisites

```bash
# From the enterprise repo root:
./scripts/setup-e2e-testing.sh community
```

This brings up an AxonFlow agent on `http://localhost:8080` in community
mode and writes credentials into `examples/governance-profiles/.env`.

## Running

```bash
cd examples/governance-profiles

# Run all four profiles in sequence
./test.sh
```

The script restarts the agent with each profile and asserts the expected
behavior. It is idempotent — re-running tears down between profiles.

## Expected output

```
=== Profile: dev ===
[PROFILE] dev: PII flows through, detection logged but not flagged
✓ PII detected (logged): email
✓ PII detected (logged): phone
✓ Query approved
✓ Response contains original PII (no redaction)

=== Profile: default ===
[PROFILE] default: PII flagged with warn, dangerous commands block
✓ PII detected (warn): email
✓ PII detected (warn): phone
✓ Query approved (warn does not block)
✓ Response contains warn flags in policy_info

=== Profile: strict ===
[PROFILE] strict: PII blocked
✓ Query rejected with PII policy violation
✓ Response status: 403

=== Profile: compliance ===
[PROFILE] compliance: HIPAA + PCI categories hard-block
✓ Query rejected with compliance policy violation
✓ Response status: 403
```

## See also

- ADR-036 (`technical-docs/architecture-decisions/ADR-036-governance-profiles.md`)
- Migration 066 (`migrations/core/066_relax_default_policy_actions.sql`)
- Public docs: `docs/guides/governance-profiles.md`
