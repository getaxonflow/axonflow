# Governance Profiles (removed in v11)

`AXONFLOW_PROFILE` (`dev` / `default` / `strict` / `compliance`) and `AXONFLOW_ENFORCE` no longer exist. Since v11 no environment variable sets a detection action: the stored action of each matched policy decides. A deployment that still sets either variable keeps running; at boot the agent logs one warning per set variable and increments `axonflow_ignored_posture_env_total{name="<NAME>"}` on `/prometheus`.

This example now shows how to reach the posture a profile used to give you, with the two supported mechanisms:

1. **An organization's recorded override** (Enterprise). One row per category in `detection_action_overrides`, written through the customer portal API (session auth, `sso:configure` permission). Every write is audited to `admin_audit_log` and records `updated_by`. Agents pick up a change within `AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS` (default 60, minimum 5).
2. **A policy action change.** Edit the tenant policy, or create a system-policy override where your edition allows it. This is the only way to change sensitive-data detection, which has no override category.

## Out of the box (no override)

| Detection | Stored action (request / response) |
|-----------|------------------------------------|
| SQL injection (`sys_sqli_*`) | warn / warn |
| SSN, credit card (`sys_pii_ssn`, `sys_pii_credit_card`) | warn / redact |
| Passport, date of birth, email | log / redact |
| Singapore NRIC | warn / redact |
| Indonesian KTP (`sys_pii_indonesia_ktp`) | block / (request phase only) |
| Sensitive data (`sys_sensitive_*`) | warn / warn |
| Dangerous commands (`security-dangerous`) | block / (request phase only) |
| Prompt injection | block / redact |

This is closest to the old `default` profile: PII and SQL injection warn, dangerous commands block.

## Profile to override mapping

| Removed profile | `pii` | `sqli` | `dangerous_command` | Not reachable by an override |
|-----------------|-------|--------|---------------------|------------------------------|
| `dev` | `log` | `log` | `warn` | sensitive data (was `log`) |
| `default` | none | none | none | - |
| `strict` | `block` | `block` | `block` | sensitive data (was `block`) |
| `compliance` | `block` | `block` | `block` | sensitive data (was `block`) |

- `pii` reaches every `pii-*` policy category, `sqli` reaches `security-sqli`, and `dangerous_command` reaches `security-dangerous`. That category also holds the prompt-injection rows, so the `dev` mapping weakens those to `warn` too.
- The profiles also set a dangerous-query action. The `dangerous_query` override category maps to no policy category, so setting it changes nothing; this example leaves it out.
- `AXONFLOW_ENFORCE=<categories>` corresponded to a `block` override for each listed category.
- Code-backed detectors with no stored policy row (the checksum NIK/NPWP detector `indonesia_pii_protection` and the India PII detector `rbi_pii_protection`) block only under `pii=block` and add a redact obligation only under `pii=redact`. With no override they detect and record, and the stored policy rows decide.

## Running

Prerequisites: an Enterprise stack with the customer portal (for example `docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d`, portal on `localhost:8082`) and a portal session for a user holding `sso:configure`.

```bash
cd examples/governance-profiles

export AXONFLOW_PORTAL_URL=http://localhost:8082
export AXONFLOW_PORTAL_SESSION=<value of the axonflow_session cookie>

./test.sh strict     # record the overrides the strict profile implied
./test.sh default    # remove them: the stored policy actions decide again
```

The script writes (`PUT /api/v1/detection-posture/{category}`) or removes (`DELETE`) the `pii`, `sqli` and `dangerous_command` overrides for your organization, reads them back with `GET /api/v1/detection-posture`, and exits 1 if the recorded overrides differ from the profile's mapping.

## Expected output

```
=== Profile 'strict' as organization overrides (http://localhost:8082) ===
  PUT pii=block -> 200
  PUT sqli=block -> 200
  PUT dangerous_command=block -> 200
Recorded overrides:
  dangerous_command = block
  pii = block
  sqli = block
✓ Recorded overrides match profile 'strict'
```

## See also

- ADR-036 (`technical-docs/architecture-decisions/ADR-036-governance-profiles.md`), superseded in v11 by #3961
- [PII detection example](../pii-detection/) and [gateway mode](../integrations/gateway-mode/) for what the stored actions do on a request
