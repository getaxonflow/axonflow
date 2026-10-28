# Hosted Starter product, data, limits, and economics acceptance

Status: engineering and security acceptance for #4488, 26 October 2026. This
is the controlling contract for the initial USD 9.99/month shared Hosted
Starter offer. It does not authorize a dedicated tenant stack at that price.

## Accepted product boundary

- One organization, two verified Portal people, all three typed outcome
  modules, one bounded JSON/API integration, 100 newly created cases per UTC
  calendar month, at most 100 unexpired cases, and 30-day primary retention.
- A case request is at most 16 KiB. Sidecar responses are at most 2 MiB. The
  durable sidecar admits at most 25 signed requests per organization per UTC
  minute. The monthly ledger is atomic and is not reduced by export or delete.
- The standard integration is the versioned typed case contract. It is not a
  generic document upload, browser plug-in with ambient authority, or live
  connection to a payment, refund, banking, CRM, or customer data system.
- Every action is a proposal or a persisted synthetic result. Hosted Starter
  has no adapter capable of moving money or writing to a customer system.
- The Portal displays the authoritative monthly case meter and remaining
  allowance. A database trigger, not UI text, rejects the 101st case.

`HostedIncludedEvents=1000` and `HostedBurstPerMinute=25` are the accepted
paid-governance parameters. These values must be applied only with the exact
module capability string and both #4486/#4488 acceptance markers. Safe-off
stacks retain zero for both values.

## Admitted data and customer terms

The shared tier accepts only opaque case, transaction, payment, order, customer,
payee, evidence and idempotency references; exact amount and currency fields;
status and reason codes; timestamps; country codes; numeric counters; and the
small enumerated evidence values in the versioned schemas. Submitted source
values are untrusted data, never instructions.

The shared tier prohibits names or contact profiles, card or bank-account data,
government identifiers, authentication material, health data, raw documents,
bulk exports, free-form customer correspondence, and data whose regulation or
contract requires a dedicated environment. The Portal presents this warning at
intake. Schema-extra fields are rejected rather than silently retained.

The accepted deployment stores and processes customer content in AWS
`us-east-1`. No EU-residency claim may be made for this offer. RDS, logs and
backups are encrypted with AWS-managed KMS boundaries; transport is TLS at
public ingress and private/loopback inside the task.

Initial Hosted Starter outcome workflows use the deterministic investigator
and do **not** send case content to an external model provider. Therefore the
accepted model token allowance and model cost are both zero. Enabling a model
client is a new data-flow change requiring provider/DPA acceptance, named
region, evaluated output quality, a token budget, and revised economics. If
OpenAI is later selected, its current API terms say API data is not used for
training by default and default abuse-monitoring logs may retain customer
content for up to 30 days; ZDR requires separate eligibility and configuration.
Those future controls must not be advertised as active merely because the
provider offers them. Sources: [OpenAI API data controls](https://developers.openai.com/api/docs/guides/your-data)
and [OpenAI enterprise privacy](https://openai.com/enterprise-privacy/).

## Lifecycle and deletion

| Data | Primary lifetime | Delete/export behavior | Residual lifetime |
| --- | --- | --- | --- |
| Typed case, evidence, state and embedded audit | Expires 30 days after creation | The owner can export all of their retained cases and delete a case immediately. Delete atomically removes its synthetic result. | Encrypted automated RDS backups expire within seven days. CloudFormation deletion/replacement does not retain a final snapshot. |
| Synthetic action idempotency result | Same bound case lifetime | Never returned across a different tenant, case, subject or binding. Deleted with the owner-authorized case or expiry sweep. | Encrypted automated RDS backups expire within seven days; no deploy-created manual snapshot is permitted for Community SaaS. |
| Monthly allowance ledger | Current month for enforcement; operational metadata may be retained for 13 months | Deleting a case never restores allowance. Contains organization ID, UTC month and count, not case content. | Backup window as above. |
| Minute rate window | Five-minute rolling cleanup | Not exported; contains organization ID, minute and count only. | Backup window as above. |
| Portal/sidecar logs | 30 days | Requests are not logged with bodies or secrets. | CloudWatch expiration at 30 days. |
| Person session and login links | Session expiry or explicit revocation; link is single-use and 15 minutes | Member removal revokes sessions and pending links transactionally. | Database backup window as above. |
| Service credential | Until rotation, revocation or organization termination | Secret is shown once; only a hash is stored. Rotation invalidates the prior value and revocation is immediate. | Hash may remain in backup for up to seven days but cannot authenticate against the live database. |

Organization termination must revoke sessions and service credentials, delete
Hosted case/action primary rows within 24 hours, and allow the seven-day
automated-backup window to expire. Community SaaS stack updates skip manual
pre-deployment snapshots, and stack deletion/replacement uses `Delete` rather
than retaining an unbounded final snapshot. Launch evidence must also show that
no legacy manual snapshot for the Hosted database remains. Re-registering an
email or organization label cannot revive the old identity, session,
credential, case, or entitlement.

## Economics snapshot and decision

Rates were checked on 26 October 2026. The observed staging topology is three
always-on Linux/x86 Fargate tasks at 1 vCPU/2 GiB, one Single-AZ PostgreSQL
`db.t3.medium`, and one ALB. The outcome sidecar uses 0.25 vCPU/0.5 GiB already
reserved inside the existing Portal task, so its incremental Fargate charge is
zero.

| Baseline item | Calculation | Monthly USD |
| --- | --- | ---: |
| Three Fargate tasks | 3 × 730 h × (`$0.000011244`/vCPU-s + 2 × `$0.000001235`/GiB-s) | 108.12 |
| PostgreSQL `db.t3.medium` | 730 h × `$0.072` | 52.56 |
| ALB fixed + one LCU | 730 h × (`$0.0225` + `$0.008`) | 22.27 |
| Measured shared baseline | Excludes usage-variable storage, logs, transfer and support | **182.95** |

AWS documents the Fargate rates in its [US East pricing example](https://aws.amazon.com/fargate/pricing/).
The RDS and ALB values were read from the AWS Price List API for
`us-east-1` on the acceptance date.

At the public USD 9.99 price, a standard EEA card has Stripe's published 1.5%
+ EUR 0.25 base fee and can add 2% when currency conversion is required
([Stripe Netherlands pricing](https://stripe.com/nl/pricing)). Using EUR/USD
parity as a conservative launch approximation, reserve USD 0.60 for payment
processing and conversion. The accepted deterministic workflow has zero
model-provider cost. Reserve USD 3.00 for three minutes of support at USD
60/hour and USD 0.50 for variable logs/storage/abuse. This leaves USD 5.89
before shared infrastructure and tax.

- Standalone economics are rejected: a dedicated stack cannot be sold for
  USD 9.99.
- Shared-platform marginal economics are accepted because the sidecar adds no
  task and no model bill. Full-cost break-even is roughly 32 paid organizations
  before variable storage; a 20% contribution target needs about 48. The
  operational launch floor is therefore 50 active paid organizations or an
  explicitly budgeted acquisition subsidy.
- At 50 paid organizations, the measured baseline allocation is about EUR/USD
  3.66 per organization and the modeled contribution is about USD 2.23 (22%)
  before tax and currency movement. Finance must replace the simple EUR/USD
  parity assumption with the booked monthly exchange rate.
- Buyer willingness-to-pay is not proven by a test-mode checkout. Public
  cohort activation remains a commercial decision and must not be represented
  as validated demand. This does not weaken the engineering/security gate.

Pricing drift is checked before changing `HostedPaidGateMode` to `enforce` and
monthly thereafter. A projected contribution below 20%, or support above three
minutes per organization, pauses new enrollments and triggers repricing or a
reduced package. Security or isolation controls are never relaxed to restore
margin.

## Acceptance tests

The release proof must show: 101st monthly case refusal after deleting earlier
cases; 26th signed request in one minute refusal; exact org/tenant binding;
cross-user and cross-tenant not-found behavior; owner-only export/delete;
separate reviewer approval and self-approval refusal; synthetic-only execution;
30-day expiry cleanup; credential issue/rotate/revoke; and the public
register/checkout/sign-in/revoke path. The exact-image deployed proof and the
independent security report are linked from the launch-gate document.
