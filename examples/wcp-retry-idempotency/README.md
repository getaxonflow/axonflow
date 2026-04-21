# WCP retry_context + idempotency_key examples

Hardened end-to-end validators for the Workflow Control Plane's retry-aware
surface:

- `retry_context` on every `StepGateResponse` — unambiguous retry state
  (counters, prior-completion enum, timestamps, last decision) replacing
  the ambiguous `cached: bool` signal.
- Caller-supplied `idempotency_key` on `/gate` + `/complete` — business-level
  key with strict match validation (`HTTP 409 IDEMPOTENCY_KEY_MISMATCH` on
  conflict).
- `step.*` condition fields for the dynamic policy engine — `gate_count`,
  `completion_count`, `prior_completion_status`, `prior_output_available`,
  `last_decision`, `first_attempt_age_seconds`, `idempotency_key`.

Every example **asserts actual behaviour** — counter values, enum strings,
error envelope fields, recovered payloads — and exits non-zero on any
mismatch. They are release-gate tests, not smoke demos.

The public API contract these examples target is documented in the
`/api/v1/workflows/.../gate` and `/api/v1/workflows/.../complete` paths
of `docs/api/orchestrator-api.yaml`.

---

## Layout

```
examples/wcp-retry-idempotency/
├── README.md                      ← you are here
├── community/                     ← Community-tier primitives (any tier)
│   ├── http/        raw HTTP (no SDK dependency)
│   ├── go/          Go SDK
│   ├── typescript/  TypeScript SDK
│   ├── python/      Python SDK (3.10+)
│   └── java/        Java SDK
└── evaluation/                    ← Evaluation-tier retry-aware policy
    ├── http/        authors a retry-aware policy + verifies it fires
    ├── go/          same flow via Go SDK
    ├── typescript/  same flow via TypeScript SDK
    ├── python/      same flow via Python SDK
    └── java/        same flow via Java SDK
```

---

## Community-tier examples

What each exercises (identical across all 5 languages):

1. **First-gate invariants** — `gate_count == 1`, `completion_count == 0`,
   `prior_completion_status == "none"`, `first_attempt_at == last_attempt_at`,
   `last_decision == decision` (first-call invariant).
2. **Re-gate post-complete** — after `/complete`, a subsequent `/gate`
   returns `gate_count == 2`, `completion_count == 1`,
   `prior_completion_status == "completed"`, `prior_output_available == true`.
3. **Gated-not-completed** — gate without complete, then re-gate → the
   "uncertain territory" state: `prior_completion_status ==
   "gated_not_completed"`, `completion_count == 0`. This is the signal an
   agent needs to reconcile with the downstream system before re-executing.
4. **`?include_prior_output=true`** — opt-in populates
   `retry_context.prior_output` with the payload passed to `/complete`.
5. **idempotency_key round-trip** — key supplied on gate echoes on every
   subsequent `retry_context.idempotency_key`; key on complete must match
   or return 409.
6. **409 IDEMPOTENCY_KEY_MISMATCH** — typed error surfaced in each SDK
   with `expected_idempotency_key`, `received_idempotency_key`,
   `workflow_id`, `step_id` all populated.

### Running any community example

```bash
# From the repo root, boot a stack (community, evaluation, or enterprise):
./scripts/setup-e2e-testing.sh community
source /tmp/axonflow-e2e-env.sh
export AXONFLOW_BASE_URL=http://localhost:8080

# HTTP (no SDK):
cd examples/wcp-retry-idempotency/community/http && go run .

# Go SDK:
cd ../go && go run .

# TypeScript SDK:
cd ../typescript && npm install && npx ts-node index.ts

# Python SDK (requires Python 3.10+):
cd ../python && python3.11 -m venv .venv && source .venv/bin/activate && \
  pip install axonflow && python main.py

# Java SDK:
cd ../java && mvn -q compile exec:java \
  -Dexec.mainClass="com.getaxonflow.examples.WcpRetryIdempotency"
```

Each example prints ✔ per assertion block and ends with
`All assertions passed ✔`. Non-zero exit on failure.

---

## Evaluation-tier example

> ⚠️ **Evaluation or Enterprise license required.**
>
> Policies that reference `step.*` retry-aware condition fields require
> the Evaluation tier or higher. On a Community license, `POST
> /api/v1/policies` returns `HTTP 403 FEATURE_REQUIRES_EVALUATION_LICENSE`
> with a link to get a free Evaluation license. Same gate applies on the
> update and import paths. Boot the stack with
> `./scripts/setup-e2e-testing.sh evaluation` (or `enterprise`) before
> running these examples.

Each example walks the same three-gate story:

1. **First gate (default `retry_policy`)** — decision `allow`,
   `gate_count == 1` (policy's `gate_count > 1` condition does NOT match).
2. **Second gate (default `retry_policy`)** — decision `allow`,
   **cached**. Cache short-circuits the policy engine; retry-aware
   conditions do **not** fire even though `gate_count == 2` and
   `prior_completion_status == "gated_not_completed"`. This assertion
   locks the current cache semantics — if a future change makes
   retry-aware policies fire on cached retries, this line fails and
   prompts a deliberate update.
3. **Third gate (`retry_policy: "reevaluate"`)** — forces fresh policy
   evaluation; all three conditions now match, policy fires, decision
   becomes `require_approval`.

**Important for policy authors:** retry-aware dynamic policies only
fire when the caller opts into reevaluation via `retry_policy:
"reevaluate"`. Default-idempotent retries hit the cache and bypass the
policy engine. If your intent is "every retry reconsiders the
decision", pass `reevaluate` on every gate call after the first.

### Running

```bash
./scripts/setup-e2e-testing.sh evaluation   # or enterprise
source /tmp/axonflow-e2e-env.sh
export AXONFLOW_BASE_URL=http://localhost:8080

# HTTP (no SDK):
cd examples/wcp-retry-idempotency/evaluation/http && go run .

# Go / TypeScript / Python / Java — same pattern as community/, but under evaluation/:
cd ../go        && go run .
cd ../typescript && npm install && npx ts-node index.ts
cd ../python    && python3.11 -m venv .venv && source .venv/bin/activate && \
  pip install axonflow && python main.py
cd ../java      && mvn -q compile exec:java \
  -Dexec.mainClass="com.getaxonflow.examples.EvalRetryAware"
```

Each example authors its policy at setup and tears it down in a
defer/finally block, so re-runs are clean.

---

## Related

- API reference: [`docs/api/orchestrator-api.yaml`](../../docs/api/orchestrator-api.yaml)
- CHANGELOG: the `[7.3.0]` entry describes the full surface area and
  the edition split (Community primitives / Evaluation retry-aware
  policy conditions / Enterprise cross-workflow features in a future
  release).
