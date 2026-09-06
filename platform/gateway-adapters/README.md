# AxonFlow Gateway PEP Adapters

Three gRPC policy-server surfaces that let an [agentgateway](https://agentgateway.dev)
or Envoy data plane call AxonFlow as its Policy Decision Point:

| Seam | Protocol | Governs |
|---|---|---|
| `ExtMcp` | agentgateway MCP authz | `tools/call` requests and their results |
| `ext_authz` | Envoy external authorization | whole requests, headers-only |
| `ext_proc` | Envoy external processing | request and response **bodies** |

The package holds **zero local policy logic**. Every verdict comes from the PDP
over `POST /api/v1/decide`; the adapter's job is to translate a gateway callout
into that call and enforce what comes back. See `doc.go` for the seam contracts
and the fail-closed semantics.

## Licence, and where this code lives

**BSL 1.1**, the same as the rest of this repository's `platform/` tree, and
**carried by the community mirror** (`getaxonflow/axonflow`) - see #3657 item 10.
Every hand-written file here carries the
`Copyright 2026 AxonFlow` / `SPDX-License-Identifier: BUSL-1.1` pair; the two
generated `.pb.go` stubs under `agentgateway/api/` deliberately carry none, for
the reason given in that directory's README.

It moved here from `ee/platform/agent/gateway_adapters` and into the root Go
module (`axonflow/platform`), so the import path is
`axonflow/platform/gateway-adapters` and no `ee` replace directive is involved.

**Tier entitlement stays platform-side at runtime.** The adapters hold a licence
key to *authenticate* to the PDP; they do not validate one and enforce no tier
of their own. A community deployment runs all three seams and receives whatever
verdicts a community PDP is entitled to give.

## The reported edition is the BUILD, not a constant

`gatewayadapters.Edition` is `edition.Current` - whichever edition this binary
was compiled as - and it goes out on the component's telemetry ping.

It used to be pinned to `enterprise`, on the argument that the component shipped
in one edition only. Moving into community-synced territory ended that: a pinned
constant would make every community deployment report `enterprise`, silently and
in the flattering direction for the adoption split. If a future image is built
without the enterprise tag but distributed *as* Enterprise, the fix is to add the
tag to that build - **not** to pin the constant back. `runtime-e2e/2886` asserts
the reported edition off the wire, from a captured ping, in both directions.

## Runtime proof does not travel to the community mirror

`runtime-e2e/` is excluded from the mirror **wholesale**, so the suites that
exercise this code do not appear in the community repository:

- `runtime-e2e/2886_agentgateway_pep_adapters` - all three seams through a real
  agentgateway against a live PDP, plus the per-surface counters, the client
  header and this component's reported edition.
- `runtime-e2e/2860_client_version_telemetry` - the adapter identifying itself
  to the engine, and its heartbeat's `org_id`.

**Runtime proof for this component lives in the enterprise repository's CI. The
community build is compiled and unit-tested by the mirror simulation** - the
staged community copy is `go vet`-ed and its Go tests run on every relevant PR,
and a positive control asserts these files actually reached the mirror rather
than the run merely being clean over a tree that lacks them.

A community-side executor for the runtime suites is a **recorded post-train
item**, not a silent absence. It is deliberately out of scope for the move.

## Building and running

```bash
# from the repo root - the ROOT module, not ee
cd platform && go build ./gateway-adapters/... && go test ./gateway-adapters/...

# the image (build context is the repo root)
docker build -f platform/gateway-adapters/cmd/axonflow-gateway-adapters/Dockerfile .
```

Configuration is `AXONFLOW_*` throughout - see `config.go` for the full set and
`cmd/axonflow-gateway-adapters/main.go` for the documented environment. Two
notes that cost debugging time if missed:

- `AXONFLOW_ORG_ID` and `AXONFLOW_LICENSE_KEY` are **all-or-nothing**. Both
  authenticate to an Enterprise PDP; neither is correct for a community one; one
  of them makes the process refuse to start.
- `AXONFLOW_ORG_ID` is *also* the `org_id` on this component's telemetry ping.
  An `axonflow-` org marks the row as an internal deployment rather than
  customer adoption (ADR-054), and the shared emitter's own fallback reads
  `ORG_ID`, which this binary never sets - so the value is passed explicitly.
