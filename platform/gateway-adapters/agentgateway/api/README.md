# Vendored agentgateway ExtMcp Go stubs

Generated Go bindings for the agentgateway `ExtMcp` gRPC contract
(`agentgateway.dev.ext_mcp.ExtMcp`), vendored **byte-identical** from the
upstream repository — they are NOT hand-transcribed and must never be edited
here.

## Licence

**The two `.pb.go` files carry no licence header, and must not be given one by
hand.** They are generated: a header added here is erased by the next
regeneration, so it would be a claim that silently stops being true. The
licence is stated here instead, beside them, where it survives.

These files are vendored from agentgateway (Apache-2.0 upstream) and, as part
of this repository's community-synced tree under `platform/`, are distributed
under **BSL 1.1** with everything else there — see the repository's top-level
`LICENSE`. Every hand-written file in `platform/gateway-adapters/` carries the
`Copyright 2026 AxonFlow` / `SPDX-License-Identifier: BUSL-1.1` pair directly;
the Dockerfile and the READMEs carry none, matching `platform/agent/Dockerfile`
and the repository README.

No lint enforces any of this today, which is precisely why it is written down.

| | |
|---|---|
| Upstream repo | https://github.com/agentgateway/agentgateway |
| Pinned tag | `v1.3.1` |
| Pinned commit | `dbaaf7ed73671e7aec9195e35e7f726c0b14b84a` |
| Source proto | `crates/protos/proto/ext_mcp.proto` |
| Vendored files | `ext_mcp.pb.go`, `ext_mcp_grpc.pb.go` (upstream `api/` — upstream-generated, protoc-gen-go v1.36.11-devel / protoc-gen-go-grpc v1.6.2) |

Upstream also ships `ext_mcp_json.gen.go` (a protoc-gen-jsonshim artifact);
it is deliberately NOT vendored — it depends on the deprecated
`github.com/golang/protobuf/jsonpb` and the adapter never JSON-marshals these
messages.

sha256 of the vendored files (must match upstream `api/` at the pinned commit):

```
f4829f8c2491b4ce087fe53e43f4dab60c2fd49f778c19a1e90e995908190547  ext_mcp.pb.go
0fe1b843801226cb1fb38eb4d5245e6b006cb4f7b0c374a621baef772bdfe89a  ext_mcp_grpc.pb.go
```

## Why vendor instead of `go get`

The upstream nested module `github.com/agentgateway/agentgateway/api` at tag
`v1.3.1` is broken standalone: its `go.mod` omits the `google.golang.org/grpc`
requirement that `ext_mcp_grpc.pb.go` imports, and the module has no `api/*`
tags, so `go get` silently resolves to a floating main-branch pseudo-version
instead of the pinned release. Vendoring the upstream-generated files keeps the
pin exact and verifiable (checksums above).

The Envoy `ext_authz` / `ext_proc` contracts used by the sibling adapters are
NOT vendored — those come from the canonical published module
`github.com/envoyproxy/go-control-plane/envoy` (see the parent package doc for
the wire-compatibility rationale).

## Regenerating / bumping the pin

```bash
git clone https://github.com/agentgateway/agentgateway.git
cd agentgateway && git checkout <new-tag>
# upstream generates via buf (buf.gen.yaml at repo root):
#   buf generate          # emits api/*.pb.go with paths=source_relative
cp api/ext_mcp.pb.go api/ext_mcp_grpc.pb.go \
   <axonflow-enterprise>/platform/gateway-adapters/agentgateway/api/
# then update the tag/commit/sha256 table in this README and re-run:
#   cd platform && go build ./gateway-adapters/... && go test ./gateway-adapters/...
```

Before bumping, diff `crates/protos/proto/ext_mcp.proto` between the old and
new tags — a contract change there is a breaking adapter change, not a routine
pin bump. (Verified at pin time: `ext_mcp.proto`, `ext_authz.proto`,
`ext_proc.proto`, `shared_envoy.proto` are byte-identical between `v1.3.1` and
upstream `main` as of 2026-07-10.)
