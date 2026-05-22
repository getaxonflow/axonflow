# v9 Identity Forwarding Example

Demonstrates the v9 identity model (ADR-052) end-to-end across the agent →
orchestrator boundary:

- `X-Org-ID` carries the customer/account org (RLS boundary).
- `X-Client-ID` carries the authenticated API credential identity (v9 successor of `X-Tenant-ID`).
- `X-Tenant-ID` is kept as a deprecated alias during the v9 compatibility window.

The Go example boots a tiny in-process pair of HTTP servers that simulate the
real agent/orchestrator handoff:

1. A *mock orchestrator* listens on a random port and reports the three identity
   headers it received.
2. A *mock agent* in front of it implements the v9 auth-header-overwrite rule:
   any caller-supplied `X-Org-ID` / `X-Client-ID` / `X-Tenant-ID` is replaced
   with the value the agent's auth path derived from the request's Basic Auth
   credentials before the request is forwarded to the orchestrator.
3. A client sends a request — first cleanly, then with adversarial
   identity-spoofing headers — and the example asserts that the orchestrator
   sees the auth-derived identity in both cases.

This is the same overwrite rule shipped in
`platform/agent/auth.go::apiAuthMiddleware` and
`platform/agent/proxy.go::proxyAuthMiddleware`; running the example is the
simplest way to see the rule in action without standing up the full stack.

## Run

```bash
go run ./examples/v9_identity/go
```

Expected output (abridged):

```
[v9-identity] Mock orchestrator listening on http://127.0.0.1:NNNNN
[v9-identity] Mock agent listening    on http://127.0.0.1:MMMMM

--- Round 1: clean request, no spoofed headers ---
   PASS: orchestrator received X-Org-ID    = "acme-corp"
   PASS: orchestrator received X-Client-ID = "acme-prod-api"
   PASS: orchestrator received X-Tenant-ID = "acme-prod-api" (compat alias)

--- Round 2: caller attempts to spoof identity ---
   PASS: spoofed X-Org-ID was overwritten (got "acme-corp", not "victim-org")
   PASS: spoofed X-Client-ID was overwritten (got "acme-prod-api", not "victim-client")
   PASS: spoofed X-Tenant-ID was overwritten (got "acme-prod-api", not "victim-tenant")

v9 identity forwarding example: OK
```

## References

- ADR-052 §5 (v9 identity model + compatibility window)
- ADR-053 §Step 2 (code identity migration)
- `technical-docs/LICENSE_AND_TENANT_ARCHITECTURE.md` (canonical reference)
- Epic [#2230](https://github.com/getaxonflow/axonflow-enterprise/issues/2230) Phase 4
