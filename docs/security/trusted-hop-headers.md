# Trusted-Hop Headers (Internal Service Channel)

**Platform Version:** Unreleased (targeting the next MAJOR train)

**Status:** Active

**Applies To:** Any deployment that terminates client traffic in front of the
AxonFlow Agent, or that runs its own gateway, reverse proxy or service mesh in
the request path

---

## What This Covers

AxonFlow's own services carry authority between planes on four request headers.
They are the **trusted-hop** set: unlike the identity headers described in
[Identity-Header Trust Model](identity-header-trust.md), these do not merely
label a row in the audit trail. They assert **authority**, and the orchestrator
acts on them.

| Header | What it asserts |
|--------|-----------------|
| `X-Axonflow-User-Role` | The caller's validated per-user authorization role. The agent sets it only from a cryptographically validated per-user token. |
| `X-Axonflow-Read-Scope` | "I have already authorized this caller for tenant-wide reads under my own access model." Stamped by the customer portal, whose RBAC made that decision. |
| `X-Axonflow-Admin-Authority` | "I have already authorized this caller as an administrator of the tenant." A separate axis from read scope: a caller may read tenant-wide without being an administrator. |
| `X-Axonflow-Tenancy-Scope` | "The caller I am forwarding for is bound to the organization, and the tenant header on this request is a display default rather than an authorization narrowing." |

Because each of these mints an authority the platform then honours, **a client
may never assert any of them, in any spelling, on any route.**

## The Two Header Families Are Not The Same

It is worth stating the difference plainly, because the two families are often
grouped together as "AxonFlow's identity headers" and they have opposite
security properties.

| | Identity headers (`X-User-Email`, `X-User-ID`, `X-Session-Id`) | Trusted-hop headers (the four above) |
|---|---|---|
| Who may set them | Any governed caller, subject to the deployment's trust gate | AxonFlow's own services only |
| What they can change | Audit attribution fields, and per-user session-override scope | Read scope, administrative authority, tenancy width, and the role a policy condition sees |
| Effect on a verdict | None, ever | They decide what a caller may read and do, and the role additionally feeds the `user.role` policy-condition field, so it CAN change a verdict |
| Posture when absent | Attribution falls back to the validated identity | Least privilege |

That last row is the sharpest reason this set is reserved. A policy condition of
the shape "block when the caller's role is not admin" is a real, supported
control, and it reads the role the request arrived with. If a client could
assert that role, the control would be defeated by typing a different value.
This is why the role is taken only from a validated per-user token and stripped
from client traffic unconditionally, rather than being trust-gated the way the
attribution headers are.

## The Trust Channel

The orchestrator honours a trusted-hop header **only** on a request that carries
a valid internal-service proxy token (`X-Axonflow-Proxy-Auth`). If the token is
absent, malformed, or fails validation, the request resolves to least privilege
**regardless of what the four headers claim**. A deployment that never
provisioned an internal-service secret has no path to an elevated read at all,
which is the safe direction.

Community mode is a single-trust-domain local deployment and does not
participate in this channel.

## The Agent Strips Them On Ingress

The AxonFlow Agent's reverse proxy adds proxy-auth to everything it forwards.
An inbound trusted-hop value that survived that hop would therefore be vouched
for downstream. So the agent **deletes all four from every inbound client
request** before forwarding, at both of its ingress branches:

- the authenticated proxy path, and
- the CORS preflight path, which terminates the request rather than forwarding
  it, and scrubs anyway so the guarantee does not silently depend on the
  termination.

Only after the strip does the agent re-assert `X-Axonflow-User-Role`, and only
from a validated per-user token. The set is defined once, in one list, and both
ingress branches iterate that list rather than keeping their own copies. Two
tests pin the behaviour, one per branch, because they are separate code paths
and a single test would report green while the other leaked.

**The practical consequence for a caller:** sending any of these four to a
governed AxonFlow endpoint has no effect. It is not an error and it is not a
rejection. The header is removed and the request proceeds at the authority the
caller actually holds.

## If You Run Your Own Gateway

This is the case that needs attention. If you operate a gateway, reverse proxy,
ingress controller or service mesh in front of AxonFlow, treat all four names as
**reserved**:

1. **Strip them on ingress from untrusted traffic**, exactly as the agent does.
   Do this even though the agent strips them too: defence in depth costs one
   configuration line, and it keeps the guarantee local to the hop you control.
2. **Never map client-controllable input onto them.** A header rewrite rule, a
   templated value taken from a query parameter, or a claim copied out of an
   unvalidated token are all ways a client value reaches a reserved name without
   anyone intending it.
3. **Do not forward them from one tenant's traffic into another's.** They carry
   no tenant of their own; they qualify the request they arrive on.
4. **If you proxy directly to the orchestrator rather than through the agent**,
   you are responsible for the strip. The agent is where the platform performs
   it, so a path that bypasses the agent bypasses the strip as well.

Adding a fourth name to an existing strip rule is the one upgrade action here:
`X-Axonflow-Tenancy-Scope` is new in **v10.0.0**, and a rule written against an
earlier release will list only the first three.

## `X-Axonflow-Read-Scope` Is Also A Response Header

One name appears on both sides of the exchange, which is worth calling out so it
is not mistaken for a reflected request value.

The orchestrator's scope-resolved read endpoints stamp an additive
`X-Axonflow-Read-Scope` **response** header describing the authority the read
actually resolved to:

| Value | Meaning |
|-------|---------|
| `tenant` | The read was cross-user, across the tenancy. |
| `own-rows` | The read was scoped to the caller's own rows. |
| `none` | Fail-closed empty read: the caller presented neither tenant-wide authority nor a per-user identity, so zero rows were returned. |

This exists so that a caller receiving `200` with an empty result set can tell
read-scoping apart from an empty audit trail. It is **diagnostic only**: the
response body is unchanged, and nothing keys authorization off it. The `none`
path also emits one diagnostic log line.

Request and response headers are separate channels, so echoing the value
outbound cannot be laundered back inbound to elevate a later request: the
inbound path honours a single recognised value, and only over a valid
proxy-auth token.

## Fail-Closed Properties

These hold by construction, and are the properties to rely on when reasoning
about a deployment:

- An absent or invalid proxy token can never elevate, whatever the four headers
  say.
- An unrecognized role string normalizes to least privilege before any check
  runs, so no forwarding path can smuggle an unrecognized-but-privileged role
  past the gate.
- Administrative authority is **not** derivable from read scope. They are two
  assertions because one header cannot carry two independent answers, and a
  caller holding read scope without authority is exactly a viewer: tenant-wide
  reads, refused on everything administrative.
- An authority assertion presented **without** read scope resolves to neither,
  not to authority alone.
- An absent tenancy-scope header means "narrow by the tenant header as before",
  so every existing caller keeps its current narrowing untouched.
- The three assertion headers (read scope, admin authority, tenancy scope) each
  recognise exactly one value and ignore everything else, so an absent or
  malformed header can never become an assertion. The role header accepts the
  platform's known role names and normalizes anything else to least privilege.

## Related

- [Identity-Header Trust Model](identity-header-trust.md) covers the separate,
  client-assertable attribution headers and the deployment trust gate that
  governs them.
