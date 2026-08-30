# ADP 0.2 — Draft Protocol Specification

## 1. Scope

The Agent Delegation Protocol (ADP) defines a portable authorization context for autonomous and delegated agent actions. ADP is designed to compose with agent communication and tool protocols rather than replace them.

## 2. Core concepts

**Principal** — the accountable user or service that originates authority.

**Agent** — an autonomous software actor operating under a principal.

**Grant** — a signed, time-bounded set of capabilities issued by one actor to another.

**Delegation** — issuance of a child grant from a parent grant. The parent issuer signs the child grant; the child does not gain signing authority merely by receiving a grant.

**Resource** — the object or namespace to which a capability applies.

**Purpose** — optional contextual binding for a grant.

**Budget** — an optional spending constraint associated with a grant. A budget carries the identifiers and limits of its ancestor grants so that a verifier can enforce the whole chain (§9).

## 3. Security invariant: attenuation

A child grant MUST NOT be broader than its parent in:

- permissions
- resources
- expiration
- budget
- delegation depth
- mandatory approval requirements

A verifier MUST reject a grant that violates these constraints at issuance time.

## 4. Token format

ADP 0.2 uses a compact three-part signed token:

```text
base64url(header).base64url(payload).base64url(signature)
```

Header:

```json
{"alg":"EdDSA","typ":"ADP","v":"0.2"}
```

Payload fields:

| Field | Meaning |
|---|---|
| `iss` | issuer of the grant |
| `sub` | receiving agent |
| `prn` | original accountable principal |
| `iat` | issued-at Unix timestamp |
| `exp` | expiry Unix timestamp |
| `permissions` | exact action capabilities |
| `resources` | resource patterns |
| `purpose` | optional purpose binding |
| `budget` | optional budget |
| `depth` | remaining delegation depth |
| `parent` | parent grant ID |
| `jti` | grant ID |
| `approval_required` | actions requiring human approval |

`budget` is an object of `currency`, `limit`, optional `spent`, and optional `chain`:
an array of `[token_id, limit]` pairs naming every ancestor grant, root first.

## 5. Verification

A resource server SHOULD:

1. decode the token
2. resolve the issuer's trusted public key
3. verify the Ed25519 signature
4. verify `iat` and `exp`
5. check revocation
6. evaluate action and resource policy
7. enforce purpose: a grant carrying a `purpose` MUST be rejected unless the request
   states the same purpose. An absent purpose is a denial, not a wildcard.
8. enforce budget across the grant and every ancestor in `budget.chain` (§9)
9. require human approval where configured
10. emit an audit event

## 6. MCP binding

ADP can be carried as a bearer authorization context to MCP gateways. MCP's current HTTP specification exposes method/name in headers, making those values available to gateways for routing and authorization. ADP implementations SHOULD map an MCP invocation to a deterministic ADP action such as `mcp:tools/call:tool_name`.

## 7. A2A binding

When an agent delegates a task to another agent, the parent agent MAY issue a child ADP grant whose resource identifies the target agent and whose purpose identifies the delegated task. The child MUST operate within the attenuated grant.

## 8. Human approval

A policy decision can be `REQUIRE_APPROVAL`. The authorization service creates an approval object bound to token ID, action, resource, and an expiry. Approval MUST NOT broaden the underlying grant; it only satisfies an explicit approval
requirement. An approval is single-use: redeeming it MUST consume it, and it MUST only be
redeemable for the exact token, action and resource it was issued against. The party that
grants an approval MUST be authenticated separately from the agent whose request is gated —
otherwise the agent approves itself.

## 9. Budget accounting

A child grant's limit is carved out of its parent at issuance time, but the issuer cannot
observe how much of the parent has already been spent at a verifier. A parent limited to 500
could therefore issue ten children of 500 each.

A verifier MUST therefore debit the grant **and every ancestor named in `budget.chain`** on
each charge, and MUST reject a charge that would take any of them past its limit. The
effective headroom for a grant is the smallest remaining headroom along its chain. Because
the chain is inside the signed payload, this holds even for a verifier that has never seen
the parent grant.

Implementations SHOULD bound the chain length; the reference implementation caps it at 16.

## 10. Audit

Authorization, delegation, revocation, approval, and budget events SHOULD be recorded in a tamper-evident append-only log. The reference implementation links events with SHA-256 hashes.

## 11. Non-goals

ADP 0.2 does not define workload identity, organization federation, key custody, hardware
attestation, or a universal trust score. Nor does it define proof-of-possession or request
binding: grants are bearer credentials, so transport confidentiality is assumed. Those are
deliberately left for later profiles or integration specifications.

## 12. Status

This document is an experimental design, not a standards-track specification.
