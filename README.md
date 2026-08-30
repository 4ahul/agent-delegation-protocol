# ADP — Agent Delegation Protocol

**Give an agent authority you can bound, trace, and take back.**

An agent that holds your API key holds *all* of it — every action, every record, forever, and it can pass that key to the next agent in the chain. ADP replaces the key with a signed grant that says exactly what an agent may do, to which resources, for how long, on whose behalf, and up to what spend. A gateway in front of your existing services enforces it, so nothing downstream has to change.

```text
Agent ──Authorization: Bearer <ADP grant>──▶  ADP Gateway  ──▶ MCP / A2A / HTTP upstream
                                                   │
                        identity · policy · delegation · budget
                        approval · revocation · audit
```

> **Status:** reference implementation. Experimental, not a finalized standard. Read [Known limits](#known-limits) before deploying it anywhere that matters.

---

## What it enforces

| Constraint | Meaning |
|---|---|
| **Permissions** | an exact set of actions — `property.read`, `mcp:tools/call:search` |
| **Resources** | glob patterns over a namespace — `mumbai://rr/*` |
| **Expiry** | every grant dies on its own |
| **Purpose** | a grant issued for `feasibility` is unusable for anything else |
| **Budget** | a spend ceiling, debited across the *whole* delegation chain |
| **Depth** | how many further hands the authority may pass through |
| **Approval** | named actions stop for a human |
| **Revocation** | kill a grant now, durably |

Delegation is **monotonic**: a child grant can only be narrower than its parent. That is checked when the child is signed, not trusted at use time.

---

## Install

```bash
pip install -e ".[dev]"
pytest                          # 30 tests
python examples/end_to_end.py
```

## 60-second walkthrough

`examples/end_to_end.py` is the whole protocol in one file. Its real output:

```text
1. issued   agent://research <- user://rahul  budget=500.0 INR
2. delegated agent://valuation <- agent://research  budget=200  depth=1
3. escalation refused at issuance: child_permissions_exceed_parent
4. decision  ALLOW (policy_satisfied)  remaining=200.0
5. wrong resource: DENY (resource_not_granted)
6. missing purpose: DENY (purpose_mismatch)
7. charged 75 -> child has 125.0 left of 200, root has 425.0 left of 500
8. audit chain of 2 events verifies: True
```

Line 7 is the interesting one. The child was given INR 200 out of the root's 500. When it spends 75, **the root is debited too** — so the root cannot mint five more children of 200 each and quietly authorize 1000 of spend.

## Anatomy of a delegated grant

A token is `base64url(header).base64url(payload).base64url(Ed25519 signature)`. Decode one with `adp decode <token>`:

```jsonc
{
  "v": "ADP-0.2",
  "iss": "agent://research",       // who signed this delegation
  "sub": "agent://valuation",      // who may use it
  "prn": "user://rahul",           // who is ultimately accountable
  "iat": 1788100000,
  "exp": 1788100900,
  "permissions": ["property.read"],
  "resources": ["mumbai://rr/123"],
  "purpose": "feasibility",
  "depth": 1,                      // one more hop allowed
  "parent": "root-demo",
  "jti": "child-demo",
  "approval_required": [],
  "budget": {
    "currency": "INR",
    "limit": 200,
    "spent": 0.0,
    "chain": [["root-demo", 500]]  // ancestors to debit, root first
  }
}
```

`prn` never changes down the chain — five hops later you still know which human is accountable. `budget.chain` sits inside the signature, so a gateway that has never seen the root grant can still enforce the root's ceiling.

---

## Running the gateway

```bash
export ADP_ADMIN_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
export ADP_DB=./adp.db
uvicorn server.app:app --port 8000
```

`GET /health` → `{"ok": true, "protocol": "ADP-0.4"}`

### Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | liveness |
| `GET /.well-known/jwks.json` | none | published agent public keys |
| `POST /v1/authorize` | agent bearer | decide one operation |
| `POST /v1/charge` | agent bearer | record spend against a grant |
| `POST /v1/keys` | **admin** | register or rotate a trusted agent key |
| `POST /v1/revoke` | **admin** | revoke a grant ID |
| `POST /v1/approvals` | **admin** | open a human-approval ticket |
| `POST /v1/approvals/{id}/approve` | **admin** | grant one approval |
| `GET /v1/audit/verify` | **admin** | verify the audit chain |
| `ANY /proxy/{route}/{path}` | agent bearer | authorize, then forward upstream |

Admin endpoints take `X-ADP-Admin: $ADP_ADMIN_TOKEN`. Agent endpoints take `Authorization: Bearer <grant>`.

> **Admin auth is not optional.** If `ADP_ADMIN_TOKEN` is unset the server generates a random one and logs it at startup — the surface is never open. An open `/v1/keys` would let anyone register a public key for any issuer and mint grants that verify; an open approve endpoint would let an agent satisfy its own human-approval gate.

### A real session

```bash
# 401 {"detail": "admin_auth_required"}
curl -X POST localhost:8000/v1/keys \
     -d "{\"agent_id\":\"user://rahul\",\"public_key\":\"$PUBKEY\"}"

# 200 {"registered": "user://rahul"}
curl -X POST localhost:8000/v1/keys -H "X-ADP-Admin: $ADP_ADMIN_TOKEN" \
     -d "{\"agent_id\":\"user://rahul\",\"public_key\":\"$PUBKEY\"}"

# 200 {"decision":"ALLOW","reason":"policy_satisfied","remaining_budget":500.0,
#      "token_id":"root-demo","approval_id":null}
curl -X POST localhost:8000/v1/authorize -H "Authorization: Bearer $GRANT" \
     -d '{"action":"property.read","resource":"mumbai://rr/123","estimated_cost":75}'

# 200 {"charged": 75.0, "remaining": 425.0}
curl -X POST localhost:8000/v1/charge -H "Authorization: Bearer $GRANT" \
     -d '{"token_id":"root-demo","amount":75}'

# 200 {"decision":"DENY","reason":"permission_not_granted", ...}
curl -X POST localhost:8000/v1/authorize -H "Authorization: Bearer $GRANT" \
     -d '{"action":"property.delete","resource":"mumbai://rr/123"}'

# 200 {"revoked": true, "token_id": "root-demo"}
curl -X POST localhost:8000/v1/revoke -H "X-ADP-Admin: $ADP_ADMIN_TOKEN" \
     -d '{"token_id":"root-demo"}'

# 401 {"detail": "token_revoked"}
curl -X POST localhost:8000/v1/authorize -H "Authorization: Bearer $GRANT" \
     -d '{"action":"property.read","resource":"mumbai://rr/123"}'

# 200 {"valid": true, "events": 5, "head": "cb08b7b3ec9123..."}
curl localhost:8000/v1/audit/verify -H "X-ADP-Admin: $ADP_ADMIN_TOKEN"
```

### Decisions you can get back

| decision | reason | meaning |
|---|---|---|
| `ALLOW` | `policy_satisfied` | proceed |
| `ALLOW` | `approved` | proceed; a human approval was redeemed and consumed |
| `DENY` | `permission_not_granted` | action is not in the grant |
| `DENY` | `resource_not_granted` | resource matches no pattern in the grant |
| `DENY` | `purpose_mismatch` | grant is purpose-bound; the request's purpose differs or is absent |
| `DENY` | `budget_exceeded` | the grant *or an ancestor* has no headroom |
| `REQUIRE_APPROVAL` | `human_approval_required` | an `approval_id` comes back; get it approved, then retry with it |

Token-level failures are `401` with a `detail` of `missing_bearer_token`, `unknown_issuer`, `token_revoked`, `token_expired`, or `invalid_token:*`.

### Human approval

```text
authorize          → REQUIRE_APPROVAL + approval_id
(a human) approve  → POST /v1/approvals/{id}/approve   [admin auth]
authorize + id     → ALLOW (approved)
authorize + id     → 403  approval_invalid_or_not_granted   ← single use
```

An approval is bound to the exact token, action and resource, expires (300s by default), and is consumed on redemption.

---

## Reverse proxy

Put the gateway in front of a service that knows nothing about ADP:

```bash
ADP_ROUTES='property=http://property-api:9000,property.read,mumbai://rr,1'
curl -H "Authorization: Bearer $GRANT" localhost:8000/proxy/property/123
```

`/proxy/property/123` is authorized as action `property.read` on resource `mumbai://rr/123`, charged 1 unit, then forwarded to `http://property-api:9000/123`.

The upstream receives **neither the agent's `Authorization` header nor its cookies** — the gateway is the credential boundary. It receives instead:

```text
X-ADP-Principal: user://rahul
X-ADP-Agent:     agent://valuation
X-ADP-Token-Id:  child-demo
```

Inbound `X-ADP-*` headers are stripped first, so an agent cannot spoof them. Budget is charged *before* forwarding, so a slow or failing upstream cannot hand back free spend.

Route syntax: `name=url,action,resource_prefix[,cost[,purpose]]`, semicolon-separated. A malformed route fails loudly at startup rather than silently allowing everything.

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `ADP_ADMIN_TOKEN` | random, logged at startup | shared secret for admin endpoints. **Set this in production.** |
| `ADP_DB` | `:memory:` | SQLite path for revocations, budgets, approvals, audit, trusted keys |
| `ADP_ROUTES` | empty | reverse-proxy routes |

Copy `.env.example` to `.env` to start.

## Deployment

```bash
cp .env.example .env      # set ADP_ADMIN_TOKEN
docker compose up --build
```

The image runs as a non-root user with a healthcheck and keeps state on a volume.

Two rules that matter:

- **`ADP_DB` unset means in-memory.** Fine for tests, wrong for production — revocations would not survive a restart, and a revoked grant coming back to life is a security bug.
- **One uvicorn worker per `ADP_DB`.** The budget ledger and audit chain share a single SQLite connection. To scale out, point every instance at the same file on shared storage, or replace `adp/db.py` with a networked database.

## CLI

```bash
adp keygen --out adp-key.json   # written 0600
adp decode <token>              # inspect a grant without verifying it
```

---

## Security model

Grants are Ed25519-signed and authorization is deny-by-default. A child grant cannot widen permissions, resources, lifetime, budget, or mandatory approvals, and that is enforced when the child is signed. Every grant carries a signed chain of its ancestors' budget IDs and limits, so a gateway debits each ancestor on every charge even if it has never seen the parent grant. A purpose-bound grant is unusable without the matching purpose — omitting it is a denial, not a bypass.

### Known limits

Real and deliberate, not oversights:

- **Bearer tokens.** A stolen grant works until it expires or is revoked. Terminate TLS in front of the gateway. Proof-of-possession and request binding are not implemented.
- **No replay protection.** A captured `/v1/authorize` call can be replayed within the grant's lifetime.
- **Keys on disk.** No KMS/HSM integration and no automated rotation; `POST /v1/keys` rotates a key in place.
- **Single-writer accounting.** Budgets and the audit chain assume one process.
- **No rate limiting.** Put the gateway behind something that has it.

### Tests

`pytest` — 30 tests. The security-relevant ones are named for the property they defend:

```text
tests/test_security.py   purpose binding cannot be skipped
                         siblings cannot overspend a shared parent budget
                         repeated decisions still enforce the chain
                         revocations and budgets survive a restart
                         a tampered audit row is detected
                         tokens from untrusted signers are rejected
tests/test_proxy.py      the proxy never forwards agent credentials
                         X-ADP-* headers cannot be spoofed
                         budget is charged per forwarded request
tests/test_gateway.py    admin endpoints reject unauthenticated callers
                         approvals are single-use
tests/test_protocol.py   attenuation invariants at issuance
```

---

## Layout

```text
adp/            protocol + policy engine (no web framework)
  token.py        issue / verify / delegate
  policy.py       the decision function
  budget.py       chain-aware spend ledger
  db.py           SQLite schema and connection
  proxy.py        reverse-proxy router
  adapters.py     MCP and A2A action mappings
server/app.py   FastAPI control plane
docs/spec.md    draft protocol specification
schemas/        JSON Schema for the grant payload
```

MCP and A2A bindings live inside `adp/` on purpose: a top-level `mcp` package would shadow the official MCP SDK for anyone who installs both.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive changes need tests for both the happy path and the escalation attempt.

Licensed under [Apache 2.0](LICENSE).
