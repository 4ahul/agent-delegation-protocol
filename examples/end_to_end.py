"""One principal, two agents, one budget — the whole protocol in 60 lines.

Run it:  python examples/end_to_end.py
"""
import time

from adp import (Authorizer, Budget, Grant, KeyPair, PolicyEngine,
                 RevocationStore, AuditLog, delegate, issue, verify)

now = int(time.time())
rahul = KeyPair.generate()       # the principal's signing key
research = KeyPair.generate()    # the first agent's signing key

# 1. The principal grants an agent narrow authority: two actions, one namespace,
#    30 minutes, INR 500, and permission to sub-delegate twice.
root = Grant(
    version="ADP-0.2", issuer="user://rahul", subject="agent://research",
    principal="user://rahul", issued_at=now, expires_at=now + 1800,
    permissions=("property.read", "property.search"), resources=("mumbai://rr/*",),
    purpose="feasibility", budget=Budget("INR", 500), delegation_depth=2,
    token_id="root-demo",
)
root_token = issue(root, rahul)
root = verify(root_token, rahul.public_key_b64)
print(f"1. issued   {root.subject} <- {root.principal}  budget={root.budget.limit} {root.budget.currency}")

# 2. That agent hands a narrower slice to a second agent. Attenuation is checked
#    at issuance: it cannot widen anything it was given.
child, child_token = delegate(
    root, "agent://valuation", research,
    permissions=["property.read"], resources=["mumbai://rr/123"],
    expires_at=now + 900, budget_limit=200,
)
print(f"2. delegated {child.subject} <- {child.issuer}  budget={child.budget.limit}  depth={child.delegation_depth}")

try:
    delegate(root, "agent://evil", research, permissions=["property.delete"],
             resources=["mumbai://rr/*"], expires_at=now + 900)
except ValueError as e:
    print(f"3. escalation refused at issuance: {e}")

# 3. A gateway that has never seen the root grant verifies the child and decides.
engine = PolicyEngine()
gateway = Authorizer(
    keys={"user://rahul": rahul.public_key_b64, "agent://research": research.public_key_b64},
    policy=engine, revocations=RevocationStore(),
)
allowed, grant = gateway.authorize(child_token, action="property.read",
                                   resource="mumbai://rr/123", estimated_cost=75,
                                   purpose="feasibility")
print(f"4. decision  {allowed.decision} ({allowed.reason})  remaining={allowed.remaining_budget}")

denied, _ = gateway.authorize(child_token, action="property.read",
                              resource="mumbai://rr/999", purpose="feasibility")
print(f"5. wrong resource: {denied.decision} ({denied.reason})")

no_purpose, _ = gateway.authorize(child_token, action="property.read",
                                  resource="mumbai://rr/123")
print(f"6. missing purpose: {no_purpose.decision} ({no_purpose.reason})")

# 4. Spending debits the child AND the root, so siblings cannot double-spend.
print(f"7. charged 75 -> child has {engine.charge(grant, 75)} left of 200, "
      f"root has {engine.ledger.remaining('root-demo')} left of 500")

# 5. Every decision is appended to a hash-chained log.
log = AuditLog()
log.append(event="authorization", principal=grant.principal, agent=grant.subject,
           action="property.read", resource="mumbai://rr/123",
           decision=allowed.decision, token_id=grant.token_id)
log.append(event="budget_charge", principal=grant.principal, agent=grant.subject,
           token_id=grant.token_id, amount=75)
print(f"8. audit chain of {len(log.events)} events verifies: {log.verify()}")
