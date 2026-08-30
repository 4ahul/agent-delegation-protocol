import time
import pytest
from adp.crypto import KeyPair
from adp.models import Grant, Budget
from adp.token import issue, verify, delegate
from adp.policy import PolicyEngine
from adp.audit import AuditLog


def root_grant(depth=2, budget=500):
    now = int(time.time())
    return Grant(
        version="ADP-0.2", issuer="user://rahul", subject="agent://research",
        principal="user://rahul", issued_at=now, expires_at=now + 600,
        permissions=("property.read", "property.search", "a2a:delegate"),
        resources=("mumbai://rr/*",), purpose="feasibility",
        budget=Budget("INR", budget), delegation_depth=depth,
        token_id="root-token", approval_required=(),
    )


def test_issue_verify():
    kp = KeyPair.generate()
    token = issue(root_grant(), kp)
    g = verify(token, kp.public_key_b64)
    assert g.subject == "agent://research"
    assert g.version == "ADP-0.2"


def test_delegation_attenuates():
    kp = KeyPair.generate()
    parent = root_grant()
    child, token = delegate(parent, "agent://valuation", kp,
                            permissions=["property.read"],
                            resources=["mumbai://rr/123"],
                            expires_at=parent.expires_at - 10,
                            budget_limit=200)
    assert child.delegation_depth == 1
    assert child.permissions == ("property.read",)
    assert child.budget.limit == 200
    verify(token, kp.public_key_b64)


def test_privilege_escalation_rejected():
    kp = KeyPair.generate()
    parent = root_grant()
    with pytest.raises(ValueError):
        delegate(parent, "agent://evil", kp,
                 permissions=["property.delete"], resources=["mumbai://rr/123"],
                 expires_at=parent.expires_at)


def test_expiry_cannot_extend():
    kp = KeyPair.generate()
    parent = root_grant()
    with pytest.raises(ValueError):
        delegate(parent, "agent://child", kp,
                 permissions=["property.read"], resources=["mumbai://rr/123"],
                 expires_at=parent.expires_at + 1)


def test_policy_and_budget():
    g = root_grant(budget=100)
    engine = PolicyEngine()
    ok = engine.decide(g, action="property.read", resource="mumbai://rr/1", estimated_cost=40, purpose="feasibility")
    assert ok.decision == "ALLOW"
    assert engine.charge(g, 40) == 60
    denied = engine.decide(g, action="property.read", resource="mumbai://rr/1", estimated_cost=61, purpose="feasibility")
    assert denied.decision == "DENY"


def test_audit_chain():
    log = AuditLog()
    log.append(event="authorization", principal="user://rahul", agent="agent://a", decision="ALLOW")
    log.append(event="budget_charge", token_id="t", amount=10)
    assert log.verify()
    e = log.events[0]
    assert e.metadata == {}
