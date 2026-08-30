"""Regression tests for the ways this gateway could be talked out of a decision."""
import time

import pytest

from adp.budget import BudgetLedger
from adp.config import PolicyConfig
from adp.crypto import KeyPair
from adp.db import connect
from adp.models import Budget, Grant
from adp.policy import PolicyEngine
from adp.proxy import STRIP_REQUEST
from adp.revocation import RevocationStore
from adp.token import delegate, issue, verify


def grant(**kw):
    now = int(time.time())
    fields = dict(version="ADP-0.2", issuer="user://rahul", subject="agent://research",
                  principal="user://rahul", issued_at=now, expires_at=now + 600,
                  permissions=("property.read", "a2a:delegate"), resources=("mumbai://rr/*",),
                  budget=Budget("INR", 500), delegation_depth=2, token_id="root")
    fields.update(kw)
    return Grant(**fields)


def test_purpose_binding_cannot_be_skipped():
    engine = PolicyEngine()
    g = grant(purpose="feasibility")
    assert engine.decide(g, action="property.read", resource="mumbai://rr/1").decision == "DENY"
    assert engine.decide(g, action="property.read", resource="mumbai://rr/1",
                         purpose="resale").decision == "DENY"
    assert engine.decide(g, action="property.read", resource="mumbai://rr/1",
                         purpose="feasibility").decision == "ALLOW"


def test_children_cannot_spend_past_the_parent_budget():
    """Two children of 300 out of a 500 parent must not add up to 600."""
    engine = PolicyEngine()
    kp = KeyPair.generate()
    parent = grant()
    a, _ = delegate(parent, "agent://a", kp, permissions=["property.read"],
                    resources=["mumbai://rr/1"], expires_at=parent.expires_at, budget_limit=300)
    b, _ = delegate(parent, "agent://b", kp, permissions=["property.read"],
                    resources=["mumbai://rr/1"], expires_at=parent.expires_at, budget_limit=300)
    assert engine.charge(a, 300) == 0
    with pytest.raises(ValueError, match="budget_exceeded"):
        engine.charge(b, 300)
    assert engine.charge(b, 200) == 0  # only the parent's last 200 remains


def test_repeated_decisions_still_enforce_the_chain():
    """The ledger skips re-registering a known grant; it must not skip enforcing it."""
    engine = PolicyEngine()
    kp = KeyPair.generate()
    parent = grant()
    child, _ = delegate(parent, "agent://a", kp, permissions=["property.read"],
                        resources=["mumbai://rr/1"], expires_at=parent.expires_at,
                        budget_limit=500)
    for _ in range(5):
        assert engine.decide(child, action="property.read", resource="mumbai://rr/1",
                             estimated_cost=1).decision == "ALLOW"
    engine.charge(child, 500)
    assert engine.decide(child, action="property.read", resource="mumbai://rr/1",
                         estimated_cost=1).decision == "DENY"


def test_budget_chain_terminates_on_a_parent_cycle():
    ledger = BudgetLedger()
    ledger.register("a", "b", 10.0)
    ledger.register("b", "a", 10.0)  # cycle
    assert len(ledger._chain("a")) <= 16
    assert ledger.remaining("a") == 10.0


def test_revocation_survives_restart(tmp_path):
    db = str(tmp_path / "adp.db")
    RevocationStore(connect(db)).revoke("tok-1")
    assert RevocationStore(connect(db)).is_revoked("tok-1")


def test_budget_survives_restart(tmp_path):
    db = str(tmp_path / "adp.db")
    first = BudgetLedger(connect(db))
    first.register("tok-1", None, 100.0)
    first.charge("tok-1", 60)
    assert BudgetLedger(connect(db)).remaining("tok-1") == 40


def test_tampered_audit_row_is_detected(tmp_path):
    from adp.audit import AuditLog
    conn = connect(str(tmp_path / "adp.db"))
    log = AuditLog(conn)
    log.append(event="authorization", decision="DENY")
    log.append(event="authorization", decision="DENY")
    assert log.verify()
    conn.execute("UPDATE audit SET decision='ALLOW' WHERE seq=1")
    assert not log.verify()


def test_token_from_untrusted_signer_is_rejected():
    from adp.middleware import Authorizer
    trusted, attacker = KeyPair.generate(), KeyPair.generate()
    az = Authorizer({"user://rahul": trusted.public_key_b64}, PolicyEngine(), RevocationStore())
    with pytest.raises(ValueError):
        az.resolve(issue(grant(), attacker))
    az.resolve(issue(grant(), trusted))


def test_expired_token_is_rejected():
    kp = KeyPair.generate()
    now = int(time.time())
    token = issue(grant(issued_at=now - 100, expires_at=now - 1), kp)
    with pytest.raises(ValueError, match="token_expired"):
        verify(token, kp.public_key_b64)


def test_invalid_public_key_is_rejected():
    with pytest.raises(ValueError, match="invalid_public_key"):
        KeyPair.validate_public("obviously-not-a-key")


def test_proxy_never_forwards_agent_credentials():
    assert {"authorization", "cookie"} <= STRIP_REQUEST


def test_bad_route_config_fails_loudly():
    with pytest.raises(ValueError):
        PolicyConfig.from_env("property=http://x:9000,property.read")
    with pytest.raises(ValueError):
        PolicyConfig.from_env("property=ftp://x,property.read,mumbai://rr/*,1")
    with pytest.raises(ValueError):
        PolicyConfig.from_env("property=http://x,property.read,mumbai://rr/*,-1")
    route = PolicyConfig.from_env("p=http://x:9000,property.read,mumbai://rr/*,1,feasibility").route("p")
    assert route.cost == 1.0 and route.purpose == "feasibility"
