import os

ADMIN_TOKEN = "test-admin-token"
os.environ.setdefault("ADP_ADMIN_TOKEN", ADMIN_TOKEN)
os.environ.setdefault("ADP_ROUTES", "")

import time  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from adp.crypto import KeyPair  # noqa: E402
from adp.models import Budget, Grant  # noqa: E402
from adp.token import issue  # noqa: E402

ADMIN = {"X-ADP-Admin": ADMIN_TOKEN}


@pytest.fixture
def app_state():
    from server import app as mod
    for store in (mod.KEYS, mod.audit, mod.revocations, mod.approvals, mod.ledger):
        store.clear()
    return mod


@pytest.fixture
def client(app_state):
    return TestClient(app_state.app)


@pytest.fixture
def signer(app_state):
    """Register a keypair and hand back a token-minting helper."""
    kp = KeyPair.generate()

    def mint(issuer="agent://research", subject="agent://valuation", **kw):
        now = int(time.time())
        fields = dict(version="ADP-0.2", issuer=issuer, subject=subject, principal="user://rahul",
                      issued_at=now, expires_at=now + 300, permissions=("property.read",),
                      resources=("mumbai://rr/*",), budget=Budget("INR", 100), token_id="tok-1")
        fields.update(kw)
        grant = Grant(**fields)
        app_state.KEYS.register(issuer, kp.public_key_b64)
        return grant, issue(grant, kp)

    mint.keypair = kp
    return mint
