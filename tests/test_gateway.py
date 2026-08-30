"""HTTP surface: authorize, charge, revoke, approve, audit, proxy."""
from tests.conftest import ADMIN


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_health_and_jwks(client, signer):
    assert client.get("/health").json()["protocol"] == "ADP-0.4"
    signer()
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    assert keys[0]["kty"] == "OKP" and keys[0]["crv"] == "Ed25519"


def test_register_key_requires_admin(client, signer):
    body = {"agent_id": "agent://x", "public_key": signer.keypair.public_key_b64}
    assert client.post("/v1/keys", json=body).status_code == 401
    assert client.post("/v1/keys", json=body, headers=ADMIN).status_code == 200


def test_register_key_rejects_garbage(client):
    r = client.post("/v1/keys", json={"agent_id": "agent://x", "public_key": "not-a-key"},
                    headers=ADMIN)
    assert r.status_code == 422


def test_authorize_then_revoke(client, signer):
    _, token = signer()
    r = client.post("/v1/authorize", headers=auth(token),
                    json={"action": "property.read", "resource": "mumbai://rr/1",
                          "estimated_cost": 10})
    assert r.json()["decision"] == "ALLOW"
    assert client.post("/v1/revoke", json={"token_id": "tok-1"}, headers=ADMIN).status_code == 200
    r = client.post("/v1/authorize", headers=auth(token),
                    json={"action": "property.read", "resource": "mumbai://rr/1"})
    assert r.status_code == 401 and "revoked" in r.json()["detail"]


def test_denies_ungranted_action(client, signer):
    _, token = signer()
    r = client.post("/v1/authorize", headers=auth(token),
                    json={"action": "admin.delete", "resource": "mumbai://rr/1"})
    assert r.json()["decision"] == "DENY"


def test_charge_enforces_limit(client, signer):
    _, token = signer()
    assert client.post("/v1/charge", headers=auth(token),
                       json={"token_id": "tok-1", "amount": 90}).json()["remaining"] == 10
    r = client.post("/v1/charge", headers=auth(token), json={"token_id": "tok-1", "amount": 20})
    assert r.status_code == 409 and r.json()["detail"] == "budget_exceeded"


def test_approval_flow(client, signer):
    _, token = signer(permissions=("property.read",), approval_required=("property.read",))
    body = {"action": "property.read", "resource": "mumbai://rr/1"}
    first = client.post("/v1/authorize", headers=auth(token), json=body).json()
    assert first["decision"] == "REQUIRE_APPROVAL"
    aid = first["approval_id"]

    assert client.post(f"/v1/approvals/{aid}/approve", json={"approver": "user://rahul"}).status_code == 401
    assert client.post(f"/v1/approvals/{aid}/approve", json={"approver": "user://rahul"},
                       headers=ADMIN).status_code == 200

    assert client.post("/v1/authorize", headers=auth(token),
                       json={**body, "approval_id": aid}).json()["decision"] == "ALLOW"
    # single use
    assert client.post("/v1/authorize", headers=auth(token),
                       json={**body, "approval_id": aid}).status_code == 403


def test_audit_chain_verifies(client, signer):
    _, token = signer()
    client.post("/v1/authorize", headers=auth(token),
                json={"action": "property.read", "resource": "mumbai://rr/1"})
    r = client.get("/v1/audit/verify", headers=ADMIN)
    assert r.json()["valid"] is True and r.json()["events"] >= 1
    assert client.get("/v1/audit/verify").status_code == 401
