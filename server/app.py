from __future__ import annotations
import logging, os, secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from adp.approval import ApprovalStore
from adp.audit import AuditLog
from adp.budget import BudgetLedger
from adp.config import PolicyConfig
from adp.db import connect
from adp.gateway import ADPGateway
from adp.jwks import KeyRegistry, public_jwk
from adp.middleware import Authorizer
from adp.policy import PolicyEngine, PolicyResult
from adp.proxy import build_proxy_router
from adp.revocation import RevocationStore

log = logging.getLogger("adp")

# One connection, one process. Run a single uvicorn worker (or point ADP_DB at a
# shared file) — the budget ledger and audit chain must not fork into copies.
DB = connect()
KEYS = KeyRegistry(DB)
ledger = BudgetLedger(DB)
engine = PolicyEngine(ledger)
audit = AuditLog(DB)
revocations = RevocationStore(DB)
approvals = ApprovalStore(DB)
authorizer = Authorizer(KEYS, engine, revocations)
gateway = ADPGateway(authorizer)

# Admin endpoints mint trust (key registration) and satisfy human-approval gates.
# Never leave them open: with no configured secret we generate one and log it,
# so the surface is closed by default rather than open by default.
ADMIN_TOKEN = os.getenv("ADP_ADMIN_TOKEN") or ""
if not ADMIN_TOKEN:
    ADMIN_TOKEN = secrets.token_urlsafe(32)
    log.warning("ADP_ADMIN_TOKEN unset; generated ephemeral admin token: %s", ADMIN_TOKEN)


def require_admin(x_adp_admin: str | None = Header(default=None)) -> None:
    if not x_adp_admin or not secrets.compare_digest(x_adp_admin, ADMIN_TOKEN):
        raise HTTPException(401, "admin_auth_required")


app = FastAPI(title="ADP Agent Control Plane", version="0.4.0")
app.include_router(build_proxy_router(gateway, PolicyConfig.from_env()))


class RegisterKey(BaseModel):
    agent_id: str = Field(min_length=1)
    public_key: str = Field(min_length=1)


class AuthorizeRequest(BaseModel):
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    estimated_cost: float = Field(default=0, ge=0)
    purpose: str | None = None
    approval_id: str | None = None


class ChargeRequest(BaseModel):
    token_id: str
    amount: float = Field(gt=0)


class RevokeRequest(BaseModel):
    token_id: str = Field(min_length=1)
    reason: str = "revoked"


class ApprovalRequest(BaseModel):
    token_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    ttl: int = Field(default=300, ge=30, le=3600)


class ApproveRequest(BaseModel):
    approver: str = Field(min_length=1)


def bearer_grant(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing_bearer_token")
    try:
        return authorizer.resolve(authorization[7:])
    except ValueError as e:
        raise HTTPException(401, str(e)) from None


@app.get("/health")
def health():
    return {"ok": True, "protocol": "ADP-0.4"}


@app.post("/v1/keys", dependencies=[Depends(require_admin)])
def register_key(req: RegisterKey):
    try:
        KEYS.register(req.agent_id, req.public_key)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    audit.append(event="key_registration", agent=req.agent_id)
    return {"registered": req.agent_id}


@app.get("/.well-known/jwks.json")
@app.get("/v1/.well-known/jwks.json")
def jwks():
    return {"keys": [public_jwk(a, k) for a, k in KEYS.items()]}


@app.post("/v1/revoke", dependencies=[Depends(require_admin)])
def revoke(req: RevokeRequest):
    revocations.revoke(req.token_id, reason=req.reason)
    audit.append(event="revocation", token_id=req.token_id, reason=req.reason)
    return {"revoked": True, "token_id": req.token_id}


@app.post("/v1/authorize")
def authorize(req: AuthorizeRequest, grant=Depends(bearer_grant)):
    result = engine.decide(grant, action=req.action, resource=req.resource,
                           estimated_cost=req.estimated_cost, purpose=req.purpose)
    approval_id = req.approval_id
    if result.decision == "REQUIRE_APPROVAL":
        if approval_id:
            # Single use, and only for the exact token/action/resource approved.
            if not approvals.consume(approval_id, token_id=grant.token_id or "",
                                     action=req.action, resource=req.resource):
                audit.append(event="authorization", principal=grant.principal, agent=grant.subject,
                             action=req.action, resource=req.resource, decision="DENY",
                             reason="approval_invalid_or_not_granted", token_id=grant.token_id,
                             approval_id=approval_id)
                raise HTTPException(403, "approval_invalid_or_not_granted")
            result = PolicyResult("ALLOW", "approved", result.remaining_budget)
        else:
            approval_id = approvals.request(grant.token_id or "", req.action, req.resource).approval_id
    audit.append(event="authorization", principal=grant.principal, agent=grant.subject,
                 action=req.action, resource=req.resource, decision=result.decision,
                 reason=result.reason, token_id=grant.token_id, approval_id=approval_id)
    return {"decision": result.decision, "reason": result.reason,
            "remaining_budget": result.remaining_budget, "token_id": grant.token_id,
            "approval_id": approval_id}


@app.post("/v1/charge")
def charge(req: ChargeRequest, grant=Depends(bearer_grant)):
    if grant.token_id != req.token_id:
        raise HTTPException(403, "token_id_mismatch")
    if not grant.budget:
        raise HTTPException(409, "no_budget_attached")
    try:
        remaining = engine.charge(grant, req.amount)
    except ValueError as e:
        raise HTTPException(409, str(e)) from None
    audit.append(event="budget_charge", principal=grant.principal, agent=grant.subject,
                 token_id=req.token_id, amount=req.amount)
    return {"charged": req.amount, "remaining": remaining}


@app.post("/v1/approvals", dependencies=[Depends(require_admin)])
def request_approval(req: ApprovalRequest):
    return approvals.request(req.token_id, req.action, req.resource, req.ttl).__dict__


@app.post("/v1/approvals/{approval_id}/approve", dependencies=[Depends(require_admin)])
def approve(approval_id: str, req: ApproveRequest):
    try:
        item = approvals.approve(approval_id, req.approver)
    except KeyError:
        raise HTTPException(404, "approval_not_found") from None
    except ValueError as e:
        raise HTTPException(409, str(e)) from None
    audit.append(event="approval", approval_id=approval_id, approver=req.approver,
                 token_id=item.token_id)
    return item.__dict__


@app.get("/v1/audit/verify", dependencies=[Depends(require_admin)])
def audit_verify():
    return {"valid": audit.verify(), "events": audit.count(), "head": audit.head()}
