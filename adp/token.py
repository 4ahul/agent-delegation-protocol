from __future__ import annotations
import hashlib, json, time, uuid
from .crypto import KeyPair, b64, unb64
from .models import Grant, Budget

MAX_CHAIN = 16  # delegation depth is bounded; refuse an unbounded ancestor list


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def _encode(obj: dict) -> str:
    return b64(canonical(obj))

def issue(grant: Grant, keypair: KeyPair) -> str:
    header = {"alg": "EdDSA", "typ": "ADP", "v": "0.2"}
    payload = grant.to_dict()
    protected = _encode(header) + "." + _encode(payload)
    sig = keypair.private.sign(protected.encode())
    return protected + "." + b64(sig)

def decode(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed_token")
    h, p, s = parts
    return json.loads(unb64(h)), json.loads(unb64(p)), s

def token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:32]

def verify(token: str, public_key_b64: str, now: int | None = None) -> Grant:
    header, payload, sig = decode(token)
    if header.get("typ") != "ADP" or header.get("v") != "0.2" or header.get("alg") != "EdDSA":
        raise ValueError("unsupported ADP token")
    protected = token.rsplit(".", 1)[0]
    KeyPair.verify_signature(public_key_b64, protected.encode(), sig)
    now = int(time.time()) if now is None else now
    iat, exp = int(payload["iat"]), int(payload["exp"])
    if now >= exp:
        raise ValueError("token_expired")
    if iat > now + 60:
        raise ValueError("token_issued_in_future")
    if exp <= iat:
        raise ValueError("invalid_expiry")
    b = payload.get("budget")
    return Grant(
        version=payload["v"], issuer=payload["iss"], subject=payload["sub"], principal=payload["prn"],
        issued_at=iat, expires_at=exp, permissions=tuple(payload.get("permissions", [])),
        resources=tuple(payload.get("resources", [])), purpose=payload.get("purpose"),
        budget=Budget(b["currency"], float(b["limit"]), float(b.get("spent", 0)),
                      tuple((str(t), float(l)) for t, l in b.get("chain", [])[:MAX_CHAIN])) if b else None,
        delegation_depth=int(payload.get("depth", 0)), parent_id=payload.get("parent"),
        token_id=payload.get("jti") or token_id(token), approval_required=tuple(payload.get("approval_required", [])),
    )

def _subset(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    return set(child).issubset(parent)

def _resource_subset(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    for c in child:
        if c in parent:
            continue
        if not any(p.endswith("*") and c.startswith(p[:-1]) for p in parent):
            return False
    return True

def delegate(parent: Grant, child_subject: str, keypair: KeyPair, *, permissions: list[str], resources: list[str], expires_at: int, budget_limit: float | None = None, purpose: str | None = None, approval_required: list[str] | None = None) -> tuple[Grant, str]:
    if parent.delegation_depth <= 0:
        raise ValueError("delegation_depth_exhausted")
    if not _subset(tuple(permissions), parent.permissions):
        raise ValueError("child_permissions_exceed_parent")
    if not _resource_subset(tuple(resources), parent.resources):
        raise ValueError("child_resources_exceed_parent")
    if expires_at > parent.expires_at:
        raise ValueError("child_expiry_exceeds_parent")
    if parent.budget:
        available = parent.budget.remaining()
        if budget_limit is None:
            budget_limit = available
        if budget_limit > available:
            raise ValueError("child_budget_exceeds_parent")
    if approval_required and not set(approval_required).issubset(set(parent.approval_required)):
        # A child may not remove a mandatory approval requirement.
        raise ValueError("child_approval_policy_exceeds_parent")
    if not approval_required:
        approval_required = list(parent.approval_required)
    child = Grant(
        version="ADP-0.2", issuer=parent.subject, subject=child_subject, principal=parent.principal,
        issued_at=int(time.time()), expires_at=expires_at, permissions=tuple(permissions), resources=tuple(resources),
        purpose=purpose or parent.purpose,
        budget=Budget(parent.budget.currency, budget_limit,
                      chain=parent.budget.chain + ((parent.token_id or "", parent.budget.limit),))
        if parent.budget and budget_limit is not None else None,
        delegation_depth=parent.delegation_depth - 1, parent_id=parent.token_id,
        token_id=str(uuid.uuid4()), approval_required=tuple(approval_required),
    )
    return child, issue(child, keypair)
