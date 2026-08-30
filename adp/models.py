from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal

Decision = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]

@dataclass(frozen=True)
class Budget:
    currency: str
    limit: float
    spent: float = 0.0
    #: (token_id, limit) of every ancestor grant, root first. Signed into the
    #: token so a gateway that has never seen the parent can still debit it and
    #: stop siblings from spending the same parent budget twice.
    chain: tuple[tuple[str, float], ...] = ()

    def remaining(self) -> float:
        return max(0.0, self.limit - self.spent)

@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    public_key: str
    principal: str
    metadata: dict = field(default_factory=dict)

@dataclass(frozen=True)
class Grant:
    version: str
    issuer: str
    subject: str
    principal: str
    issued_at: int
    expires_at: int
    permissions: tuple[str, ...]
    resources: tuple[str, ...]
    purpose: str | None = None
    budget: Budget | None = None
    delegation_depth: int = 0
    parent_id: str | None = None
    token_id: str | None = None
    approval_required: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        d = {
            "v": self.version, "iss": self.issuer, "sub": self.subject,
            "prn": self.principal, "iat": self.issued_at, "exp": self.expires_at,
            "depth": self.delegation_depth, "permissions": list(self.permissions),
            "resources": list(self.resources), "purpose": self.purpose,
            "parent": self.parent_id, "jti": self.token_id,
            "approval_required": list(self.approval_required),
        }
        if self.budget:
            d["budget"] = {"currency": self.budget.currency, "limit": self.budget.limit,
                           "spent": self.budget.spent}
            if self.budget.chain:
                d["budget"]["chain"] = [[t, l] for t, l in self.budget.chain]
        return {k: v for k, v in d.items() if v is not None}
