from __future__ import annotations
from dataclasses import dataclass

from .models import Grant
from .policy import PolicyEngine, PolicyResult
from .revocation import RevocationStore
from .token import decode, verify


@dataclass
class Authorizer:
    """Token verification + revocation check + policy evaluation, in that order."""
    keys: dict[str, str]
    policy: PolicyEngine
    revocations: RevocationStore

    def resolve(self, token: str) -> Grant:
        """Verify a bearer token. Every failure surfaces as ValueError."""
        try:
            _, payload, _ = decode(token)
            key = self.keys.get(payload.get("iss"))
            if not key:
                raise ValueError("unknown_issuer")
            grant = verify(token, key)
        except ValueError:
            raise
        except Exception as e:  # bad base64, bad signature, missing claim
            raise ValueError(f"invalid_token:{type(e).__name__}") from None
        if self.revocations.is_revoked(grant.token_id or ""):
            raise ValueError("token_revoked")
        return grant

    def authorize(self, token: str, *, action: str, resource: str, estimated_cost: float = 0,
                  purpose: str | None = None) -> tuple[PolicyResult, Grant]:
        grant = self.resolve(token)
        return self.policy.decide(grant, action=action, resource=resource,
                                  estimated_cost=estimated_cost, purpose=purpose), grant
