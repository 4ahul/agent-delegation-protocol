from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable

from .middleware import Authorizer
from .models import Grant
from .policy import PolicyResult


@dataclass(frozen=True)
class GatewayDecision:
    result: PolicyResult
    grant: Grant


class ADPGateway:
    """Framework-neutral authorization gateway for MCP/A2A/HTTP adapters."""

    def __init__(self, authorizer: Authorizer):
        self.authorizer = authorizer

    def check(self, bearer_token: str, *, action: str, resource: str,
              estimated_cost: float = 0, purpose: str | None = None) -> GatewayDecision:
        result, grant = self.authorizer.authorize(
            bearer_token, action=action, resource=resource,
            estimated_cost=estimated_cost, purpose=purpose
        )
        return GatewayDecision(result, grant)

    def enforce(self, bearer_token: str, *, action: str, resource: str,
                estimated_cost: float = 0, purpose: str | None = None,
                execute: Callable[[Grant], Any] | None = None) -> Any:
        decision = self.check(bearer_token, action=action, resource=resource,
                              estimated_cost=estimated_cost, purpose=purpose)
        if decision.result.decision != "ALLOW":
            raise PermissionError(decision.result.reason)
        if execute is None:
            return decision
        # Charge before the side effect: a crash mid-call must not hand back free spend.
        if estimated_cost:
            self.authorizer.policy.charge(decision.grant, estimated_cost)
        return execute(decision.grant)
