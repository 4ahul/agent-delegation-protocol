from __future__ import annotations
import fnmatch
from dataclasses import dataclass
from .budget import BudgetLedger
from .models import Decision, Grant


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str
    remaining_budget: float | None = None


class PolicyEngine:
    """Deny-by-default evaluation of a verified grant against one operation."""

    def __init__(self, ledger: BudgetLedger | None = None):
        self.ledger = ledger or BudgetLedger()

    def _track(self, grant: Grant) -> None:
        """Teach the ledger this grant's budget lineage before it is consulted."""
        if not grant.budget or self.ledger.known(grant.token_id or ""):
            return  # lineage is written root-first, so a known leaf means a known chain
        previous = None
        for token_id, limit in grant.budget.chain:
            self.ledger.register(token_id, previous, limit)
            previous = token_id
        self.ledger.register(grant.token_id or "", previous or grant.parent_id, grant.budget.limit)

    def decide(self, grant: Grant, *, action: str, resource: str, estimated_cost: float = 0,
               purpose: str | None = None) -> PolicyResult:
        if action not in grant.permissions:
            return PolicyResult("DENY", "permission_not_granted")
        if not any(fnmatch.fnmatchcase(resource, pattern) for pattern in grant.resources):
            return PolicyResult("DENY", "resource_not_granted")
        # A purpose-bound grant is only usable for that purpose. Omitting the
        # purpose must not be a way around the binding.
        if grant.purpose and grant.purpose != purpose:
            return PolicyResult("DENY", "purpose_mismatch")
        self._track(grant)
        remaining = self.ledger.remaining(grant.token_id or "") if grant.budget else None
        if remaining is not None and estimated_cost > remaining:
            return PolicyResult("DENY", "budget_exceeded", remaining)
        if action in grant.approval_required:
            return PolicyResult("REQUIRE_APPROVAL", "human_approval_required", remaining)
        return PolicyResult("ALLOW", "policy_satisfied", remaining)

    def charge(self, grant: Grant, amount: float) -> float | None:
        if not grant.budget:
            return None
        self._track(grant)
        return self.ledger.charge(grant.token_id or "", amount)
