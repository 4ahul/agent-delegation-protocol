"""Protocol bindings that map MCP and A2A operations onto ADP actions.

Lives inside the `adp` package on purpose: a top-level `mcp` package would
shadow the official MCP SDK for anyone who installs both.
"""
from __future__ import annotations
from dataclasses import dataclass

from .gateway import ADPGateway, GatewayDecision


@dataclass
class MCPGateway:
    """MCP exposes method/name on the HTTP request; map them to `mcp:<method>:<name>`."""
    gateway: ADPGateway

    def check(self, bearer_token: str, *, method: str, name: str, resource: str,
              estimated_cost: float = 0, purpose: str | None = None) -> GatewayDecision:
        return self.gateway.check(bearer_token, action=f"mcp:{method}:{name}", resource=resource,
                                  estimated_cost=estimated_cost, purpose=purpose)


@dataclass
class A2AGateway:
    """Agent-to-agent task delegation: the target agent is the resource."""
    gateway: ADPGateway

    def check(self, bearer_token: str, *, task: str, target_agent: str,
              estimated_cost: float = 0, purpose: str | None = None) -> GatewayDecision:
        return self.gateway.check(bearer_token, action=f"a2a:delegate:{task}",
                                  resource=f"agent://{target_agent}",
                                  estimated_cost=estimated_cost, purpose=purpose)
