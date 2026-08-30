from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Route:
    name: str
    url: str
    action: str
    resource_prefix: str = "*"
    cost: float = 0.0
    purpose: str | None = None


class PolicyConfig:
    """Reverse-proxy routes, parsed from ADP_ROUTES."""

    SYNTAX = "name=url,action,resource_prefix[,cost[,purpose]];..."

    def __init__(self, routes: list[Route] | None = None):
        self.routes = routes or []

    @classmethod
    def from_env(cls, raw: str | None = None) -> "PolicyConfig":
        raw = os.getenv("ADP_ROUTES", "") if raw is None else raw
        routes = []
        for item in filter(None, (i.strip() for i in raw.split(";"))):
            name, _, rest = item.partition("=")
            fields = rest.split(",")
            if not name or len(fields) < 3 or len(fields) > 5 or not all(fields[:3]):
                raise ValueError(f"invalid ADP_ROUTES entry {item!r}; expected {cls.SYNTAX}")
            url, action, resource = fields[:3]
            try:
                cost = float(fields[3]) if len(fields) > 3 and fields[3] else 0.0
            except ValueError:
                raise ValueError(f"invalid cost in ADP_ROUTES entry {item!r}") from None
            if cost < 0:
                raise ValueError(f"negative cost in ADP_ROUTES entry {item!r}")
            if not url.startswith(("http://", "https://")):
                raise ValueError(f"route url must be http(s) in {item!r}")
            routes.append(Route(name, url, action, resource, cost, fields[4] if len(fields) > 4 and fields[4] else None))
        return cls(routes)

    def route(self, name: str) -> Route | None:
        return next((r for r in self.routes if r.name == name), None)
