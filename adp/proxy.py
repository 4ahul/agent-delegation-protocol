from __future__ import annotations
import httpx
from fastapi import APIRouter, Header, HTTPException, Request, Response

from .config import PolicyConfig
from .gateway import ADPGateway

# Neither the agent's ADP token nor its cookies reach the upstream: the gateway
# is the credential boundary. Hop-by-hop headers are dropped per RFC 9110.
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailer", "transfer-encoding", "upgrade"}
STRIP_REQUEST = HOP_BY_HOP | {"host", "content-length", "authorization", "cookie"}
STRIP_RESPONSE = HOP_BY_HOP | {"content-length"}


def build_proxy_router(gateway: ADPGateway, config: PolicyConfig, *, timeout: float = 60.0) -> APIRouter:
    router = APIRouter(prefix="/proxy")
    # ponytail: one shared client for connection reuse; closed by process exit.
    client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    @router.api_route("/{route_name}/{path:path}",
                      methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def proxy(route_name: str, path: str, request: Request,
                    authorization: str | None = Header(default=None)):
        route = config.route(route_name)
        if not route:
            raise HTTPException(404, "route_not_found")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing_bearer_token")

        prefix = route.resource_prefix.rstrip("/")
        resource = prefix if path == "" else f"{prefix}/{path}"
        try:
            decision = gateway.check(authorization[7:], action=route.action, resource=resource,
                                     estimated_cost=route.cost, purpose=route.purpose)
        except ValueError as e:
            raise HTTPException(401, f"invalid_token:{e}") from None
        if decision.result.decision != "ALLOW":
            raise HTTPException(403, {"decision": decision.result.decision,
                                      "reason": decision.result.reason})

        # Charge before forwarding: the upstream call is the spend, and a failed
        # or slow upstream must not leave the budget un-debited.
        if route.cost:
            try:
                gateway.authorizer.policy.charge(decision.grant, route.cost)
            except ValueError as e:
                raise HTTPException(409, str(e)) from None

        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in STRIP_REQUEST and not k.lower().startswith("x-adp-")}
        headers["x-adp-principal"] = decision.grant.principal
        headers["x-adp-agent"] = decision.grant.subject
        headers["x-adp-token-id"] = decision.grant.token_id or ""
        upstream = await client.request(request.method, f"{route.url.rstrip('/')}/{path}",
                                        content=await request.body(), headers=headers,
                                        params=request.query_params)
        return Response(content=upstream.content, status_code=upstream.status_code,
                        headers={k: v for k, v in upstream.headers.items()
                                 if k.lower() not in STRIP_RESPONSE})

    return router
