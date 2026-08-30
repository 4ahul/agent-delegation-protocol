"""The proxy is the credential boundary: prove nothing leaks upstream."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from adp.config import PolicyConfig, Route
from adp.crypto import KeyPair
from adp.gateway import ADPGateway
from adp.middleware import Authorizer
from adp.models import Budget, Grant
from adp.policy import PolicyEngine
from adp.proxy import build_proxy_router
from adp.revocation import RevocationStore
from adp.token import issue


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}})
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_):
        pass


@pytest.fixture(scope="module")
def upstream():
    server = HTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def proxy(upstream):
    kp = KeyPair.generate()
    engine = PolicyEngine()
    authorizer = Authorizer({"user://rahul": kp.public_key_b64}, engine, RevocationStore())
    routes = PolicyConfig([Route("property", upstream, "property.read", "mumbai://rr", 1.0)])
    app = FastAPI()
    app.include_router(build_proxy_router(ADPGateway(authorizer), routes))
    now = int(time.time())
    grant = Grant("ADP-0.2", "user://rahul", "agent://research", "user://rahul", now, now + 300,
                  ("property.read",), ("mumbai://rr/*",), budget=Budget("INR", 2), token_id="px")
    return TestClient(app), issue(grant, kp), engine


def test_forwards_allowed_request_without_agent_credentials(proxy):
    client, token, _ = proxy
    r = client.get("/proxy/property/123", headers={"Authorization": f"Bearer {token}",
                                                   "Cookie": "session=secret",
                                                   "X-ADP-Principal": "user://attacker"})
    assert r.status_code == 200
    headers = r.json()["headers"]
    assert "authorization" not in headers and "cookie" not in headers
    assert headers["x-adp-principal"] == "user://rahul"  # spoofed value overwritten
    assert headers["x-adp-agent"] == "agent://research"


def test_denies_ungranted_resource(proxy):
    client, token, _ = proxy
    r = client.get("/proxy/property/../other", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (403, 404)


def test_unknown_route_and_missing_token(proxy):
    client, token, _ = proxy
    assert client.get("/proxy/nope/1", headers={"Authorization": f"Bearer {token}"}).status_code == 404
    assert client.get("/proxy/property/1").status_code == 401


def test_budget_is_charged_per_forwarded_request(proxy):
    client, token, engine = proxy
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/proxy/property/1", headers=headers).status_code == 200
    assert client.get("/proxy/property/2", headers=headers).status_code == 200
    assert engine.ledger.remaining("px") == 0
    assert client.get("/proxy/property/3", headers=headers).status_code == 403
