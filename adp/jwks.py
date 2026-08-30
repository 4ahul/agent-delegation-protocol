from __future__ import annotations
import sqlite3, time

from .crypto import KeyPair
from .db import LOCK, connect


def public_jwk(agent_id: str, public_key_b64: str) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": public_key_b64,
            "use": "sig", "kid": agent_id, "alg": "EdDSA"}


class KeyRegistry:
    """Durable agent_id -> Ed25519 public key map backing token verification.

    Dict-like on purpose: `Authorizer.keys` only ever does `.get`.
    """

    def __init__(self, conn: sqlite3.Connection | None = None):
        self.conn = conn or connect()

    def get(self, agent_id: str | None, default=None):
        if not agent_id:
            return default
        row = self.conn.execute("SELECT public_key FROM keys WHERE agent_id=?", (agent_id,)).fetchone()
        return row["public_key"] if row else default

    def register(self, agent_id: str, public_key_b64: str) -> None:
        KeyPair.validate_public(public_key_b64)  # reject anything that is not an Ed25519 key
        with LOCK:
            self.conn.execute(
                "INSERT INTO keys(agent_id, public_key, registered_at) VALUES(?,?,?) "
                "ON CONFLICT(agent_id) DO UPDATE SET public_key=excluded.public_key, "
                "registered_at=excluded.registered_at",
                (agent_id, public_key_b64, int(time.time())),
            )

    __setitem__ = register

    def items(self):
        return [(r["agent_id"], r["public_key"]) for r in
                self.conn.execute("SELECT agent_id, public_key FROM keys ORDER BY agent_id")]

    def __contains__(self, agent_id: str) -> bool:
        return self.get(agent_id) is not None

    def clear(self) -> None:
        with LOCK:
            self.conn.execute("DELETE FROM keys")
