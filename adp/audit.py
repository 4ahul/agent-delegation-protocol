from __future__ import annotations
import hashlib, json, sqlite3, time
from dataclasses import dataclass
from .db import LOCK, connect

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditEvent:
    ts: int
    event: str
    principal: str | None
    agent: str | None
    action: str | None
    resource: str | None
    decision: str | None
    reason: str | None
    token_id: str | None
    prev_hash: str
    hash: str
    metadata: dict


def _digest(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    """Append-only hash-chained log. Durable, so the chain survives a restart."""

    def __init__(self, conn: sqlite3.Connection | None = None):
        self.conn = conn or connect()

    def _last_hash(self) -> str:
        row = self.conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    def append(self, *, event: str, principal: str | None = None, agent: str | None = None,
               action=None, resource=None, decision=None, reason=None, token_id=None, **metadata) -> AuditEvent:
        with LOCK:
            body = {"ts": int(time.time()), "event": event, "principal": principal, "agent": agent,
                    "action": action, "resource": resource, "decision": decision,
                    "reason": reason, "token_id": token_id, "prev_hash": self._last_hash(),
                    "metadata": metadata}
            e = AuditEvent(**body, hash=_digest(body))
            self.conn.execute(
                "INSERT INTO audit(ts,event,principal,agent,action,resource,decision,reason,token_id,"
                "metadata,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (e.ts, e.event, e.principal, e.agent, e.action, e.resource, e.decision, e.reason,
                 e.token_id, json.dumps(e.metadata, sort_keys=True), e.prev_hash, e.hash),
            )
            return e

    @property
    def events(self) -> list[AuditEvent]:
        return [
            AuditEvent(
                ts=r["ts"], event=r["event"], principal=r["principal"], agent=r["agent"],
                action=r["action"], resource=r["resource"], decision=r["decision"], reason=r["reason"],
                token_id=r["token_id"], prev_hash=r["prev_hash"], hash=r["hash"],
                metadata=json.loads(r["metadata"]),
            )
            for r in self.conn.execute("SELECT * FROM audit ORDER BY seq")
        ]

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"]

    def head(self) -> str | None:
        row = self.conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else None

    def verify(self) -> bool:
        """Walk the chain streaming, one row at a time.

        The log only grows, so materialising it to check it would eventually
        be the thing that takes the gateway down.
        """
        prev = GENESIS
        for r in self.conn.execute("SELECT * FROM audit ORDER BY seq"):
            body = {"ts": r["ts"], "event": r["event"], "principal": r["principal"],
                    "agent": r["agent"], "action": r["action"], "resource": r["resource"],
                    "decision": r["decision"], "reason": r["reason"], "token_id": r["token_id"],
                    "prev_hash": r["prev_hash"], "metadata": json.loads(r["metadata"])}
            if r["prev_hash"] != prev or _digest(body) != r["hash"]:
                return False
            prev = r["hash"]
        return True

    def clear(self) -> None:
        with LOCK:
            self.conn.execute("DELETE FROM audit")
