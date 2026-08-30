from __future__ import annotations
import secrets, sqlite3, time
from dataclasses import dataclass
from .db import LOCK, connect


@dataclass(frozen=True)
class Approval:
    approval_id: str
    token_id: str
    action: str
    resource: str
    expires_at: int
    approved: bool = False
    approver: str | None = None
    approved_at: int | None = None


def _row(r: sqlite3.Row) -> Approval:
    return Approval(r["approval_id"], r["token_id"], r["action"], r["resource"],
                    r["expires_at"], bool(r["approved"]), r["approver"], r["approved_at"])


class ApprovalStore:
    """Single-use, expiring human-approval tickets bound to token/action/resource."""

    def __init__(self, conn: sqlite3.Connection | None = None):
        self.conn = conn or connect()

    def request(self, token_id: str, action: str, resource: str, ttl: int = 300) -> Approval:
        item = Approval(secrets.token_urlsafe(18), token_id, action, resource, int(time.time()) + ttl)
        with LOCK:
            self.conn.execute(
                "INSERT INTO approvals(approval_id,token_id,action,resource,expires_at,approved) "
                "VALUES(?,?,?,?,?,0)",
                (item.approval_id, token_id, action, resource, item.expires_at),
            )
        return item

    def get(self, approval_id: str) -> Approval | None:
        r = self.conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
        return _row(r) if r else None

    def approve(self, approval_id: str, approver: str) -> Approval:
        with LOCK:
            item = self.get(approval_id)
            if item is None:
                raise KeyError(approval_id)
            if int(time.time()) >= item.expires_at:
                raise ValueError("approval_expired")
            if item.approved:
                raise ValueError("approval_already_used")
            now = int(time.time())
            self.conn.execute(
                "UPDATE approvals SET approved=1, approver=?, approved_at=? WHERE approval_id=?",
                (approver, now, approval_id),
            )
            return Approval(item.approval_id, item.token_id, item.action, item.resource,
                            item.expires_at, True, approver, now)

    def consume(self, approval_id: str, *, token_id: str, action: str, resource: str) -> bool:
        """Redeem an approval exactly once for the exact operation it was granted for."""
        with LOCK:
            item = self.get(approval_id)
            if (item is None or not item.approved or item.token_id != token_id
                    or item.action != action or item.resource != resource
                    or int(time.time()) >= item.expires_at):
                return False
            self.conn.execute("DELETE FROM approvals WHERE approval_id=?", (approval_id,))
            return True

    def clear(self) -> None:
        with LOCK:
            self.conn.execute("DELETE FROM approvals")
