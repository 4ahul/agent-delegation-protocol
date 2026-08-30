from __future__ import annotations
import sqlite3, time
from .db import LOCK, connect


class RevocationStore:
    """Durable deny-list of grant IDs."""

    def __init__(self, conn: sqlite3.Connection | None = None):
        self.conn = conn or connect()

    def revoke(self, token_id: str, *, reason: str = "revoked", at: int | None = None) -> None:
        with LOCK:
            self.conn.execute(
                "INSERT INTO revocations(token_id, ts, reason) VALUES(?,?,?) "
                "ON CONFLICT(token_id) DO NOTHING",
                (token_id, int(time.time()) if at is None else int(at), reason),
            )

    def is_revoked(self, token_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM revocations WHERE token_id=?", (token_id,)
        ).fetchone() is not None

    def timestamp(self, token_id: str) -> int | None:
        row = self.conn.execute("SELECT ts FROM revocations WHERE token_id=?", (token_id,)).fetchone()
        return row["ts"] if row else None

    def clear(self) -> None:
        with LOCK:
            self.conn.execute("DELETE FROM revocations")
