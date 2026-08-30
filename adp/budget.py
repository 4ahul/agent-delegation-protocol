from __future__ import annotations
import sqlite3
from .db import LOCK, connect

EPS = 1e-9
MAX_CHAIN = 16  # delegation depth is bounded; refuse to walk a cycle forever


class BudgetLedger:
    """Spend accounting across a delegation chain.

    A child grant's limit is carved out of its parent at issuance time, but the
    issuer cannot see how much the parent has already spent at the gateway.
    Without charging ancestors, one parent grant of 500 can mint ten children of
    500 each. So every charge walks up the chain and debits each ancestor too.
    """

    def __init__(self, conn: sqlite3.Connection | None = None):
        self.conn = conn or connect()

    def known(self, token_id: str) -> bool:
        """True once this grant's lineage has been recorded."""
        return self.conn.execute(
            "SELECT 1 FROM budgets WHERE token_id=?", (token_id,)).fetchone() is not None

    def register(self, token_id: str, parent_id: str | None, limit: float | None) -> None:
        """Record a grant's lineage and limit the first time the gateway sees it."""
        with LOCK:
            self.conn.execute(
                "INSERT INTO budgets(token_id, parent_id, limit_amount, spent) VALUES(?,?,?,0) "
                "ON CONFLICT(token_id) DO UPDATE SET parent_id=COALESCE(budgets.parent_id, excluded.parent_id), "
                "limit_amount=COALESCE(budgets.limit_amount, excluded.limit_amount)",
                (token_id, parent_id, limit),
            )

    #: One walk of the grant and its ancestors. `depth` both bounds the chain
    #: and stops a parent cycle from recursing forever.
    _CHAIN_SQL = f"""
    WITH RECURSIVE chain(token_id, parent_id, limit_amount, spent, depth) AS (
        SELECT token_id, parent_id, limit_amount, spent, 0 FROM budgets WHERE token_id = ?
        UNION ALL
        SELECT b.token_id, b.parent_id, b.limit_amount, b.spent, chain.depth + 1
        FROM budgets b JOIN chain ON b.token_id = chain.parent_id
        WHERE chain.depth < {MAX_CHAIN - 1}
    )
    SELECT token_id, limit_amount, spent FROM chain
    """

    def _chain(self, token_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(self._CHAIN_SQL, (token_id,)).fetchall()

    def spent(self, token_id: str) -> float:
        row = self.conn.execute("SELECT spent FROM budgets WHERE token_id=?", (token_id,)).fetchone()
        return row["spent"] if row else 0.0

    def remaining(self, token_id: str) -> float | None:
        """Smallest headroom across the grant and its ancestors, or None if unlimited."""
        headroom = [r["limit_amount"] - r["spent"] for r in self._chain(token_id) if r["limit_amount"] is not None]
        return max(0.0, min(headroom)) if headroom else None

    def charge(self, token_id: str, amount: float) -> float | None:
        if amount < 0:
            raise ValueError("negative_cost")
        with LOCK:
            chain = self._chain(token_id)
            if not chain:
                raise ValueError("unknown_grant")
            for row in chain:
                if row["limit_amount"] is not None and row["spent"] + amount > row["limit_amount"] + EPS:
                    raise ValueError("budget_exceeded")
            self.conn.executemany(
                "UPDATE budgets SET spent=spent+? WHERE token_id=?",
                [(amount, row["token_id"]) for row in chain],
            )
            # The chain is already in hand; re-reading it to report the balance
            # would double the queries on the hottest path.
            headroom = [r["limit_amount"] - r["spent"] - amount
                        for r in chain if r["limit_amount"] is not None]
            return max(0.0, min(headroom)) if headroom else None

    def clear(self) -> None:
        with LOCK:
            self.conn.execute("DELETE FROM budgets")
