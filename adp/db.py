"""SQLite-backed state for the gateway.

Revocations, budgets, approvals and audit must survive a restart: a revoked
token that comes back to life after a redeploy is a security bug, not an
inconvenience. sqlite3 is stdlib, so this costs no dependency.
"""
from __future__ import annotations
import os, sqlite3
from pathlib import Path
from threading import RLock

# ponytail: one process-wide write lock. SQLite serialises writers anyway;
# swap for per-connection locks only if you ever share a connection across processes.
LOCK = RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
  agent_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, registered_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS revocations (
  token_id TEXT PRIMARY KEY, ts INTEGER NOT NULL, reason TEXT);
CREATE TABLE IF NOT EXISTS budgets (
  token_id TEXT PRIMARY KEY, parent_id TEXT, limit_amount REAL, spent REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY, token_id TEXT NOT NULL, action TEXT NOT NULL,
  resource TEXT NOT NULL, expires_at INTEGER NOT NULL, approved INTEGER NOT NULL DEFAULT 0,
  approver TEXT, approved_at INTEGER);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, event TEXT NOT NULL,
  principal TEXT, agent TEXT, action TEXT, resource TEXT, decision TEXT, reason TEXT,
  token_id TEXT, metadata TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""


def connect(path: str | None = None) -> sqlite3.Connection:
    """Open (and migrate) the gateway store. Defaults to $ADP_DB, else in-memory."""
    path = path or os.getenv("ADP_DB") or ":memory:"
    if path != ":memory:":
        Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn
