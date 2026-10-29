"""Private SQLite plans/receipts. Crash ambiguity never automatically re-executes."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .config import ForgeError, canonical


class State:
    def __init__(self, directory: Path):
        directory = directory.absolute()
        if directory.is_symlink():
            raise ForgeError("State directory must not be a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            raise ForgeError("State directory must be private (0700)")
        if hasattr(os, "getuid") and directory.stat().st_uid != os.getuid():
            raise ForgeError("State directory has another owner")
        self.path = directory / "state.sqlite3"
        if self.path.is_symlink():
            raise ForgeError("State file must not be a symlink")
        fd = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077:
            raise ForgeError("State file must be private (0600)")
        with self.connection() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS plans (
              id TEXT PRIMARY KEY, principal TEXT NOT NULL, payload TEXT NOT NULL,
              fingerprint TEXT NOT NULL, expires REAL NOT NULL,
              approved INTEGER NOT NULL DEFAULT 0, claimed_by TEXT);
            CREATE TABLE IF NOT EXISTS runs (
              request_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, principal TEXT NOT NULL,
              status TEXT NOT NULL, result TEXT, created REAL NOT NULL);
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def plan(self, principal: str, payload: dict, fingerprint: str, ttl: int, max_records: int) -> dict:
        plan_id = "plan_" + secrets.token_hex(16)
        expires = time.time() + ttl
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM plans WHERE expires < ? AND claimed_by IS NULL", (time.time(),))
            if db.execute("SELECT count(*) FROM plans").fetchone()[0] >= max_records:
                raise ForgeError("State capacity reached; operator maintenance required")
            db.execute("INSERT INTO plans(id,principal,payload,fingerprint,expires) VALUES(?,?,?,?,?)",
                       (plan_id, principal, canonical(payload), fingerprint, expires))
        return {"plan_id": plan_id, "expires_at": expires, **payload, "requires_operator_approval": True}

    def inspect(self, plan_id: str) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
        if row is None:
            raise ForgeError("Plan not found")
        return {**dict(row), "payload": json.loads(row["payload"])}

    def approve(self, plan_id: str, fingerprint: str) -> dict:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            if row is None or row["expires"] <= time.time() or row["fingerprint"] != fingerprint:
                raise ForgeError("Plan missing, expired, or configuration changed")
            if row["claimed_by"] is not None:
                raise ForgeError("Plan already consumed")
            db.execute("UPDATE plans SET approved=1 WHERE id=?", (plan_id,))
        return {"plan_id": plan_id, "approved": True}

    def claim(self, principal: str, plan_id: str, request_id: str, fingerprint: str,
              max_records: int, approval_required: bool) -> tuple[dict, dict | None]:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM runs WHERE request_id=?", (request_id,)).fetchone()
            if old is not None:
                if old["principal"] != principal or old["plan_id"] != plan_id:
                    raise ForgeError("request_id conflict")
                if old["status"] != "completed":
                    raise ForgeError("Request running or outcome uncertain; inspect receipt, do not retry with a new id")
                return {}, {**json.loads(old["result"]), "replayed": True}
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            if row is None or row["principal"] != principal:
                raise ForgeError("Plan not found or not owned by principal")
            if row["expires"] <= time.time() or row["fingerprint"] != fingerprint:
                raise ForgeError("Plan expired or configuration changed; create a new plan")
            if row["claimed_by"] is not None:
                raise ForgeError("Plan already consumed; use original request_id")
            if approval_required and not row["approved"]:
                raise ForgeError("Operator approval required; approval is not an MCP tool")
            if db.execute("SELECT count(*) FROM runs").fetchone()[0] >= max_records:
                raise ForgeError("Receipt capacity reached; operator maintenance required")
            db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?)",
                       (request_id, plan_id, principal, "running", None, time.time()))
            db.execute("UPDATE plans SET claimed_by=? WHERE id=?", (request_id, plan_id))
        return json.loads(row["payload"]), None

    def finish(self, request_id: str, result: dict) -> None:
        with self.connection() as db:
            db.execute("UPDATE runs SET status='completed', result=? WHERE request_id=? AND status='running'",
                       (canonical(result), request_id))

    def receipt(self, principal: str, request_id: str) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT * FROM runs WHERE request_id=? AND principal=?",
                             (request_id, principal)).fetchone()
        if row is None:
            raise ForgeError("Receipt not found")
        return {"request_id": request_id, "plan_id": row["plan_id"], "status": row["status"],
                "result": json.loads(row["result"]) if row["result"] else None,
                "warning": "running may also indicate crash/interruption; never automatically re-execute"}
